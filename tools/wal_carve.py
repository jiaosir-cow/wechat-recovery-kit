# -*- coding: utf-8 -*-
"""
解密微信 WAL 日志（SQLCipher 加密帧），并扫描其中的记录。
用法：python wal_carve.py <xxx.db-wal> <对应主库.db> <密钥hex> [--session 32]
只读输入，结果打印并写 <wal>_decrypted_pages.bin
"""
import os, sys, struct, hashlib
import hmac as hmac_mod
from Crypto.Cipher import AES

PAGE_SZ = 4096
RESERVE = 80
IV_SZ = 16
SALT_SZ = 16
KEY_SZ = 32
SQLITE_HDR = b'SQLite format 3\x00'


def derive_mac_key(enc_key, salt):
    mac_salt = bytes(b ^ 0x3a for b in salt)
    return hashlib.pbkdf2_hmac("sha512", enc_key, mac_salt, 2, dklen=KEY_SZ)


def decrypt_page(enc_key, page_data, pgno):
    iv = page_data[PAGE_SZ - RESERVE: PAGE_SZ - RESERVE + IV_SZ]
    cipher = AES.new(enc_key, AES.MODE_CBC, iv)
    if pgno == 1:
        dec = cipher.decrypt(page_data[SALT_SZ: PAGE_SZ - RESERVE])
        return bytes(bytearray(SQLITE_HDR + dec + b'\x00' * RESERVE))
    dec = cipher.decrypt(page_data[:PAGE_SZ - RESERVE])
    return dec + b'\x00' * RESERVE


def main():
    wal_path, db_path, key_hex = sys.argv[1], sys.argv[2], sys.argv[3]
    want_session = None
    for i, a in enumerate(sys.argv):
        if a == "--session":
            want_session = int(sys.argv[i + 1])
    given = bytes.fromhex(key_hex.lower().removeprefix("0x"))

    # 用主库 page1 的 salt 推导实际 AES 密钥（passphrase 模式）
    with open(db_path, "rb") as f:
        page1 = f.read(PAGE_SZ)
    salt = page1[:SALT_SZ]
    cands = [given, hashlib.pbkdf2_hmac("sha512", given, salt, 256000, dklen=KEY_SZ)]
    enc_key = None
    for cand in cands:
        mac_key = derive_mac_key(cand, salt)
        hm = hmac_mod.new(mac_key, page1[SALT_SZ: PAGE_SZ - RESERVE + IV_SZ], hashlib.sha512)
        hm.update(struct.pack('<I', 1))
        if hm.digest() == page1[PAGE_SZ - 64:]:
            enc_key = cand
            break
    if enc_key is None:
        print("[错误] 密钥与主库不匹配")
        sys.exit(1)
    print("[密钥] 匹配主库成功")

    with open(wal_path, "rb") as f:
        data = f.read()
    magic, fmt_ver, pgsz = struct.unpack(">III", data[:12])
    print(f"WAL头: magic={magic:08x} 页大小={pgsz} 文件={len(data)} 字节")
    if pgsz != PAGE_SZ:
        print("[警告] WAL页大小与预期不符")
    frame_sz = 24 + PAGE_SZ
    nframes = (len(data) - 32) // frame_sz
    out_path = wal_path + "_decrypted_pages.bin"
    n_ok = 0
    hits = []
    kw = None
    for i, a in enumerate(sys.argv):
        if a == "--keyword":
            kw = sys.argv[i + 1].encode("utf-8")
    with open(out_path, "wb") as fo:
        for i in range(nframes):
            off = 32 + i * frame_sz
            pgno, dbsize = struct.unpack(">II", data[off:off + 8])
            page = data[off + 24: off + 24 + PAGE_SZ]
            try:
                dec = decrypt_page(enc_key, page, pgno)
            except Exception:
                continue
            # 校验：解密后首字节应为合法页类型
            t = dec[0] if pgno > 1 else dec[100]
            if t not in (2, 5, 10, 13):
                continue
            n_ok += 1
            fo.write(struct.pack(">I", pgno) + dec)
            if kw and kw in dec:
                hits.append((i, pgno, "含关键词"))
            if want_session is not None and t == 13:
                # 粗扫：页面内是否存在该 session 的 fts 记录特征（小整数 32 难直接匹配，略过，交由后续 strings）
                pass
    print(f"解密帧: {n_ok}/{nframes}，输出 {out_path}")
    for h in hits[:20]:
        print("命中帧:", h)


if __name__ == "__main__":
    main()
