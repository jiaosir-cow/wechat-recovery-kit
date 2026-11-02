# -*- coding: utf-8 -*-
"""
解密微信 WAL 日志（SQLCipher 加密帧），并扫描其中的记录。
用法：python wal_carve.py <xxx.db-wal> <对应主库.db> <密钥hex> [--keyword 文本]
只读输入。解密页写到本仓库 04_恢复输出，不写回 WAL 所在目录。
--session 不筛选帧。
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


def _under_live_wechat(path):
    norm = os.path.normcase(os.path.abspath(path))
    return ("\\xwechat_files\\" in norm) or ("\\wechat files\\" in norm)


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help") or len(args) < 3:
        print("用法: python wal_carve.py <xxx.db-wal> <对应主库.db> <密钥hex> [--keyword 文本]")
        print("只读 WAL 与主库。解密页写到本仓库 04_恢复输出，不写回源目录。")
        print("--session 不筛选帧（未实现）。")
        sys.exit(0 if args and args[0] in ("-h", "--help") else 2)
    wal_path, db_path, key_hex = args[0], args[1], args[2]
    out_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "04_恢复输出")
    out_path = os.path.join(out_dir, os.path.basename(wal_path) + "_decrypted_pages.bin")
    if _under_live_wechat(out_path) or os.path.normcase(os.path.abspath(os.path.dirname(out_path))) in (
        os.path.normcase(os.path.abspath(os.path.dirname(wal_path))),
        os.path.normcase(os.path.abspath(os.path.dirname(db_path))),
    ):
        print("[错误] 拒绝把解密页写进微信数据目录或源文件所在目录")
        sys.exit(1)
    if "--session" in args:
        print("[提示] --session 不筛选 WAL 帧：当前只解密帧，不按会话过滤。")
    try:
        given = bytes.fromhex(key_hex.lower().removeprefix("0x"))
    except ValueError:
        print("[错误] 密钥不是十六进制，未开始解密")
        sys.exit(1)

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
    if len(data) < 32:
        print("[错误] WAL 文件过短，无法读取帧头")
        sys.exit(1)
    magic, fmt_ver, pgsz = struct.unpack(">III", data[:12])
    print(f"WAL头: magic={magic:08x} 页大小={pgsz} 文件={len(data)} 字节")
    if pgsz != PAGE_SZ:
        print("[警告] WAL页大小与预期不符")
    frame_sz = 24 + PAGE_SZ
    nframes = (len(data) - 32) // frame_sz
    os.makedirs(out_dir, exist_ok=True)
    n_ok = 0
    n_fail = 0
    hits = []
    kw = None
    for i, a in enumerate(sys.argv):
        if a == "--keyword" and i + 1 < len(sys.argv):
            kw = sys.argv[i + 1].encode("utf-8")
    with open(out_path, "wb") as fo:
        for i in range(nframes):
            off = 32 + i * frame_sz
            pgno, dbsize = struct.unpack(">II", data[off:off + 8])
            page = data[off + 24: off + 24 + PAGE_SZ]
            try:
                dec = decrypt_page(enc_key, page, pgno)
            except Exception:
                n_fail += 1
                continue
            # 校验：解密后首字节应为合法页类型
            t = dec[0] if pgno > 1 else dec[100]
            if t not in (2, 5, 10, 13):
                continue
            n_ok += 1
            fo.write(struct.pack(">I", pgno) + dec)
            if kw and kw in dec:
                hits.append((i, pgno, "含关键词"))
    print(f"解密帧: {n_ok}/{nframes}，解密异常 {n_fail}，输出 {out_path}")
    for h in hits[:20]:
        print("命中帧:", h)


if __name__ == "__main__":
    main()
