# -*- coding: utf-8 -*-
"""
解密微信 WAL 日志（SQLCipher 加密帧），并扫描其中的记录。
用法：python wal_carve.py <xxx.db-wal> <对应主库.db> --key-file <密钥文件> [--keyword 文本]
也接受第三个参数为 64 位十六进制密钥。只读输入。解密页写到本仓库 04_恢复输出。
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


def _read_key_file(path):
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                line = line.rsplit("=", 1)[1].strip()
            return line.lower().removeprefix("0x")
    return ""


def _pop_option(args, name):
    if name not in args:
        return args, None
    i = args.index(name)
    if i + 1 >= len(args):
        print(f"[错误] {name} 后面需要参数")
        sys.exit(2)
    return args[:i] + args[i + 2:], args[i + 1]


def main():
    args = sys.argv[1:]
    args, key_file = _pop_option(args, "--key-file")
    needs_hex = key_file is None and (len(args) < 3 or args[2].startswith("-"))
    if not args or args[0] in ("-h", "--help") or len(args) < 2 or needs_hex:
        print("用法: python wal_carve.py <xxx.db-wal> <对应主库.db> --key-file <密钥文件> [--keyword 文本]")
        print("也接受: python wal_carve.py <xxx.db-wal> <对应主库.db> <密钥hex> [--keyword 文本]")
        print("只读 WAL 与主库。解密页写到本仓库 04_恢复输出，不写回源目录。")
        print("--session 不筛选帧（未实现）。优先用 --key-file，避免密钥留在命令行历史里。")
        sys.exit(0 if args and args[0] in ("-h", "--help") else 2)
    wal_path, db_path = args[0], args[1]
    key_hex = None if key_file else args[2]
    out_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "04_恢复输出")
    out_path = os.path.join(out_dir, os.path.basename(wal_path) + "_decrypted_pages.bin")
    if _under_live_wechat(out_path) or os.path.normcase(os.path.abspath(os.path.dirname(out_path))) in (
        os.path.normcase(os.path.abspath(os.path.dirname(wal_path))),
        os.path.normcase(os.path.abspath(os.path.dirname(db_path))),
    ):
        print("[错误] 拒绝把解密页写进微信数据目录或源文件所在目录")
        sys.exit(1)
    if "--session" in sys.argv:
        print("[提示] --session 不筛选 WAL 帧：当前只解密帧，不按会话过滤。")
    if key_file:
        try:
            key_hex = _read_key_file(key_file)
        except OSError as e:
            print(f"[错误] 读不到密钥文件: {type(e).__name__}")
            sys.exit(1)
        if not key_hex:
            print("[错误] 密钥文件里没有可用的十六进制密钥")
            sys.exit(1)
    try:
        given = bytes.fromhex(key_hex.lower().removeprefix("0x"))
    except ValueError:
        print("[错误] 密钥不是十六进制，未开始解密")
        sys.exit(1)
    if len(given) != KEY_SZ:
        print("[错误] 密钥必须是 32 字节（64 位十六进制），未开始解密")
        sys.exit(1)

    # 用主库 page1 的 salt 推导实际 AES 密钥（passphrase 模式）
    try:
        with open(db_path, "rb") as f:
            page1 = f.read(PAGE_SZ)
    except OSError as e:
        print(f"[错误] 读不到主库: {type(e).__name__}")
        sys.exit(1)
    if len(page1) < PAGE_SZ:
        print("[错误] 主库过短，无法核对密钥")
        sys.exit(1)
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

    try:
        wal_size = os.path.getsize(wal_path)
    except OSError as e:
        print(f"[错误] 读不到 WAL: {type(e).__name__}")
        sys.exit(1)
    if wal_size < 32:
        print("[错误] WAL 文件过短，无法读取帧头")
        sys.exit(1)
    kw = None
    kw16 = None
    for i, a in enumerate(sys.argv):
        if a == "--keyword" and i + 1 < len(sys.argv):
            kw = sys.argv[i + 1].encode("utf-8")
            kw16 = sys.argv[i + 1].encode("utf-16-le")
    frame_sz = 24 + PAGE_SZ
    nframes = (wal_size - 32) // frame_sz
    os.makedirs(out_dir, exist_ok=True)
    n_ok = 0
    n_fail = 0
    n_bad = 0
    n_hit = 0
    hits = []
    with open(wal_path, "rb") as f, open(out_path, "wb") as fo:
        header = f.read(32)
        if len(header) < 32:
            print("[错误] WAL 文件过短，无法读取帧头")
            sys.exit(1)
        magic, fmt_ver, pgsz = struct.unpack(">III", header[:12])
        print(f"WAL头: magic={magic:08x} 页大小={pgsz} 文件={wal_size} 字节")
        if pgsz != PAGE_SZ:
            print("[警告] WAL页大小与预期不符")
        for i in range(nframes):
            frame = f.read(frame_sz)
            if len(frame) < frame_sz:
                n_fail += 1
                break
            pgno, _dbsize = struct.unpack(">II", frame[:8])
            page = frame[24:24 + PAGE_SZ]
            try:
                dec = decrypt_page(enc_key, page, pgno)
            except Exception:
                n_fail += 1
                continue
            t = dec[0] if pgno > 1 else dec[100]
            if t not in (2, 5, 10, 13):
                n_bad += 1
                continue
            n_ok += 1
            fo.write(struct.pack(">I", pgno) + dec)
            if kw and (kw in dec or (kw16 and kw16 != kw and kw16 in dec)):
                n_hit += 1
                if len(hits) < 20:
                    hits.append((i, pgno, "含关键词"))
    print(f"解密帧: {n_ok}/{nframes}，解密异常 {n_fail}，页类型不符 {n_bad}，输出 {out_path}")
    if kw:
        print(f"关键词命中帧 {n_hit}")
    for h in hits:
        print("命中帧:", h)


if __name__ == "__main__":
    main()
