# -*- coding: utf-8 -*-
"""
第1步 · 微信 4.x 数据库批量解密（自包含，不依赖外部配置文件）
只读 01_副本存放，输出到 03_解密输出，绝不写回源目录。

密钥三种给法（按优先级自动识别）：
  1. 01_副本存放\\all_keys.json        —— 由 find_all_keys.py 在微信电脑上生成
  2. 01_副本存放\\密钥.txt             —— 手工整理，每行一条：相对路径或文件名=64位hex密钥
  3. 命令行 --key <64位hex> 或运行时输入 —— 所有库用同一个密钥尝试

自检：python decrypt_all.py --selftest
"""
import hashlib, struct, os, sys, json, shutil
import hmac as hmac_mod
from Crypto.Cipher import AES

PAGE_SZ = 4096
KEY_SZ = 32
SALT_SZ = 16
IV_SZ = 16
HMAC_SZ = 64
RESERVE_SZ = 80
SQLITE_HDR = b'SQLite format 3\x00'

HERE = os.path.dirname(os.path.abspath(__file__))          # 02_工具
ROOT = os.path.dirname(HERE)                                # 工作区根
SRC_DIR = os.path.join(ROOT, "01_副本存放")
OUT_DIR = os.path.join(ROOT, "03_解密输出")


def _under_live_wechat(path):
    norm = os.path.normcase(os.path.abspath(path))
    return ("\\xwechat_files\\" in norm) or ("\\wechat files\\" in norm)


def _inside(root, path):
    root_r = os.path.normcase(os.path.abspath(root))
    path_r = os.path.normcase(os.path.abspath(path))
    try:
        return os.path.commonpath([root_r, path_r]) == root_r
    except ValueError:
        return False


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


# ---------- 解密核心（4.x 算法与 wechat-decrypt/decrypt_db.py 一致；3.x 为经典 SQLCipher3 参数，自动识别） ----------
PROFILES = {
    "4.x": dict(reserve=80, iv_off=(-80, -64), hmac_len=64, hmac_algo="sha512"),
    "3.x": dict(reserve=48, iv_off=(-48, -32), hmac_len=20, hmac_algo="sha1"),
}


def derive_mac_key(enc_key, salt, algo):
    mac_salt = bytes(b ^ 0x3a for b in salt)
    return hashlib.pbkdf2_hmac(algo, enc_key, mac_salt, 2, dklen=KEY_SZ)


def page1_hmac_ok(page1, salt, mac_key, prof):
    a, b = prof["iv_off"]
    hmac_data = page1[SALT_SZ: PAGE_SZ + b]
    stored = page1[PAGE_SZ - prof["hmac_len"]:]
    hm = hmac_mod.new(mac_key, hmac_data, getattr(hashlib, prof["hmac_algo"]))
    hm.update(struct.pack('<I', 1))
    return hm.digest() == stored


def detect_profile(page1, key_or_pass):
    """自动识别：3.x/4.x 加密格式 × 密钥形态（raw key / passphrase 推导）。
    返回 (格式名, profile, 实际AES密钥, 密钥形态说明)"""
    salt = page1[:SALT_SZ]
    cands = [("raw", key_or_pass),
             ("passphrase", hashlib.pbkdf2_hmac("sha512", key_or_pass, salt, 256000, dklen=KEY_SZ))]
    for mode, enc_key in cands:
        for name, prof in PROFILES.items():
            if page1_hmac_ok(page1, salt, derive_mac_key(enc_key, salt, prof["hmac_algo"]), prof):
                return name, prof, enc_key, mode
    return None, None, None, None


def decrypt_page(enc_key, page_data, pgno, reserve, iv_a, iv_b):
    iv = page_data[PAGE_SZ + iv_a: PAGE_SZ + iv_b]
    cipher = AES.new(enc_key, AES.MODE_CBC, iv)
    if pgno == 1:
        decrypted = cipher.decrypt(page_data[SALT_SZ: PAGE_SZ - reserve])
        return bytes(bytearray(SQLITE_HDR + decrypted + b'\x00' * reserve))
    decrypted = cipher.decrypt(page_data[:PAGE_SZ - reserve])
    return decrypted + b'\x00' * reserve


def decrypt_database(db_path, out_path, enc_key, quiet=False):
    """返回 (是否成功, 说明)。自动识别微信 4.x / 3.x 加密格式。"""
    file_size = os.path.getsize(db_path)
    total_pages = file_size // PAGE_SZ + (1 if file_size % PAGE_SZ else 0)
    if file_size < PAGE_SZ:
        return False, "文件太小"
    with open(db_path, 'rb') as fin:
        page1 = fin.read(PAGE_SZ)
    name, prof, real_key, mode = detect_profile(page1, enc_key)
    if prof is None:
        return False, "Page1 HMAC 校验失败（密钥不对或版本不符）"
    reserve = prof["reserve"]
    iv_a, iv_b = prof["iv_off"]
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(db_path, 'rb') as fin, open(out_path, 'wb') as fout:
        for pgno in range(1, total_pages + 1):
            page = fin.read(PAGE_SZ)
            if not page:
                break
            if len(page) < PAGE_SZ:
                page = page + b'\x00' * (PAGE_SZ - len(page))
            fout.write(decrypt_page(real_key, page, pgno, reserve, iv_a, iv_b))
            if not quiet and pgno % 20000 == 0:
                print(f"    进度 {pgno}/{total_pages}")
    # 用 sqlite3 验证可读
    try:
        import sqlite3
        conn = sqlite3.connect(out_path)
        n = conn.execute("SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0]
        conn.close()
        return True, f"微信{name}格式/{mode}密钥，表数量 {n}"
    except Exception as e:
        try:
            os.remove(out_path)
        except OSError:
            pass
        return False, f"解密后校验失败: {e}（已删除不完整输出）"


# ---------- 密钥收集 ----------
def load_keys():
    """返回 dict: 各种形式的相对路径/文件名 -> enc_key(bytes)，外加 ('*',) 表示全局单密钥"""
    keys = {}
    def take_hex(text):
        g = str(text).strip().lower().removeprefix("0x")
        if len(g) != 64 or any(c not in "0123456789abcdef" for c in g):
            return None
        return bytes.fromhex(g)

    jf = os.path.join(SRC_DIR, "all_keys.json")
    if os.path.exists(jf):
        with open(jf, encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                print("[错误] all_keys.json 不是合法 JSON，已停止")
                sys.exit(1)
        if not isinstance(data, dict):
            print("[错误] all_keys.json 的内容必须是对象，已停止")
            sys.exit(1)
        bad = 0
        for k, v in data.items():
            try:
                raw = v["enc_key"] if isinstance(v, dict) else v
                got = take_hex(raw)
            except (KeyError, TypeError, AttributeError):
                got = None
            if got is None:
                bad += 1
                continue
            keys[str(k).replace("/", "\\")] = got
        print(f"[密钥] 从 all_keys.json 载入 {len(keys)} 条" + (f"，跳过 {bad} 条无法解析的记录" if bad else ""))
    tf = os.path.join(SRC_DIR, "密钥.txt")
    if os.path.exists(tf):
        n = 0
        bad = 0
        with open(tf, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    got = take_hex(line)
                    if got is None:
                        bad += 1
                        continue
                    keys["*"] = got
                    n += 1
                    continue
                name, hexkey = line.rsplit("=", 1)
                name = name.strip().replace("/", "\\")
                got = take_hex(hexkey)
                if got is None or not name:
                    bad += 1
                    continue
                keys[name] = got
                n += 1
        print(f"[密钥] 从 密钥.txt 载入 {n} 条" + (f"，跳过 {bad} 条无法解析的行" if bad else ""))
    return keys


def find_key_for(rel_path, keys, single_key):
    """按更长的路径优先。全路径、末两级、文件名，以及带分隔符的后缀都算匹配。"""
    rp = rel_path.replace("/", "\\")
    parts = [p for p in rp.split("\\") if p]
    if not parts:
        return single_key
    tail2 = "\\".join(parts[-2:]) if len(parts) >= 2 else parts[-1]
    base = parts[-1]
    best = None
    best_len = -1
    for k, v in keys.items():
        if k == "*":
            continue
        kn = k.replace("/", "\\").strip("\\")
        if not kn:
            continue
        matched = kn in (rp, tail2, base) or rp.endswith("\\" + kn) or kn.endswith("\\" + rp)
        if matched and len(kn) > best_len:
            best = v
            best_len = len(kn)
    return best if best is not None else single_key


# ---------- 自检：按微信 4.x / 3.x / 4.x-passphrase 三种形态各加密一个真 sqlite 库，再解密比对 ----------
def _roundtrip(profile_name, tmp, use_pass=False):
    import sqlite3, secrets
    prof = PROFILES[profile_name]
    reserve = prof["reserve"]
    suffix = f"{profile_name}{'_pass' if use_pass else ''}"
    plain = os.path.join(tmp, f"plain_{suffix}.db")
    enc = os.path.join(tmp, f"enc_{suffix}.db")
    dec = os.path.join(tmp, f"dec_{suffix}.db")
    conn = sqlite3.connect(plain)
    conn.execute("CREATE TABLE t(a TEXT)")
    conn.execute("INSERT INTO t VALUES ('这是一条自检测试消息')")
    for i in range(3000):  # 撑到多页
        conn.execute("INSERT INTO t VALUES (?)", (f"填充行{i}" * 20,))
    conn.commit(); conn.close()
    # 把页保留区字节（header 偏移20）设为对应值并 VACUUM 重建，模拟微信库 usable_size
    with open(plain, "r+b") as f:
        f.seek(20); f.write(bytes([reserve]))
    conn = sqlite3.connect(plain)
    conn.execute("VACUUM")
    conn.close()
    given_key = secrets.token_bytes(32)   # 解密时传入的密钥（passphrase 模式下是口令）
    data = open(plain, "rb").read()
    data += b"\x00" * ((-len(data)) % PAGE_SZ)
    salt = secrets.token_bytes(16)
    enc_key = (hashlib.pbkdf2_hmac("sha512", given_key, salt, 256000, dklen=KEY_SZ)
               if use_pass else given_key)  # 实际 AES 密钥
    mac_key = derive_mac_key(enc_key, salt, prof["hmac_algo"])
    iv_a, iv_b = prof["iv_off"]
    out = bytearray()
    for pgno in range(1, len(data) // PAGE_SZ + 1):
        page = data[(pgno - 1) * PAGE_SZ: pgno * PAGE_SZ]
        iv = secrets.token_bytes(16)
        cipher = AES.new(enc_key, AES.MODE_CBC, iv)
        body = cipher.encrypt(page[SALT_SZ: PAGE_SZ - reserve] if pgno == 1
                              else page[:PAGE_SZ - reserve])
        hm = hmac_mod.new(mac_key, body + iv, getattr(hashlib, prof["hmac_algo"]))
        hm.update(struct.pack('<I', pgno))
        pad = b"\x00" * (reserve - IV_SZ - prof["hmac_len"])  # 3.x 保留区有 12 字节空隙
        out += (salt + body + iv + pad + hm.digest()) if pgno == 1 else (body + iv + pad + hm.digest())
    open(enc, "wb").write(bytes(out))
    ok, msg = decrypt_database(enc, dec, given_key, quiet=True)
    assert ok, f"{suffix} 解密失败: {msg}"
    assert msg.startswith(f"微信{profile_name}"), f"{suffix} 被误识别为: {msg}"
    if use_pass:
        assert "passphrase" in msg, f"passphrase 模式未被识别: {msg}"
    a, b = open(plain, "rb").read(), open(dec, "rb").read()
    pages = len(a) // PAGE_SZ
    same = all(a[i * PAGE_SZ: i * PAGE_SZ + PAGE_SZ - reserve]
               == b[i * PAGE_SZ: i * PAGE_SZ + PAGE_SZ - reserve] for i in range(pages))
    conn = sqlite3.connect(dec)
    hit = conn.execute("SELECT a FROM t WHERE a LIKE '%自检测试%'").fetchall()
    conn.close()
    assert same and hit, f"{suffix} 内容比对失败"
    # 错误密钥必须被拒绝
    ok2, _ = decrypt_database(enc, os.path.join(tmp, f"bad_{suffix}.db"), secrets.token_bytes(32), quiet=True)
    assert not ok2, f"{suffix} 错误密钥未被拒绝"
    print(f"  [{suffix}] 通过：加解密逐页一致，测试消息可读出（{hit[0][0]}），错误密钥被拒绝")


def selftest():
    print("== 自检：构造微信格式加密库 -> 解密 -> 比对 ==")
    tmp = os.path.join(ROOT, "_selftest_tmp")
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp, exist_ok=True)
    _roundtrip("4.x", tmp)
    _roundtrip("3.x", tmp)
    _roundtrip("4.x", tmp, use_pass=True)
    shutil.rmtree(tmp, ignore_errors=True)
    print("== 自检全部通过：4.x(raw/passphrase) 与 3.x 解密链路均可用 ==")


# ---------- 主流程 ----------
def main():
    args = sys.argv[1:]
    if "--selftest" in args:
        selftest(); return
    if _under_live_wechat(OUT_DIR) or _under_live_wechat(SRC_DIR):
        print("[错误] 本仓库位于微信数据目录下，已停止。请把仓库放到 xwechat_files / WeChat Files 之外。")
        sys.exit(1)
    single_key = None

    def parse_cli_key(text):
        try:
            got = bytes.fromhex(text.strip().lower().removeprefix("0x"))
        except ValueError:
            print("[错误] 密钥不是十六进制，未开始解密")
            sys.exit(2)
        if len(got) != KEY_SZ:
            print("[错误] 密钥必须是 32 字节（64 位十六进制），未开始解密")
            sys.exit(2)
        return got

    if "--key-file" in args:
        i = args.index("--key-file")
        if i + 1 >= len(args):
            print("[错误] --key-file 后面需要路径")
            sys.exit(2)
        try:
            text = _read_key_file(args[i + 1])
        except OSError as e:
            print(f"[错误] 读不到密钥文件: {type(e).__name__}")
            sys.exit(1)
        if not text:
            print("[错误] 密钥文件里没有可用的十六进制密钥")
            sys.exit(1)
        single_key = parse_cli_key(text)
    elif "--key" in args:
        i = args.index("--key")
        if i + 1 >= len(args):
            print("[错误] --key 后面需要 64 位十六进制。密钥放进 01_副本存放\\密钥.txt 或使用 --key-file，避免留在命令行历史里。")
            sys.exit(2)
        single_key = parse_cli_key(args[i + 1])
    if not os.path.isdir(SRC_DIR):
        print(f"[错误] 找不到 {SRC_DIR}"); sys.exit(1)
    db_list = []
    for root, _, files in os.walk(SRC_DIR):
        for f in files:
            if f.endswith(".db"):
                db_list.append(os.path.join(root, f))
    if not db_list:
        print(f"[错误] {SRC_DIR} 里没有 .db 文件，请先把微信数据复制进来")
        sys.exit(1)
    keys = load_keys()
    if single_key is None:
        single_key = keys.get("*")  # 密钥.txt 里单独一行的通用密钥
    if not keys and single_key is None:
        print("未找到 all_keys.json / 密钥.txt。")
        s = input("请粘贴 64 位十六进制密钥（对所有库尝试同一密钥），直接回车退出: ").strip()
        if not s:
            print("已退出。"); sys.exit(1)
        single_key = parse_cli_key(s)
    ok_n, fail_n = 0, 0
    fails = []
    for path in sorted(db_list):
        rel = os.path.relpath(path, SRC_DIR)
        # 剥离 wxid 这一层，使 message\message_0.db 这种形式也能匹配密钥表
        parts = rel.split(os.sep)
        rel_short = "\\".join(parts[1:]) if len(parts) > 1 else rel
        key = find_key_for(rel, keys, None) or find_key_for(rel_short, keys, single_key)
        if key is None:
            print(f"[跳过] {rel} —— 没有匹配密钥")
            fails.append(rel); fail_n += 1; continue
        out_path = os.path.join(OUT_DIR, rel)
        if not _inside(OUT_DIR, out_path) or _under_live_wechat(out_path):
            print(f"[跳过] {rel} —— 输出路径越出 03_解密输出")
            fails.append(rel); fail_n += 1; continue
        print(f"[解密] {rel} ...", end=" ", flush=True)
        ok, msg = decrypt_database(path, out_path, key)
        if ok:
            print(f"成功（{msg}）"); ok_n += 1
        else:
            print(f"失败：{msg}"); fails.append(rel); fail_n += 1
            continue
        for cand in (path + "-wal", path + "-shm", path[:-3] + "-backup", path + "-backup"):
            if not os.path.isfile(cand):
                continue
            try:
                rel_cand = os.path.relpath(cand, SRC_DIR)
            except ValueError:
                print(f"    [跳过附件] {os.path.basename(cand)} 不在副本目录内")
                continue
            dest = os.path.join(OUT_DIR, rel_cand)
            if not _inside(OUT_DIR, dest) or _under_live_wechat(dest):
                print(f"    [跳过附件] {os.path.basename(cand)} 的输出路径不安全")
                continue
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            shutil.copy2(cand, dest)
    print("=" * 50)
    print(f"完成：成功 {ok_n} 个，失败/跳过 {fail_n} 个")
    print(f"解密输出目录: {OUT_DIR}")
    if fails:
        print("失败清单（多为非消息库或密钥不匹配，可忽略非 message 库）:")
        for f_ in fails:
            print("  -", f_)
    print("下一步：运行 第2步_扫描已删除记录.bat")


if __name__ == "__main__":
    main()
