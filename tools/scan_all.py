# -*- coding: utf-8 -*-
"""
第2步 · 批量恢复已删除记录并按关键词搜索
输入：03_解密输出 里的所有 .db（第1步的产物）
输出：04_恢复输出 里的 _recovered.sql / _report.txt / 搜索结果.txt
只读不写源目录。原始字节按块搜索 UTF-8 和 UTF-16LE。用法：python scan_all.py [--关键词 某某]
"""
import os, sys, subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
IN_DIR = os.path.join(ROOT, "03_解密输出")
OUT_DIR = os.path.join(ROOT, "04_恢复输出")
SQLITE3 = os.path.join(HERE, "sqlite3", "sqlite3.exe")
PARSER = os.path.join(HERE, "sqlite-parser", "sqlparse_v1.3_py3.py")
KEYWORD = ""
for i, a in enumerate(sys.argv):
    if a == "--关键词" and i + 1 < len(sys.argv):
        KEYWORD = sys.argv[i + 1]


def run(cmd, out_file=None, timeout=3600):
    try:
        if out_file:
            with open(out_file, "wb") as fo:
                r = subprocess.run(cmd, stdout=fo, stderr=subprocess.PIPE, timeout=timeout)
        else:
            r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return r.returncode, (r.stderr or b"").decode("utf-8", "ignore")[:300]
    except Exception as e:
        return -1, str(e)


def count_deleted_lines(path):
    n = 0
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                if ln.strip():
                    n += 1
    except Exception:
        return 0
    return n


def _under_live_wechat(path):
    norm = os.path.normcase(os.path.abspath(path))
    return ("\\xwechat_files\\" in norm) or ("\\wechat files\\" in norm)


def scan_file_patterns(path, patterns, chunk_size=8 * 1024 * 1024, max_shown=200):
    """分块查找。patterns 是 (名称, 字节串)。不把整个库读进内存。"""
    patterns = [(label, pat) for label, pat in patterns if pat]
    counts = {label: 0 for label, _ in patterns}
    shown = []
    if not patterns:
        return counts, []
    overlap = max(len(pat) - 1 for _, pat in patterns)
    carry = b""
    pos = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            data = carry + chunk
            limit = len(data) if not chunk else max(0, len(data) - overlap)
            base = pos - len(carry)
            for label, pat in patterns:
                start = 0
                while start < limit:
                    i = data.find(pat, start)
                    if i < 0 or i >= limit:
                        break
                    counts[label] += 1
                    if len(shown) < max_shown:
                        shown.append((label, base + i))
                    start = i + 1
            if not chunk:
                break
            carry = data[-overlap:] if overlap else b""
            pos += len(chunk)
        rendered = []
        for label, off in shown:
            start = max(0, off - 300)
            if label == "UTF-16LE" and (off - start) % 2:
                start += 1
            f.seek(start)
            blob = f.read(600)
            text = blob.decode("utf-16-le" if label == "UTF-16LE" else "utf-8", "ignore")
            text = "".join(ch if (ch.isprintable() or ch in "\n\t") else "·" for ch in text)
            rendered.append((label, off, text))
    return counts, rendered


def sample_keyword_lines(path, keyword, limit=500):
    hits = 0
    sample = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for ln in f:
            if keyword in ln:
                hits += 1
                if len(sample) < limit:
                    sample.append(ln[:2000].rstrip("\r\n"))
    return hits, sample


def main():
    global KEYWORD
    if not KEYWORD:
        KEYWORD = input("请输入要搜索的关键词（如联系人备注名）: ").strip()
        if not KEYWORD:
            print("[错误] 关键词不能为空"); sys.exit(1)
    if _under_live_wechat(IN_DIR) or _under_live_wechat(OUT_DIR):
        print("[错误] 输入或输出目录位于微信数据目录下，已停止。请把本仓库放到 xwechat_files / WeChat Files 之外。")
        sys.exit(1)
    if not os.path.isdir(IN_DIR):
        print(f"[错误] 找不到 {IN_DIR}，请先运行第1步")
        sys.exit(1)
    os.makedirs(OUT_DIR, exist_ok=True)
    dbs = []
    for root, _, files in os.walk(IN_DIR):
        for f in files:
            if f.endswith(".db"):
                dbs.append(os.path.join(root, f))
    if not dbs:
        print(f"[错误] {IN_DIR} 里没有 .db 文件，请先运行第1步")
        sys.exit(1)
    has_sqlite3 = os.path.exists(SQLITE3)
    has_parser = os.path.exists(PARSER)
    if not has_sqlite3:
        print(f"[警告] 缺少 {SQLITE3}，跳过 .recover 环节")
    if not has_parser:
        print(f"[警告] 缺少 {PARSER}，跳过空闲页解析环节")

    products = []
    for path in sorted(dbs):
        rel = os.path.relpath(path, IN_DIR)
        tag = rel.replace("\\", "_").replace("/", "_")[:-3]
        print(f"[处理] {rel}")
        if has_sqlite3:
            out_sql = os.path.join(OUT_DIR, tag + "_recovered.sql")
            rc, err = run([SQLITE3, path, ".recover"], out_sql)
            n = count_deleted_lines(out_sql) if os.path.exists(out_sql) else 0
            print(f"    .recover -> {os.path.basename(out_sql)}（{n} 行）" + ("" if rc == 0 else f" [返回码{rc} {err}]"))
            products.append(out_sql)
        if has_parser:
            out_txt = os.path.join(OUT_DIR, tag + "_report.txt")
            rc, err = run([sys.executable, PARSER, "-f", path, "-r", "-o", out_txt])
            print(f"    空闲页解析 -> {os.path.basename(out_txt)}" + ("" if rc == 0 and os.path.exists(out_txt) else f" [返回码{rc} {err}]"))
            if os.path.exists(out_txt):
                products.append(out_txt)

    # 兜底：分块在解密库原始字节里搜关键词，并导出最多 200 处上下文
    patterns = [("UTF-8", KEYWORD.encode("utf-8"))]
    kw16 = KEYWORD.encode("utf-16-le")
    if kw16 != patterns[0][1]:
        patterns.append(("UTF-16LE", kw16))
    raw_hits = []
    raw_total = 0
    for path in dbs:
        try:
            counts, shown = scan_file_patterns(path, patterns)
            c = sum(counts.values())
            if not c:
                continue
            raw_total += c
            tag2 = os.path.relpath(path, IN_DIR).replace("\\", "_").replace("/", "_")[:-3]
            ctx_file = os.path.join(OUT_DIR, tag2 + "_关键词上下文.txt")
            detail = "，".join(f"{label} {counts[label]} 次" for label, _ in patterns if counts[label])
            with open(ctx_file, "w", encoding="utf-8") as cf:
                cf.write(f"库文件：{os.path.relpath(path, IN_DIR)}，关键词「{KEYWORD}」命中 {c} 处（{detail}）\n")
                cf.write("以下片段为命中位置前后的原始内容（含已删除记录的残留），最多 200 处：\n\n")
                for n, (label, off, text) in enumerate(shown, 1):
                    cf.write(f"--- 命中 #{n}，{label}，偏移 {off} ---\n{text}\n\n")
            raw_hits.append(
                f"{os.path.relpath(path, IN_DIR)}: 原始字节命中 {c} 次（{detail}）-> 上下文见 {os.path.basename(ctx_file)}"
            )
        except Exception as e:
            print(f"    [错误] 原始字节扫描失败 {os.path.relpath(path, IN_DIR)}: {type(e).__name__}: {e}")

    # 汇总搜索。按行读取，不把整个恢复产物读进内存。上下文文件另计，避免和恢复产物重复计数。
    result_file = os.path.join(OUT_DIR, "搜索结果.txt")
    total = 0
    with open(result_file, "w", encoding="utf-8") as out:
        out.write(f"搜索关键词：{KEYWORD}\n{'=' * 60}\n")
        for p in products:
            try:
                hits, sample = sample_keyword_lines(p, KEYWORD)
            except Exception as e:
                out.write(f"\n### {os.path.basename(p)} 读取失败：{type(e).__name__}\n")
                continue
            if hits:
                out.write(f"\n### {os.path.basename(p)}（{hits} 条命中）\n")
                for ln in sample:
                    out.write(ln + "\n")
                total += hits
        out.write(f"\n{'=' * 60}\n恢复产物中共命中 {total} 条\n")
        out.write("\n### 解密库原始字节直接命中（未经恢复的关键词残留，命中即说明数据还在库文件里）\n")
        out.write("同时查找 UTF-8 和 UTF-16LE。\n")
        for h in raw_hits:
            out.write(h + "\n")
    print("=" * 50)
    print(f"完成。产物 {len(products)} 个，恢复产物中命中「{KEYWORD}」{total} 条，原始字节命中 {raw_total} 次、{len(raw_hits)} 个库")
    print(f"结果汇总: {result_file}")
    print("用记事本打开 搜索结果.txt 查看；上下文到对应的 _recovered.sql / _report.txt 里搜同一关键词")


if __name__ == "__main__":
    main()
