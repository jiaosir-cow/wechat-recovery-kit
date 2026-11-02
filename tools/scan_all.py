# -*- coding: utf-8 -*-
"""
第2步 · 批量恢复已删除记录并按关键词搜索
输入：03_解密输出 里的所有 .db（第1步的产物）
输出：04_恢复输出 里的 _recovered.sql / _report.txt / 搜索结果.txt
只读不写源目录。用法：python scan_all.py [--关键词 某某]
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
    try:
        with open(path, "rb") as f:
            data = f.read().decode("utf-8", "ignore")
        return sum(1 for ln in data.splitlines() if ln.strip())
    except Exception:
        return 0


def main():
    global KEYWORD
    if not KEYWORD:
        KEYWORD = input("请输入要搜索的关键词（如联系人备注名）: ").strip()
        if not KEYWORD:
            print("[错误] 关键词不能为空"); sys.exit(1)
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

    # 兜底：直接在解密库原始字节里搜关键词（UTF-8），并导出命中位置的上下文片段
    kw_bytes = KEYWORD.encode("utf-8")
    raw_hits = []
    for path in dbs:
        try:
            with open(path, "rb") as f:
                data = f.read()
            c = data.count(kw_bytes)
            if not c:
                continue
            tag2 = os.path.relpath(path, IN_DIR).replace("\\", "_").replace("/", "_")[:-3]
            ctx_file = os.path.join(OUT_DIR, tag2 + "_关键词上下文.txt")
            with open(ctx_file, "w", encoding="utf-8") as cf:
                cf.write(f"库文件：{os.path.relpath(path, IN_DIR)}，关键词「{KEYWORD}」命中 {c} 处\n")
                cf.write("以下片段为命中位置前后的原始内容（含已删除记录的残留）：\n\n")
                pos, shown = 0, 0
                while shown < 200:
                    i = data.find(kw_bytes, pos)
                    if i < 0:
                        break
                    seg = data[max(0, i - 300): i + 300].decode("utf-8", "ignore")
                    seg = "".join(ch if (ch.isprintable() or ch in "\n\t") else "·" for ch in seg)
                    cf.write(f"--- 命中 #{shown + 1}，偏移 {i} ---\n{seg}\n\n")
                    pos = i + 1
                    shown += 1
            raw_hits.append(f"{os.path.relpath(path, IN_DIR)}: 原始字节命中 {c} 次 -> 上下文见 {os.path.basename(ctx_file)}")
            products.append(ctx_file)
        except Exception as e:
            print(f"    [错误] 原始字节扫描失败 {os.path.relpath(path, IN_DIR)}: {type(e).__name__}: {e}")

    # 汇总搜索
    result_file = os.path.join(OUT_DIR, "搜索结果.txt")
    total = 0
    with open(result_file, "w", encoding="utf-8") as out:
        out.write(f"搜索关键词：{KEYWORD}\n{'=' * 60}\n")
        for p in products:
            try:
                with open(p, "rb") as f:
                    text = f.read().decode("utf-8", "ignore")
            except Exception:
                continue
            hits = [ln for ln in text.splitlines() if KEYWORD in ln]
            if hits:
                out.write(f"\n### {os.path.basename(p)}（{len(hits)} 条命中）\n")
                for ln in hits[:500]:
                    out.write(ln[:2000] + "\n")
                total += len(hits)
        out.write(f"\n{'=' * 60}\n恢复产物中共命中 {total} 条\n")
        out.write("\n### 解密库原始字节直接命中（未经恢复的关键词残留，命中即说明数据还在库文件里）\n")
        for h in raw_hits:
            out.write(h + "\n")
    print("=" * 50)
    print(f"完成。产物 {len(products)} 个，恢复产物中命中「{KEYWORD}」{total} 条，原始字节命中 {len(raw_hits)} 个库")
    print(f"结果汇总: {result_file}")
    print("用记事本打开 搜索结果.txt 查看；上下文到对应的 _recovered.sql / _report.txt 里搜同一关键词")


if __name__ == "__main__":
    main()
