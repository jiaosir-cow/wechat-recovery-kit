# -*- coding: utf-8 -*-
"""
SQLite 删除行雕刻器：解析解密库的每一页，从 freeblock 链和页内未分配区
还原被删除的记录。输出 CSV：页码, 来源, 创建时间, 列值...
用法：python carver.py <解密后的db> <输出.csv> [--session 32] [--msgmode]
只读输入文件。
"""
import os, sys, struct, csv, datetime

PAGE_SZ = 4096
RESERVE = 80          # 微信4.x解密页 usable=4016
USABLE = PAGE_SZ - RESERVE


def varint(buf, off):
    """SQLite 变长整数，返回 (值, 消耗字节数)"""
    val = 0
    for i in range(9):
        if off + i >= len(buf):
            return None, 0
        b = buf[off + i]
        if i == 8:
            return (val << 8) | b, 9
        val = (val << 7) | (b & 0x7f)
        if not (b & 0x80):
            return val, i + 1
    return None, 0


def parse_record(buf, off, avail):
    """在 buf[off:off+avail] 尝试解析 record，返回 (列值列表, 消耗) 或 None"""
    hlen, n = varint(buf, off)
    if hlen is None or hlen < 2 or hlen > avail or hlen > 400:
        return None
    types = []
    p = off + n
    while p < off + hlen:
        t, m = varint(buf, p)
        if t is None or m == 0:
            return None
        types.append(t)
        p += m
    if not (2 <= len(types) <= 30):
        return None
    vals = []
    q = off + hlen
    for t in types:
        if t == 0:
            vals.append(None)
        elif t in (1, 2, 3, 4, 5, 6):
            sz = (1, 2, 3, 4, 6, 8)[t - 1]
            if q + sz > off + avail:
                return None
            vals.append(int.from_bytes(buf[q:q + sz], "big", signed=True))
            q += sz
        elif t == 7:
            if q + 8 > off + avail:
                return None
            vals.append(struct.unpack(">d", buf[q:q + 8])[0])
            q += 8
        elif t == 8:
            vals.append(0)
        elif t == 9:
            vals.append(1)
        elif t in (10, 11):
            return None
        else:
            ln = (t - 12) // 2 if t % 2 == 0 else (t - 13) // 2
            if ln < 0 or q + ln > off + avail:
                return None
            raw = bytes(buf[q:q + ln])
            if t % 2 == 1:
                try:
                    vals.append(raw.decode("utf-8"))
                except Exception:
                    return None
            else:
                vals.append(raw)
            q += ln
    return vals, (q - off)


def extract_text(v):
    """从 blob（protobuf）里抽可读 UTF-8 文本"""
    if isinstance(v, str):
        return v
    if not isinstance(v, (bytes, bytearray)):
        return ""
    s = v.decode("utf-8", "ignore")
    out, cur = [], []
    for ch in s:
        if ch.isprintable() and ch not in "\x0b\x0c":
            cur.append(ch)
        else:
            if len(cur) >= 2:
                out.append("".join(cur))
            cur = []
    if len(cur) >= 2:
        out.append("".join(cur))
    return " | ".join(out)


def carve_page(page, pgno, want_session, msgmode, rows_out):
    if not page or page[0] != 0x0D:  # 只处理叶子表页
        # free page 可能是 0x00 起始（被覆盖），尝试整页 brute force 仅 msgmode
        return
    usable = page[:USABLE]
    fb_head = struct.unpack(">H", usable[1:3])[0]
    ncell = struct.unpack(">H", usable[3:5])[0]
    cell_start = struct.unpack(">H", usable[5:7])[0]
    if cell_start == 0:
        cell_start = 65536
    hdr_sz = 8

    regions = []  # (起点, 可用长度, 来源)
    # 1) freeblock 链
    fb = fb_head
    guard = 0
    while fb and fb < USABLE and guard < 500:
        guard += 1
        nxt, sz = struct.unpack(">HH", usable[fb:fb + 4])
        if sz < 4 or fb + sz > USABLE + 4:
            break
        regions.append((fb + 4, sz - 4, "freeblock"))
        fb = nxt
    # 2) 未分配区（cell 指针数组末端 ~ cell 内容区起点）
    ua_start = hdr_sz + ncell * 2
    ua_end = min(cell_start, USABLE)
    if ua_end - ua_start > 12:
        regions.append((ua_start, ua_end - ua_start, "unalloc"))

    for start, length, kind in regions:
        # 在区域内逐偏移尝试 record 解析
        off = start
        end = start + length
        while off < end - 8:
            r = parse_record(usable, off, end - off)
            if r is None:
                off += 1
                continue
            vals, used = r
            ok = False
            session = None
            if want_session is not None:
                # fts 结构：text, int, int, int, session, sender, time
                ints = [v for v in vals if isinstance(v, int)]
                if want_session in ints:
                    session = want_session
                    ok = True
            elif msgmode:
                # Msg 结构：id, server_id, type, sort_seq, sender, create_time,...
                if (len(vals) >= 13 and isinstance(vals[2], int) and 0 < vals[2] < 100000
                        and isinstance(vals[5], int) and 1500000000 < vals[5] < 1900000000):
                    ok = True
            else:
                ok = True
            if ok:
                rows_out.append((pgno, kind, off, vals))
                off += max(used, 1)
            else:
                off += 1


def _under_live_wechat(path):
    norm = os.path.normcase(os.path.abspath(path))
    return ("\\xwechat_files\\" in norm) or ("\\wechat files\\" in norm)


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help") or len(args) < 2:
        print("用法: python carver.py <解密后的db> <输出.csv> [--session N] [--msgmode]")
        print("只读数据库。拒绝把 CSV 写进微信数据目录（xwechat_files / WeChat Files）。")
        sys.exit(0 if args and args[0] in ("-h", "--help") else 2)
    db_path, out_csv = args[0], args[1]
    if _under_live_wechat(out_csv):
        print("[错误] 拒绝把 CSV 写进微信数据目录。请改到本仓库的 04_恢复输出。")
        sys.exit(1)
    want_session = None
    msgmode = False
    for i, a in enumerate(args):
        if a == "--session" and i + 1 < len(args):
            want_session = int(args[i + 1])
        if a == "--msgmode":
            msgmode = True
    sz = os.path.getsize(db_path)
    npages = sz // PAGE_SZ
    rows_out = []
    skipped = 0
    with open(db_path, "rb") as f:
        for pgno in range(1, npages + 1):
            page = f.read(PAGE_SZ)
            if len(page) < PAGE_SZ:
                break
            try:
                carve_page(page, pgno, want_session, msgmode, rows_out)
            except Exception:
                skipped += 1
                continue
    print(f"扫描 {npages} 页，还原记录 {len(rows_out)} 条，跳过无法解析的页 {skipped} 页")
    with open(out_csv, "w", newline="", encoding="utf-8-sig") as fo:
        w = csv.writer(fo)
        w.writerow(["页码", "来源", "偏移", "列数", "创建时间", "发送者/会话", "类型", "文本", "原始列"])
        for pgno, kind, off, vals in rows_out:
            ts, sender, ltype, text = "", "", "", ""
            ints = [v for v in vals if isinstance(v, int)]
            for v in ints:
                if 1500000000 < v < 1900000000:
                    ts = datetime.datetime.fromtimestamp(v).strftime("%Y-%m-%d %H:%M:%S")
                    break
            if len(vals) > 4 and isinstance(vals[4], int):
                sender = str(vals[4])
            if len(vals) > 2 and isinstance(vals[2], int):
                ltype = str(vals[2])
            texts = [extract_text(v) for v in vals if isinstance(v, (str, bytes, bytearray))]
            text = max(texts, key=len) if texts else ""
            w.writerow([pgno, kind, off, len(vals), ts, sender, ltype, text[:2000],
                        "|".join(str(v)[:60] for v in vals)])
    print("已写出:", out_csv)


if __name__ == "__main__":
    main()
