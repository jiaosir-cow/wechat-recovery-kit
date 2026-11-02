# WeChat Recovery Kit

在你自己的 Windows 电脑上，从**只读副本**里找回本人微信 3.x / 4.x 中已删除的聊天。解密和扫描都在本仓库目录里完成，不写回微信的原始数据目录。本仓库不附带取密钥程序。

只处理本人账号。不要用它读取他人聊天。

## 快速开始

需要 Windows 10/11 和 Python 3.10+。

```bat
pip install pycryptodome
```

1. 退出微信。把该账号的整个文件夹复制到 `01_副本存放\`，连同 `.db-wal`、`.db-shm`、`.db-backup`、`*.material` 一起复制。不要把本工具的输出写回原目录。
   - 4.x 默认在 `C:\Users\<用户名>\Documents\xwechat_files\` 下，文件夹名以 `wxid_` 开头。
   - 3.x 默认在 `C:\Users\<用户名>\Documents\WeChat Files\`。
   - 4.x 如果改过位置，在微信「设置 → 存储管理」里查看。
2. 把已经取得的 64 位十六进制密钥写入 `01_副本存放\密钥.txt`（单独一行就是全局密钥，也可以写 `文件名=密钥`）。取 key 工具生成的 `all_keys.json` 放在同一目录时优先使用。密钥与这台电脑和这个账号绑定，只能在登录过该微信的电脑上取得。**本仓库不包含 DbkeyHook、wx_key、wechat-dump-rs 或其他取 key 程序，也不说明如何从进程里提取密钥。**
3. 双击 `第1步_解密数据库.bat`。明文库在 `03_解密输出\`。
4. 双击 `第2步_扫描已删除记录.bat`。结果在 `04_恢复输出\`，先打开 `搜索结果.txt` 和各 `*_关键词上下文.txt`。更换关键词：

```bat
第2步_扫描已删除记录.bat --关键词 某某
```

可选雕刻（在仓库根目录执行）。WAL 解密页写入 `04_恢复输出\`，不会写到 WAL 旁边：

```bat
python tools\wal_carve.py 01_副本存放\<wxid>\db_storage\message\message_fts.db-wal 01_副本存放\<wxid>\db_storage\message\message_fts.db <64位密钥hex>
python tools\carver.py 03_解密输出\<相对路径>\message_fts.db 04_恢复输出\carve.csv --session <会话ID>
```

`wal_carve.py` 的密钥会出现在命令行历史中。`carver.py` 只接受已经解密的库。两条命令在参数不足时会打印用法并退出；`decrypt_all.py` 的现成自检是 `python tools\decrypt_all.py --selftest`（只构造临时测试库，不读取微信目录）。

## 恢复不了什么

- **微信 4.1.x** 的 WCDB 默认打开 **secure_delete**。删除聊天时消息表会被 DROP，释放掉的页会被清零，主库里往往没有正文残留。此后主要只能看 **WAL**（大约最近一两天）、**FTS 残留**、**会话摘要**，以及还在磁盘上的附件。`msg\file` 下的文档可能还在；图片目录可能已经一起删除。
- **3.x / 4.0.x** 的空闲页和 WAL 里通常残留更多。
- 没有正确密钥就解不开。密钥不对时，第 1 步会报 Page1 HMAC 失败，不会假装解密成功。
- 主库页已被清零之后，本仓库不能从磁盘空闲空间里再挖出更早的页。

## 脚本对应关系

| 文件 | 作用 |
|---|---|
| `第1步_解密数据库.bat` → `tools/decrypt_all.py` | 只读 `01_副本存放` 里的 `.db`，自动区分 SQLCipher3（3.x）和 SQLCipher4-WCDB（4.x），以及 raw key / passphrase（passphrase 用 PBKDF2-HMAC-SHA512，迭代 256000）。输出到 `03_解密输出` |
| `第2步_扫描已删除记录.bat` → `tools/scan_all.py` | 对解密库做 sqlite `.recover`、空闲页解析，并在原始字节里搜索关键词，导出命中点前后 300 字节。汇总为 `搜索结果.txt` |
| `tools/carver.py` | 读解密后的库，从 freeblock 和页内未分配区还原删除行，写出 CSV |
| `tools/wal_carve.py` | 解密 WAL 帧，结果写到 `04_恢复输出\<wal文件名>_decrypted_pages.bin` |
| `tools/sqlite3/` | SQLite 官方命令行（Public Domain） |
| `tools/sqlite-parser/` | SQLite-Deleted-Records-Parser 的 Python 3 移植 |

## 目录

```
wechat-recovery-kit\
├─ 01_副本存放\      只放副本和密钥.txt / all_keys.json
├─ 03_解密输出\      第1步产物
├─ 04_恢复输出\      第2步和雕刻产物
├─ tools\
├─ 第1步_解密数据库.bat
└─ 第2步_扫描已删除记录.bat
```

## 安全

- 第 1 步只读 `01_副本存放`，写入 `03_解密输出`。
- `wal_carve.py` 和 `carver.py` 如果发现输出路径位于 `xwechat_files` 或 `WeChat Files` 下，会直接退出，不写文件。
- `密钥.txt` 和 `all_keys.json` 只留在本机。不要提交，不要上传。`.gitignore` 已忽略 `all_keys.json`、数据库和 `03`/`04` 里的产物。仓库里的 `密钥.txt` 只有注释，没有可用密钥。
- 恢复出来的文本是个人通信，用完请自行删除。

## 第三方组件

- **SQLite**（`tools/sqlite3/sqlite3.exe`）：Public Domain，https://sqlite.org
- **SQLite-Deleted-Records-Parser**（Mari DeGrazia / mdegrazia）：`tools/sqlite-parser/sqlparse_v1.3_py3.py` 是其 v1.3 的 Python 3 移植。原作者页面未见明确许可证，此处仅作学习交流分发，版权归原作者。https://github.com/mdegrazia/SQLite-Deleted-Records-Parser
- 取密钥的外部项目未随附二进制。
- Recuva（Piriform）为商业免费软件，本仓库不附带，也不代为分发。

## 免责声明

本工具只用于本人数据的恢复。用它解密他人设备或他人账号可能违法，后果由使用者承担。项目与腾讯公司无关。

## License

本仓库自有代码（`tools/*.py`、批处理、文档）以 [MIT License](LICENSE) 发布。第三方组件遵循各自许可。
