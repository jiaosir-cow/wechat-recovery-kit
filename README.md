# WeChat Recovery Kit · 微信聊天记录删除恢复工具箱

Windows 电脑版微信（**3.x 老版 / 4.x 新版**）"右键删除聊天"后的**本地数据恢复流水线**。
全程离线运行、只读源数据、副本操作，面向普通用户的双击式流程 + 面向取证的手工雕刻工具。

> ⚠️ **合法用途**：仅限恢复**你本人账号**的微信数据。请勿用于获取他人聊天记录。

---

## 功能一览

| 模块 | 作用 |
|---|---|
| `第1步_解密数据库.bat` → `tools/decrypt_all.py` | 遍历副本目录，**自动识别 3.x / 4.x 加密格式**（SQLCipher3 / SQLCipher4-WCDB），**自动识别密钥形态**（raw key / passphrase，后者按 PBKDF2-HMAC-SHA512×256000 推导），批量解密全部数据库 |
| `第2步_扫描已删除记录.bat` → `tools/scan_all.py` | 对解密库执行 sqlite `.recover`、空闲页解析、**关键词原始字节扫描并导出命中点前后 300 字节上下文**（被删内容常以此形式残留），汇总 `搜索结果.txt` |
| `tools/carver.py` | SQLite 删除行雕刻器：解析每页 freeblock 链与页内未分配区，还原被删记录（支持按会话 ID 精确过滤） |
| `tools/wal_carve.py` | 解密微信 **WAL 日志帧**（历史页镜像），已删除会话的索引行常能在日志帧里捞回 |
| `tools/sqlite3/` | SQLite 官方命令行（Public Domain） |
| `tools/sqlite-parser/` | SQLite-Deleted-Records-Parser 的 Python3 移植版（致谢见下） |

## 快速开始

**环境**：Windows 10/11 + Python 3.10+（`pip install pycryptodome`）。解密/扫描在本仓库目录内完成，**不碰微信原始数据**。

1. **复制数据副本**：在登录微信的电脑上退出微信，把数据目录里 `wxid_` 开头的整个账号文件夹复制到本仓库的 `01_副本存放\`。
   - 4.x 默认位置：`C:\Users\<用户名>\Documents\xwechat_files\`
   - 3.x 默认位置：`C:\Users\<用户名>\Documents\WeChat Files\`
   - 微信 4.x 若改过存储位置：微信「设置 → 存储管理」里查看。
   - 连同所有 `.db-wal / .db-shm / .db-backup / *.material` 文件一起复制。
2. **取解密密钥**（必须在登录微信的那台电脑上做，密钥与机器+账号绑定）：
   - 微信 4.x：用注入式取 key 工具，例如 [DbkeyHook](https://github.com/gzygood/DbkeyHook)（Hook 方式，4.1.x 可用），或 wx_key（原仓已清空，需自行寻找可信镜像，注意甄别）。
   - 微信 3.x：历史上的 chatlog / wechat-dump-rs 等项目已被 DMCA 下架，请自行寻找镜像或替代方案。
   - 拿到 64 位十六进制密钥后填入 `01_副本存放\密钥.txt`（模板已附，单独一行即为全局密钥，也支持 `文件名=密钥` 逐库指定，或 `all_keys.json`）。
3. **双击 `第1步_解密数据库.bat`** → 解密产物在 `03_解密输出\`。
4. **双击 `第2步_扫描已删除记录.bat`** → 恢复产物在 `04_恢复输出\`，先看 `搜索结果.txt` 和各 `*_关键词上下文.txt`。换关键词：`第2步_扫描已删除记录.bat --关键词 某某`。
5. **日志深挖（可选）**：
   ```
   python tools\wal_carve.py 01_副本存放\<wxid>\db_storage\message\message_fts.db-wal 01_副本存放\<wxid>\db_storage\message\message_fts.db <64位密钥hex>
   python tools\carver.py 03_解密输出\<...>\message\message_fts.db 输出.csv --session <会话ID>
   ```

## 恢复效果与限制（实测结论）

- **4.1.x（约 2025 年底起）** 的 WCDB 默认开启 **secure_delete**：删除聊天时消息表被 DROP、释放页内容**立即清零**，主库内基本无残留；此时主要恢复来源是 **WAL 日志帧**（窗口约最近一两天）、**fts 索引残留**、**会话摘要历史**、以及**聊天附件**（`msg\file` 下的文档不随删除清除，图片目录会被一并删除）。
- **3.x / 4.0.x**：数据库空闲页与 WAL 中残留更多，删除行恢复率明显更高。
- 想进一步提高找回率：对数据盘做**空闲空间镜像**（FTK Imager 等），再对镜像中的旧日志帧做密钥扫描。

## 目录约定

```
wechat-recovery-kit\
├─ 01_副本存放\      ← 微信数据副本放这里（密钥.txt 也放这里）
├─ 03_解密输出\      ← 第1步产物
├─ 04_恢复输出\      ← 第2步产物
├─ tools\            ← 全部脚本与工具
├─ 第1步_解密数据库.bat
└─ 第2步_扫描已删除记录.bat
```

## 安全与隐私

- 所有操作只读 `01_副本存放`，输出写入 03/04 目录，绝不修改源数据。
- 密钥仅存于本机 `密钥.txt`，**请勿将其提交到任何仓库或上传到网络**。
- 恢复产物含个人通信内容，请妥善保管、及时清理。

## 致谢与第三方组件许可

- **SQLite**（`tools/sqlite3/sqlite3.exe`）：Public Domain，https://sqlite.org
- **SQLite-Deleted-Records-Parser**（Mari DeGrazia / mdegrazia）：`tools/sqlite-parser/sqlparse_v1.3_py3.py` 为其 v1.3 的 Python3 移植版（原作者页面未见明确许可证，仅作学习交流分发，版权归原作者），https://github.com/mdegrazia/SQLite-Deleted-Records-Parser
- 取密钥环节依赖的开源项目（DbkeyHook、wx_key、wechat-decrypt 等）因版权与合规原因**未随附二进制**，请从上方链接处自行获取并遵守其许可。
- 数据恢复软件 Recuva（Piriform）为商业免费软件，不允许再分发，请从官网下载：https://www.ccleaner.com/recuva/download

## 免责声明

本工具仅供数据恢复技术研究与个人数据自救使用。使用本工具访问、解密他人设备或他人账号数据可能违反法律法规与平台协议，后果由使用者自负。项目与腾讯公司无任何关联。

## License

本仓库自有代码（`tools/*.py`、批处理、文档）以 [MIT License](LICENSE) 发布。
第三方组件遵循其各自许可（见上）。
