# 更新日志

本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## 2.0.0 — 2026-10-29

首个重构版本。v1.0 的判定思路是对的，但大量结论没有真正落到代码里：控制组算出来了却不参与判定、
HTTP 收不到任何字节也被当成"反爬"、证书通配符匹配漏掉一个点导致误判。这一版把这些补上，
并把单文件拆成可测试的包。

### 判定更可信

- **控制组真正参与判定**。v1.0 里控制组只被打印、从不参与结论；现在控制组全部不通时直接判
  `INCONCLUSIVE`（本机出网受限），不再把责任推给目标站点。
- **区分"反爬"和"链路不通"**。HTTP 结果拆成 `OK` / `REJECT` / `NO_RESPONSE` / `MALFORMED`。
  一个字节都没收到（`NO_RESPONSE`）是链路问题，不是反爬，两者处理方式完全不同。
- **新增 `PROXY_REQUIRED`**。直连不通、经代理可访问时，明确指出问题在本机代理配置，而不是让人去改 hosts。
- **证书 SAN 匹配按 RFC 6125 修正**。v1.0 用 `host.endswith(name[2:])` 匹配通配符，漏掉了点，
  导致 `*.example.com` 会命中 `evilexample.com`。实测 3 个反例全部误判为"证书匹配"。

### 快了一个数量级

- DNS 解析、控制组校验、逐 IP 探测全部并发，探测再分两阶段（先并发 TCP 筛掉死的，再并发做 TLS + HTTP）。
  同一场景 v1.0 实测 53 秒，现在能直连的站点 2~4 秒。
- 分层超时：TCP 4 秒 / TLS 6 秒 / HTTP 6 秒 / 代理对照 4 秒。各层该等多久本来就不一样，共用一个 8 秒既慢又粗糙。
- 站点被黑洞（TCP 通但 HTTP 一个字节不回）时最坏约 16 秒——这段等待省不掉，它正是"服务端慢"和
  "链路被切断"的分界线。

### 探测覆盖更全

- 支持 AAAA 记录与 CNAME 链。
- DoH 强制不走代理：加密 DNS 和普通 DNS 必须走同一条路径，否则"两者结果不同 = 污染"这个推论不成立。
- 证书链不可信（自签 / 私有 CA）时降级重试，只取证书内容判 SAN 并标注"链不可信"，而不是直接放弃。
- 控制组不再硬编码 IP。v1.0 把 GitHub 的 IP 写死在代码里，那个 IP 早已失效，控制组形同虚设。

### 工程化

- 单文件 `sitecheck.py`（746 行）拆成 `src/sitecheck/` 包：`models` / `dns` / `proxy` / `probe` /
  `verdict` / `orchestrator` / `hosts` / `audit` / `dnsbench` / `render` / `cli`。
- `verdict.py` 保持零 IO（不 import socket/ssl/urllib），判定树因此可以被完整单测。
- 84 个离线单元测试，全部不依赖网络。
- GitHub Actions：CI 覆盖 Linux/Windows × Python 3.10/3.12/3.13；打 tag 自动打包并发布。
- 删除 6 个遗留脚本，移除所有硬编码的本机绝对路径。
- `dist/` 不再入库（原来 98MB 二进制躺在仓库里）。

### 界面与报告

- 窗口可缩放（v1.0 是固定尺寸）；进度条确定化；日志与结果分栏。
- 新增批量检测标签页，一次输入多个域名，结果表格可导出 CSV。
- 报告支持 Markdown / JSON / HTML 三种格式。
- hosts 备份移到 `%LOCALAPPDATA%\sitecheck\backups`，保留最近 10 份，新增 `hosts --restore` 一键回滚。
- 修复打包为无控制台程序后中文输出乱码的问题。

### 不兼容变更

- 模块结构由单文件改为 `src/sitecheck` 包，作为库引用时 import 路径全部变化。
- **命令行用法保持兼容**：`sitecheck github.com` 仍然可用，不带子命令时等价于 `sitecheck check github.com`。

## 1.0 — 2026-10-01

首个公开版本：CLI + PyQt5 图形界面，按 DNS / TCP / TLS / HTTP 逐层定位打不开的原因，
仅在 hosts 真能解决问题时才建议修改。
