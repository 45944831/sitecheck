# sitecheck

网站直连检测工具。输入一个域名，逐层定位"为什么打不开"，并只在 hosts 真的能解决时才建议你改 hosts。

```bash
sitecheck github.com
```

---

## 它能回答什么

1. **这个站的真实 IP 是多少** —— 判定依据是 TLS 证书 SAN 匹配，不是 DNS 说什么。DNS 被污染成别家 IP 时，它会如实报"未能确认"，不会把伪造 IP 当真的给你。
1. **有没有可用的备用地址** —— 从证书 SAN 里筛出同站备用域名（如 `github.com` 的 `www.github.com`），逐个探测后列出哪些真能用。共享证书上的跨品牌域名会被过滤，不会把陌生站点当备用地址推荐；SNI 被切断、拿不到证书时该区块不出现，不猜地址。
2. **能不能直连**
3. **不能连的话卡在哪一层**
   | 阻断点 | 含义 | 改 hosts 有用吗 |
   |---|---|---|
   | `DNS` | 域名解析不出记录 | 不适用 |
   | `TCP` | 服务器 443 端口连不上 | 无效 |
   | `TLS/SNI` | TCP 能连但握手被切断 | **无效**，hosts 够不到 SNI 层 |
   | `DNS 污染` | 解析到的 IP 上不是你要访问的站 | 有效（前提是能找到真 IP） |
   | `HTTP_NO_RESPONSE` | 证书正常，但 HTTP 层没响应 | 无效，检查代理 / 防火墙 |
   | `HTTP_REJECT` | 拿到 4xx/5xx，链路是通的 | 无效，问题在服务端策略 |
   | `PROXY_REQUIRED` | 直连不通，但经代理可访问 | **无效**，是本机代理配置问题 |
   | `INCONCLUSIVE` | 控制组也不通，本机出网受限 | 先修网络 |
4. **能不能靠改 hosts 解决** —— 只有「DNS 给的 IP 全不通，但存在证书匹配且能正常响应的其他 IP」时才建议改，并直接给出可粘贴的条目。DNS 本身正常时不会误导你去改 hosts；如果本机**已经有**该域名的 hosts 条目，会先指出其中哪些已失效——hosts 优先于 DNS，坏条目会覆盖正常解析，先清理再复测。
5. **证据有多硬** —— 每条结论标注证据强度（强 / 中 / 弱）。TLS/SNI 阻断会额外做一次 SNI 对照实验：换无关域名对同一 IP 握手，能通即证实是域名级阻断；无 IPv6 出口时会说明 AAAA 不可达只是环境限制。
6. **是不是链路在抖动** —— 同一 IP 在不同探测阶段得出相反结论（如主探测 TLS 成功、备用域名探测超时）时，给出可核对的反证并把结论降级为「响应不稳定，建议复测」，不把一次丢包写成稳定故障。
7. **链路可用时才给优化建议** —— DNS 延迟对比、HTTP/2、TLS 版本、证书到期、跳转、首字节耗时；失败场景只给诊断信息，不会说「换个 DNS 就能解决」。

每条结论都附带**依据**（为什么这么判）和**下一步**（现在该做什么），两者分开。报告里只放人能执行的操作；带 `sitecheck` 命令的提示只在命令行终端显示，不会出现在 GUI 或导出的报告里。

---

## 安装

### 直接下载（Windows x64）

从 [Releases](https://github.com/45944831/sitecheck/releases) 下载 `sitecheck-*-windows-x64.zip`，解压后整个文件夹一起保留（`sitecheck.exe` 依赖同目录的 `_internal`），双击即可运行，无需 Python 环境。

### 从源码

```bash
git clone https://github.com/45944831/sitecheck.git
cd sitecheck
pip install -e ".[gui]"        # 只要命令行的话：pip install -e .
```

安装后可以直接用 `sitecheck` 命令。

---

## 用法

### 命令行

```bash
sitecheck github.com                          # 检测
sitecheck github.com --ip 1.2.3.4             # DNS 被污染时手动指定真实 IP
sitecheck github.com --report out.md          # 导出 Markdown
sitecheck github.com --json out.json --html out.html
sitecheck github.com --apply-hosts            # 直接写入 hosts 并刷新缓存（需管理员）

sitecheck hosts                               # 列出 hosts 条目
sitecheck hosts --audit                       # 体检：逐条探测是否真的可用
sitecheck hosts --backups                     # 列出备份
sitecheck hosts --restore                     # 还原最新备份
sitecheck hosts --restore 1                   # 还原第 1 个（0 是最新）

sitecheck dns-bench                           # 公共 DNS 延迟 / 防污染基准测试
sitecheck github.com --watch --interval 60    # 持续监控，只记录变化，不自动改 hosts
sitecheck --profile github                    # 一次检查主站 / API / Raw / 下载四条链路
sitecheck family github                       # 核验 GitHub 全部 40 个关联域名（图片/下载/API/Copilot…）
sitecheck family github --apply-hosts         # 把检测到可用真实 IP 的域名批量写入 hosts
sitecheck --version
```

`--watch` 用 `--count N` 限定检测次数、`--confirm N` 过滤抖动（连续 N 次同状态才算变化）、`--watch-json <路径>` 导出事件时间线。退出码取最后一次检测的结论。

`--profile` 并发检测多条链路，给出聚合结论；部分可用时退出码为 20，任何一条证据不足时整体判为无法判定，不会含糊报"部分可用"。

### 域名族核验（`family`）

解决"只修了 github.com，网页能开但图片/下载照样挂"的问题：一次发现并检测一个服务的**整族关联域名**。

```bash
sitecheck family github                 # 核验全部 40 个域名，按分组列出状态
sitecheck family github --json r.json   # 同时导出 JSON
sitecheck family github --apply-hosts   # 批量写入（先展示完整改动计划再确认）
```

域名清单来自 GitHub520 与 GitHub 官方 meta API 交叉核对（2026-11-17），共 40 个：31 个落在 GitHub 自有 IP 段、适合固定 hosts；9 个走第三方 CDN（S3 / Fastly / Azure），**只检测、不写入**（写了反而容易失效）。候选 IP 一律运行时现取并做 TLS 证书校验，不因情报源声称可用就直接写入。

状态含义：`可用`（当前系统解析的 IP 就能用）、`可修复`（当前不通但找到了已验证的真实 IP，`--apply-hosts` 会写这些）、`不可用`（候选 IP 均未通过证书校验，多为间歇性网络封锁）、`无法判定`（证据不足）。

⚠️ 批量写入会逐个域名替换 hosts 条目，每个域名写入前单独备份；写入后统一刷新 DNS 缓存。需要管理员权限。第三方 CDN 域名自动排除。

**退出码**（便于脚本按结论分支）：

```
0 可直连 | 2 参数错误 | 3 无法判定 | 4 报告写入失败
10 服务端拒绝 | 11 需代理 | 12 应用层无响应 | 13 DNS 污染
14 TLS/SNI 阻断 | 15 TCP 不通 | 16 解析失败 | 19 未知 | 20 部分可用
```

只判断成功 / 失败的旧脚本行为不变。JSON 报告带 `schema_version`（当前 5），字段含义变化时才递增。每条结论都带 `evidence`（为什么这么判）、`fix_hint`（人能执行的下一步）与 `cli_hint`（命令行专用，仅终端显示），三者分开。

`sitecheck github.com` 与 `sitecheck check github.com` 等价 —— 保留 v1.0 的调用方式。

### 图形界面

```bash
sitecheck-gui
```

- **单站检测**：完整详情，结论区说明依据；左侧日志保留每一步耗时
- **批量检测**：一次输入多个域名，表格展示结论 / 阻断点 / 真实 IP / HTTP / 耗时，可导出 CSV
- **写入 hosts**：只在真的需要写时才亮起；点击后先展示改动预演，确认后自动备份、写入、刷新缓存（需管理员）
- **导出**：Markdown / JSON / HTML

窗口可缩放、可最大化，进度条是确定的。

---

## 判定是怎么做的

完整说明见 [`docs/design.md`](docs/design.md)。核心原则：

**「能连通」不等于「返回 2xx」。** 判定标准是 TCP 通 + TLS 握手成功 + 证书匹配 + 拿到合法 HTTP 响应，与状态码无关。走 Cloudflare 返回 403 的站点，链路其实是通的。

**「没收到响应」不等于「服务端拒绝」。** 一个字节都没收到是链路问题，拿到 403 才是服务端策略问题。这两件事的处理方式完全不同，所以必须分开报。

**候选 IP 必须包含 hosts 文件里已有的条目。** 用户问"这个域名能不能访问"时，真正想问的往往是"我现在 hosts 里这条还能不能用"。只探测 DNS 解析结果会漏掉用户当前的生效配置——DNS 被污染时那些解析结果全是假 IP。

**候选 IP 还有一个不依赖本机解析的来源。** DNS 被污染时本机所有解析结果都可能是假的，此时会从远程 hosts 情报源（默认 GitHub520，可用 `SITECHECK_REMOTE_HOSTS_URL` 覆盖）取候选。它只是"情报"不是"证据"—— 仍必须通过证书校验才会被认定为真实 IP；源不可达时静默降级，不影响检测。

**控制组有否决权。** 控制组（多个不同运营商的站点）全部不通时，说明本机出网受限，此时"目标站点 TCP 不通"的结论毫无意义，直接判 `INCONCLUSIVE`，而不是把责任推给目标站。

**探测方式和用户实际访问方式必须一致。** 浏览器走系统代理，工具也测一遍代理路径。直连不通、经代理可通时，明确告诉你这是本机代理配置问题，不要改 hosts。

**结论和用户实际体验冲突时，先怀疑工具。**

---

## 几个实现上的判断

**并发是必须的，不是优化。** v1.0 三层全串行，单个死 IP 就吃掉 8 秒超时，6 个候选 IP 实测 53 秒。现在 DNS、控制组、逐 IP 探测全部并发，并且探测分两阶段（先并发 TCP 筛掉死的，再并发做 TLS + HTTP），同一场景约 3~8 秒。能直连的站点实测 2~4 秒；站点被黑洞（TCP 通但 HTTP 一个字节不回）时最坏约 16 秒 —— 那段等待省不掉，它正是"服务端慢"和"链路被切断"的分界线。

**本机解析与远端解析分区呈现。** 报告里 6 家 UDP DNS 归在「本机解析」，3 个 DoH 端点归在「远端解析」，逐 IP 探测的来源列也分别标注「解析」和「远端 DoH」——两者给出不同 IP 时一眼可辨。远端解析只是候选，同样要过证书校验才算真实 IP；换来源不会改变判定逻辑。注意远端 IP 也可能已被污染（实测部分境外域名经 DoH 仍拿到假 IP），所以真相标准始终是证书匹配，不是"谁离用户更远"。

**DoH 强制不走代理。** 加密 DNS 和普通 DNS 必须走同一条网络路径，否则"两者结果不同 = 污染"这个推论就不成立。

**证书链不可信不等于无法判定。** 自签 / 私有 CA 站点会降级重试，只取证书内容判 SAN，并标注"链不可信"，而不是直接放弃。

**hosts 按原编码写回。** 读 `utf-8-sig` 写 `utf-8` 会把原文件里的 GBK 注释变成乱码，这是不可逆损坏。现在检测编码后原样写回，并用临时文件 + 原子替换，中途失败不会留下半截 hosts。

**备份不放在 `etc` 目录。** 改到 `%LOCALAPPDATA%\sitecheck\backups`，保留最近 10 份，并提供 `--restore` 一键回滚。

---

## 开发

```bash
pip install -e ".[dev,gui]"
pytest -q                     # 222 个测试，全部不依赖网络
ruff check src tests
python build.py               # 打包 onedir（默认）
python build.py onefile       # 单文件，启动 23~35 秒，不推荐
```

### 结构

```
src/sitecheck/
├── models.py        数据结构（无 IO，判定层只依赖它）
├── dns.py           DNS：A/AAAA、CNAME 链、TCP 回退、DoH
├── proxy.py         系统代理探测（WinINET / PAC / 环境变量）+ CONNECT 隧道
├── probe.py         TCP / TLS / HTTP 探测，证书 SAN 匹配
├── verdict.py       判定树（纯函数，可脱离网络测试）
├── orchestrator.py  并发调度
├── hosts.py         hosts 读写（编码保留、原子替换、备份还原）
├── audit.py         hosts 体检
├── dnsbench.py      DNS 基准测试
├── render.py        Markdown / JSON / HTML
├── exitcodes.py     语义化退出码
├── watch.py         持续监控与事件时间线（抖动抑制）
├── profile.py       服务画像：多链路并发检测与聚合判定
├── family.py        服务域名族清单（用途分组、是否适合固定 hosts）
├── familycheck.py   域名族轻量核验与批量写入计划
├── altdomains.py    证书 SAN 同站备用域名发现、跨品牌过滤与可用性探测
├── cdn.py           CDN / Anycast 归属识别（只做解释性提示）
└── cli.py           命令行入口
src/sitecheck_gui/app.py     PyQt5 界面
```

**核心不变量**：`verdict.py` 不 import 任何 IO 模块。判定逻辑只吃 dataclass，所以每个分支都能用构造的数据测到——这是 v1.0 最缺的东西，也是"控制组不通却仍报 TCP 不通"这类 bug 能长期存在的原因。

---

## 注意

- 除「写入 hosts」外，本工具是只读的，不修改任何系统配置
- 改 hosts 需要管理员权限
- 本工具发的是极简请求头，服务端返回 403/429 多半是反爬 / 地域 / WAF，不代表浏览器打不开
- 网络存在抖动：同一个域名连续检测，个别 IP 的 TCP 结果可能不同。这是网络本身的不确定性，不是工具缓存

## 许可

[MIT](LICENSE)
