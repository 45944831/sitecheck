# sitecheck

网站直连检测工具。输入一个域名，逐层定位"为什么打不开"，并只在 hosts 真的能解决时才建议你改 hosts。

## 下载

[**v1.0 · Windows x64（zip，37 MB）**](https://github.com/45944831/sitecheck/releases/download/v1.0/sitecheck-v1.0-windows-x64.zip)

解压后整个文件夹一起保留（`sitecheck.exe` 依赖同目录的 `_internal`），双击即可运行，无需 Python 环境。

## 它能回答什么

1. **这个站的真实 IP 是多少** —— 判定依据是 TLS 证书 SAN 匹配，不是 DNS 说什么。DNS 被污染成别家 IP 时，它会如实报"未能确认"，不会把伪造 IP 当真的给你。
2. **能不能直连**
3. **不能连的话卡在哪一层**
   - `DNS` —— 域名解析不出记录
   - `TCP` —— 服务器 443 端口连不上
   - `TLS/SNI` —— TCP 能连但握手被切断。**这种情况改 hosts 无效**，hosts 工作在 DNS 层，够不到 SNI
   - `DNS 污染` —— 解析到的 IP 上根本不是你要访问的站
   - `HTTP_REJECT` —— 链路通，但服务端返回 4xx/5xx（多为反爬 / 地域 / WAF，不代表浏览器打不开）
4. **能不能靠改 hosts 解决** —— 只有「DNS 给的 IP 全不通，但存在证书匹配且能正常响应的其他 IP」时才建议改，并直接给出可粘贴的条目。DNS 本身正常时不会误导你去改 hosts。
5. **能连的话给优化建议** —— DNS 延迟对比、HTTP/2、TLS 1.3、跳转、建连耗时

## 用法

### 图形界面

双击 `dist/sitecheck/sitecheck.exe`：

- 输入域名，回车即可开始检测
- 顶部一行显示检测出的**真实 IP**，旁边 `+` 按钮可把它追加进下方「指定 IP」栏
- 「写入 hosts」按钮只在真的需要写时才亮起；点击后先展示改动预演，确认后自动备份 hosts、写入、并刷新 DNS 缓存（需管理员权限）
- 「保存报告」导出 Markdown

窗口尺寸固定 920×700，结果再长也不会把窗口撑大。

### 命令行

```bash
sitecheck.exe github.com
sitecheck.exe example.com --ip 1.2.3.4 --ip 5.6.7.8   # DNS 被污染时必须手动指定真实 IP
sitecheck.exe example.com --report out.md
sitecheck.exe example.com --apply-hosts                 # 直接写入 hosts 并刷新 DNS
```

## 源码运行

```bash
python sitecheck.py <域名> [--ip IP]... [--report out.md]
python sitecheck_gui.py          # 无参数 → 图形界面
```

## 重新打包

```bash
python build.py            # onedir（默认），启动约 0.5~1 秒
python build.py onefile    # 单文件，启动 23~35 秒，不推荐
```

需要 `pyinstaller` 和 `PyQt5`。`build.py` 会自动定位 pyinstaller（环境变量 `PYINSTALLER` → PATH → 当前 Python 的 `Scripts/`），找不到时给出提示。

默认用 `--onedir` 是因为单文件模式每次启动都要把约 98 MB 依赖解压到临时目录再加载，实测冷启动 23~35 秒；onedir 只要 0.5~1 秒。

## 文件说明

| 文件 | 说明 |
|---|---|
| `sitecheck.py` | 检测引擎（解析、探测、判定、渲染、hosts 写入） |
| `sitecheck_gui.py` | PyQt5 图形界面；带参数运行时走命令行，不加载 Qt |
| `build.py` | PyInstaller 打包脚本 |
| `hosts_audit.py` / `hosts-verify.py` | hosts 文件体检工具（只读，输出清理建议） |
| `dns_bench.py` | 公共 DNS 延迟 / 成功率 / 防污染基准测试 |
| `gf_probe.py` | 带证书主体与页面标题的 IP 真身探测脚本 |
| `dist/sitecheck/` | 打包产物，Windows 可直接运行 |

## 几个设计上的判断

**「能连通」不等于「返回 2xx」。** 判定标准是 TCP 通 + TLS 握手成功 + 证书匹配 + 拿到 HTTP 响应，与状态码无关。走 Cloudflare 返回 403 的站点，链路其实是通的。

**候选 IP 必须包含 hosts 文件里已有的条目。** 用户问"这个域名能不能访问"时，真正想问的往往是"我现在 hosts 里这条还能不能用"。只探测 DNS 解析结果会漏掉用户当前的生效配置——DNS 被污染时那些解析结果全是假 IP。

**结论和用户实际体验冲突时，先怀疑工具。** 不要急着把矛盾解释成网络问题。

## 注意

- 除「写入 hosts」按钮外，本工具是只读的，不修改任何系统配置
- 改 hosts 需要管理员权限
- 报告开头有「控制组」一栏；若控制组也不通，说明当前网络出网受限，报告中"TCP 不通"类结论不可信
