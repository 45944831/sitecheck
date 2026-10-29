# 判定逻辑说明

这份文档解释 sitecheck 为什么给出某个结论。工具的价值不在于跑通几个探测，而在于**结论可信**——所以每个判定都要能追溯到具体证据。

代码位置：`src/sitecheck/verdict.py`（纯函数，不依赖网络）。

---

## 一、数据模型

探测结果按层拆分，每层一个状态枚举，不用字符串前缀猜：

```
DnsStatus    ok / nxdomain / empty / timeout / error
TcpStatus    ok / refused / timeout / reset / unreachable
TlsStatus    ok / chain_untrusted / cert_mismatch / blocked / error
HttpStatus   ok / reject / no_response / malformed / skipped
```

`TlsStatus.blocked` 和 `error` 必须分开：**握手被切断**（超时、RST、EOF）是 SNI 层封锁的特征，而普通 TLS 错误（协议不支持、套件不匹配）是另一回事。v1.0 把两者都归为"TLS 错误"，导致 SNI 封锁识别不出来。

`HttpStatus` 的四种状态也必须分开：

| 状态 | 判据 | 含义 |
|---|---|---|
| `ok` | 拿到合法状态行，2xx/3xx | 完整可用 |
| `reject` | 拿到合法状态行，4xx/5xx | **链路通**，服务端策略拒绝 |
| `no_response` | 一个字节都没收到 | **链路不通**，与反爬无关 |
| `malformed` | 收到数据但不是 HTTP | 异常中间件 / 协议不匹配 |

v1.0 把后三种混成一个 `"?"`，于是"什么都没收到"被报成"服务端反爬"。

---

## 二、判定顺序

判定是**有序的**，前一条成立就不再往下走。顺序本身就是优先级。

```
0. 控制组全部不通                      -> INCONCLUSIVE
1. 有 IP 拿到 2xx/3xx                  -> SUCCESS
2. 有 IP 拿到合法 4xx/5xx              -> HTTP_REJECT
3. 直连无响应、经代理可通              -> PROXY_REQUIRED
4. 证书匹配、但 HTTP 无响应            -> HTTP_NO_RESPONSE
5. TCP+TLS 通、证书不匹配              -> DNS 污染
6. TCP 通、握手被切断                  -> TLS/SNI
7. 全部 TCP 不通                       -> TCP
8. 无任何解析结果                      -> DNS
9. 其余                                -> 未知
```

### 为什么第 0 步是控制组

控制组是几个不同运营商的稳定站点（百度、腾讯、Cloudflare）。它们的 TLS 握手全部失败，只能说明一件事：**本机出网通道有问题**。此时目标站点"连不上"没有任何诊断价值。

v1.0 把控制组写进报告但判定时不读，于是本机断网时会输出"所有候选 IP 的 443 端口均不可达，可能是服务器下线"。用户会去查服务器，而真正的问题在自己这边。

### 为什么第 3 步在 HTTP_NO_RESPONSE 之前

直连 HTTP 没响应、经代理有响应，这个组合的信息量很明确：**问题在本机到目标之间的直连路径上**，不在站点。此时如果建议用户改 hosts，等于让他做无用功。

`PROXY_REQUIRED` 是 v1.0 完全没有的状态。它恰好对应最常见的困惑——"工具说打不开，但浏览器明明能打开"。

### 为什么第 4 步独立成一层

TLS 握手成功、证书确认属于该站、但 HTTP 请求没有任何响应。这说明：

- 不是 DNS 问题（证书都匹配上了）
- 不是证书问题（握手完成了）
- 不是 SNI 问题（握手没被切断）

只能是应用层中断。可能原因：本机代理 / 防火墙拦了应用数据、目标 IP 只提供非 HTTP 服务、中间设备做了深度包检测。

v1.0 让这个场景落到"未知"，因为它的判定树里没有这一格。

---

## 三、hosts 建议的生成规则

`hosts_advice` 不是独立判断，而是从结论推导出来的：

| 结论 | hosts 建议 |
|---|---|
| `SUCCESS` + IP 来自 DNS | 无需添加；若 hosts 里有条目则提示"冗余，删掉不影响" |
| `SUCCESS` + IP 来自 hosts | 保持现状，无需改动 |
| `SUCCESS` + IP 既非 DNS 也非 hosts | 建议写入，给出可粘贴的条目 |
| `HTTP_REJECT` | 无需修改，问题在服务端策略 |
| `PROXY_REQUIRED` | 不要改，是本机代理配置 |
| `HTTP_NO_RESPONSE` | 不要改，DNS 和证书都已确认正确 |
| `TLS/SNI` | 无效，hosts 够不到 SNI 层 |
| `TCP` | 无效，换 IP 也解决不了 |
| `DNS 污染` | 未找到真 IP 时不建议写；找到才建议 |

只有第三种情况 `hosts_write_needed = True`，GUI 的「写入 hosts」按钮才亮起。

---

## 四、DNS 一致性分析

"DNS 是否被污染"不用列表全等判断——CDN 轮询时不同 DNS 返回不同节点是**正常的**。

```python
udp_union = 所有 UDP DNS 结果的并集
doh_union = 所有 DoH 结果的并集

doh_disjoint = udp_union 与 doh_union 无交集
```

- 有交集 → 正常（至少有一个 IP 双方都认）
- 无交集 → 高度可疑，提示"建议启用 DoH"
- UDP 之间不一致 → CDN 就近调度，提示"通常无需处理"

v1.0 用 `tuple(ips)` 全等比较，任何 CDN 轮询都会被误报成"疑似污染"。

---

## 五、证书匹配

按 RFC 6125 实现，`cert_matches(host, san)`：

| host | SAN | 结果 | 说明 |
|---|---|---|---|
| `www.example.com` | `*.example.com` | ✓ | 通配匹配最左一级 |
| `example.com` | `*.example.com` | ✗ | 通配至少需要一个标签 |
| `a.b.example.com` | `*.example.com` | ✗ | 不跨多级 |
| `evilexample.com` | `*.example.com` | ✗ | 必须有 `.` 边界 |

v1.0 的实现是 `host.endswith(x[2:])`，丢掉了点，`evilexample.com` 会被 `*.example.com` 命中。由于整个"真实 IP"结论都建立在这个函数上，这个 bug 足以让工具把伪造 IP 认证成真实 IP 并建议写进 hosts——恰好是它最想避免的事。

---

## 六、控制组的设计

```python
CONTROLS = [
    ("www.baidu.com", "百度"),
    ("www.qq.com", "腾讯"),
    ("www.cloudflare.com", "Cloudflare"),
]
```

三个约束：

1. **不写死 IP。** v1.0 把 GitHub 的 IP 硬编码成 `20.205.243.166`，该 IP 早已失效，控制组形同虚设。现在运行时解析。
2. **多个运营商。** 单个目标挂了不代表本机出网有问题。
3. **测 TLS 而不是 TCP。** TCP 能连但 TLS 被切断，也属于"出网通道不完整"，应该算控制组失败。

---

## 七、代理感知

探测顺序：WinINET 注册表 → PAC → 环境变量。

- 浏览器（IE / Edge / Chrome）在 Windows 上都读 WinINET
- 命令行工具读环境变量

两者可能不同，所以报告里标注来源。

**DoH 强制不走代理**（`ProxyHandler({})`）。因为 UDP DNS 走的是裸网，如果 DoH 走代理，两者网络路径不同，"结果不同 = 污染"这个推论就不成立。

**HTTP 双路径对照**：直连失败时，经代理再试一次（只对一个 IP 做，避免耗时翻倍）。隧道目标是 **IP** 而不是域名，这样"经代理"与"直连"测的是同一个 IP，两者才是严格对照；域名只用于 TLS 的 SNI。

---

## 八、如何验证判定逻辑

`tests/test_verdict.py` 用构造的数据覆盖全部分支，不打网络：

```python
def test_control_all_failed_yields_inconclusive():
    rep = report(control=[control(False), control(False)],
                 probes=[probe("1.2.3.4", tcp=TcpStatus.TIMEOUT)])
    assert judge(rep).layer is Layer.INCONCLUSIVE

def test_http_no_response_is_not_reject():
    rep = report(probes=[probe("1.2.3.4", tls=tls_ok(), http=http_silent())])
    assert judge(rep).layer is Layer.HTTP_NO_RESPONSE
```

这两个测试分别锁死了 v1.0 的两个 P0 误判。只要有人改坏了判定树，测试会立刻失败。

`verdict.py` 不 import 任何 IO 模块，这是让上述测试成立的前提。
