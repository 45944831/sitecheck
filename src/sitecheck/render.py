# -*- coding: utf-8 -*-
"""报告渲染：Markdown / JSON / HTML。

HTML 直接生成，不再像 v1.0 那样先写 Markdown 再用手写解析器转一遍 ——
那个 50 行的解析器遇到表格里的竖线、代码块嵌套就会坏，属于多余的风险。
"""
from __future__ import annotations

import dataclasses
import json
from enum import Enum
from typing import Any

from .models import (
    HttpStatus,
    Layer,
    ProbeResult,
    ProxyKind,
    Report,
    TcpStatus,
    TlsStatus,
)

_LAYER_LABEL = {
    Layer.SUCCESS: "可直连",
    Layer.HTTP_REJECT: "服务端拒绝",
    Layer.PROXY_REQUIRED: "需要代理",
    Layer.HTTP_NO_RESPONSE: "应用层无响应",
    Layer.DNS_POISONED: "DNS 污染",
    Layer.TLS_BLOCKED: "TLS/SNI 被切断",
    Layer.TCP_BLOCKED: "TCP 不通",
    Layer.DNS_FAIL: "解析失败",
    Layer.INCONCLUSIVE: "无法判定",
    Layer.UNKNOWN: "未知",
}


def _layer_label(layer: Layer) -> str:
    return _LAYER_LABEL.get(layer, layer.value)


def _fmt_ips(ips: list[str], limit: int = 6) -> str:
    if not ips:
        return "无"
    shown = "、".join(ips[:limit])
    return shown + ("…" if len(ips) > limit else "")


def _tcp_text(status: TcpStatus) -> str:
    return {
        TcpStatus.OK: "通",
        TcpStatus.REFUSED: "拒绝",
        TcpStatus.TIMEOUT: "超时",
        TcpStatus.RESET: "重置",
        TcpStatus.UNREACHABLE: "不可达",
    }.get(status, status.value)


def _tls_text(probe: ProbeResult) -> str:
    tls = probe.tls
    if not tls:
        return "-"
    if tls.status is TlsStatus.OK:
        return "成功"
    if tls.status is TlsStatus.CHAIN_UNTRUSTED:
        return "成功(链不可信)"
    if tls.status is TlsStatus.CERT_MISMATCH:
        return "成功(证书不匹配)"
    if tls.status is TlsStatus.BLOCKED:
        return "被切断"
    return "失败"


def _http_text(probe: ProbeResult) -> str:
    http = probe.http
    if not http:
        return "-"
    if http.status is HttpStatus.OK:
        return str(http.code or "OK")
    if http.status is HttpStatus.REJECT:
        return str(http.code or "拒绝")
    if http.status is HttpStatus.NO_RESPONSE:
        return "无响应"
    if http.status is HttpStatus.MALFORMED:
        return "响应异常"
    return "-"


def _match_text(probe: ProbeResult) -> str:
    if not probe.tls:
        return "-"
    if probe.tls.cert_match is None:
        return "无证书"
    return "是" if probe.tls.cert_match else "否"


def _proxy_text(report: Report) -> str:
    if not report.proxy.present:
        return "未检测到"
    text = "%s（%s）" % (report.proxy.url, report.proxy.source)
    if report.proxy.kind is ProxyKind.PAC:
        text += "　— PAC 脚本仅展示，不参与探测"
    return text


def _resolution_consistency(report: Report) -> str:
    """一句话说明 UDP / DoH 解析是否一致，用于证书未验证时的归因。

    关键是比较「各家返回的集合是否相同」，而不是把所有地址并起来看数量 ——
    6 家都返回同样的 2 个 v4 + 2 个 v6 时并集是 4 个地址，但一致性是 6/6，
    旧写法会误报成「CDN 就近调度」，其实根本没有任何分歧。
    """
    udp_sets = [frozenset(e.all_ips) for e in report.dns if e.ok and e.all_ips]
    doh_sets = [frozenset(e.all_ips) for e in report.doh if e.ok and e.all_ips]
    udp_union = frozenset().union(*udp_sets) if udp_sets else frozenset()
    doh_union = frozenset().union(*doh_sets) if doh_sets else frozenset()
    if not udp_union and not doh_union:
        return "本机与远端 DNS 均未返回地址"

    udp_agree = len(set(udp_sets)) <= 1
    doh_agree = len(set(doh_sets)) <= 1
    n_udp = len(udp_sets)
    n_addr = len(udp_union)
    if udp_agree and doh_agree and udp_union and doh_union and udp_union == doh_union:
        return ("本机 %d 家 DNS 与远端加密解析结果完全一致（%d 个地址），"
                "无 DNS 污染迹象" % (n_udp, n_addr))
    if udp_union and doh_union and not (udp_union & doh_union):
        return "本机 DNS 与远端加密解析返回的地址完全不同，存在污染迹象"
    if udp_agree:
        return "本机 %d 家 DNS 结果完全一致（%d 个地址）" % (n_udp, n_addr)
    if udp_sets:
        return "本机 %d 家 DNS 返回了不同地址，属于 CDN 就近调度，属正常现象" % n_udp
    return "仅远端加密解析返回地址（本机 UDP DNS 未返回）"


def _dns_ms_text(ms: float) -> str:
    """耗时加慢响应标记：超过 1 秒说明该 DNS 服务器响应异常缓慢。"""
    if ms >= 1000:
        return "%.0f ms（响应缓慢）" % ms
    return "%.0f ms" % ms


def _confidence_text(verdict, compact: bool = False) -> str:
    """证据强度的可读文案。compact 下只留标签，去掉复述依据的 note。"""
    if not verdict:
        return ""
    mapping = {"strong": "强（有证书 / 对照实验等直接证据）",
               "moderate": "中（分层探测推断）",
               "weak": "弱（证据不完整，建议复测）"}
    label = mapping.get(getattr(verdict, "confidence", ""), "中")
    if compact:
        return label
    note = getattr(verdict, "confidence_note", "")
    return "%s%s" % (label, ("　— " + note) if note else "")


def _compact_text(text: str, limit: int = 110,
                  keywords: tuple[str, ...] = ()) -> str:
    """压缩长段文案到一行：第一句必留（结论），再补一句含关键词的硬证据。

    用于 GUI 结果区的 evidence / hosts 建议 —— 判定层写得完整（供报告
    留档），但界面上只抓结论 + 最关键的那句证据，其余折叠成省略号。
    """
    if not text or len(text) <= limit:
        return text
    sentences = [s.strip() for s in text.replace("\n", " ").split("。") if s.strip()]
    if not sentences:
        return text[:limit] + "…"
    picked = [sentences[0]]
    for sentence in sentences[1:]:
        if keywords and any(word in sentence for word in keywords):
            picked.append(sentence)
            break
    result = "。".join(picked) + "。"
    if len(result) > limit:
        result = result[:limit].rstrip("，、；。") + "…"
    return result


def _compact_hosts_advice(verdict, report: Report) -> str:
    """hosts 建议精简版：只讲该不该改、为什么，不重复 fix_hint 的动作。"""
    text = getattr(verdict, "hosts_advice", "") or ""
    if not text:
        return ""
    # 有本机 hosts 条目时，列出失效 IP 比长篇解释更有用
    if report.hosts:
        return _compact_text(text, 120, ("失效", "TLS 握手失败"))
    return _compact_text(text, 95, ("Anycast", "代理", "防火墙"))


# ---------------------------------------------------------------- Markdown

def render_markdown(report: Report) -> str:
    verdict = report.verdict
    lines: list[str] = []
    add = lines.append

    add("# 网站直连检测：%s" % report.domain)
    add("")
    # 把"解析"和"证书归属"拆成两个维度：过去失败时统一写"真实 IP 未能确认"，
    # 在 SNI 阻断场景下会被误读成"DNS 有问题"，而真实情况是 DNS 完全正常、
    # 只是握手拿不到证书。这里分别陈述，避免自相矛盾。
    if report.real_ips:
        add("**证书归属：已确认**　%s 通过 TLS 证书校验，归属该站。"
            % "、".join(report.real_ips))
    else:
        consistency = _resolution_consistency(report)
        add("**证书归属：未能验证**　TLS 握手未完成，无法读取证书；"
            "这不等于 IP 不存在，也不代表 DNS 有问题。")
        if consistency:
            add("- **解析一致性**：%s" % consistency)
    add("")
    add("检测时间：%s　|　工具版本 v%s" % (report.time, report.version or "-"))
    add("")

    # ---- 结论
    add("## 结论")
    add("")
    if verdict:
        add("- **判定**：%s" % verdict.headline)
        add("- **阻断点**：`%s`（%s）" % (verdict.layer.value, _layer_label(verdict.layer)))
        if verdict.evidence:
            add("- **依据**：%s" % verdict.evidence)
        add("- **hosts 建议**：%s" % verdict.hosts_advice)
        conf = _confidence_text(verdict)
        if conf:
            add("- **证据强度**：%s" % conf)
        if verdict.fix_hint:
            add("- **下一步**：%s" % verdict.fix_hint)
    add("")

    # ---- 链路抖动：同一 IP 结论冲突，单次失败不能当稳定故障
    if report.flaky_evidence:
        add("> **链路抖动警告**：同一 IP 在不同探测阶段得出相反结论，"
            "本次失败可能是暂时丢包，不建议据此判定为稳定故障或据此改 hosts。")
        for item in report.flaky_evidence:
            add("> - %s" % item)
        add("")

    # ---- 证书备用域名（仅握手成功拿到 SAN 且筛出同站域名时出现）
    if report.alt_domains:
        add("## 证书备用域名")
        add("")
        add("> 这张证书还覆盖下列同站域名，已逐个用本机网络探测可达性；"
            "跨品牌的共享证书域名已过滤。")
        add("> 每个域名只探测一次：标为「不可用」可能是暂时抖动，"
            "建议复测确认后再下结论。")
        add("")
        add("| 备用域名 | 可用性 | 解析 IP | 说明 |")
        add("|---|---|---|---|")
        for alt in report.alt_domains:
            add("| %s | %s | %s | %s |" % (
                alt.domain, alt.status_text, alt.ip or "-", alt.detail or "-"))
        add("")
        usable = [a.domain for a in report.alt_domains if a.usable is True]
        if usable:
            add("**可用的备用地址：%s**" % "、".join(usable))
            add("")

    # ---- 补充信息（诊断类 / 优化类，措辞中性，避免暗示"改一下就能通"）
    if report.tips:
        add("## 补充信息")
        add("")
        for tip in report.tips:
            add("- %s" % tip)
        add("")

    # ---- 本机环境
    add("## 本机环境")
    add("")
    add("- **代理**：%s" % _proxy_text(report))
    if report.proxy.present and verdict and verdict.proxy_note:
        add("  - %s" % verdict.proxy_note)
    dns_ips = {ip for e in report.dns if e.ok for ip in e.all_ips}
    sys_set = set(report.sys_ips)
    if sys_set and dns_ips and sys_set == dns_ips:
        add("- **系统解析结果**：与下方 DNS 解析一致（含 hosts 影响）")
    elif report.sys_ips:
        add("- **系统解析结果**（含 hosts 影响）：%s" % _fmt_ips(report.sys_ips))
    else:
        add("- **系统解析结果**：无")
    add("- **IPv6 出口**：%s" % {
        True: "有出口", False: "无出口（AAAA 不可达属环境限制，不代表站点问题）",
        None: "未检测"}.get(report.ipv6_outbound, "未检测"))
    add("- **hosts 条目**：%s" % (
        "第 %s 行" % "、".join(str(no) for no, _ in report.hosts)
        if report.hosts else "无该域名条目"))
    add("")

    # ---- 控制组
    add("## 控制组（探测可信度）")
    add("")
    for item in report.control:
        add("- %s（%s）：%s%s" % (item.host, item.ip,
                                 "通" if item.ok else "不通",
                                 "" if item.ok else "　— " + item.detail))
    if report.control_all_failed:
        add("")
        add("> [!] 控制组全部不通，说明本机出网受限，"
            "本次「连不上」类结论不可信，请在网络正常的环境重跑。")
    add("")

    # ---- DNS：本机 UDP 与远端加密解析分区展示，两者可能给出不同 IP
    add("## DNS 解析")
    add("")
    add("### 本机解析（UDP，走本机网络）")
    add("")
    add("| 服务器 | 结果（A） | 结果（AAAA） | 耗时 |")
    add("|---|---|---|---|")
    for entry in report.dns:
        add("| %s %s | %s | %s | %s |" % (
            entry.name, entry.server,
            ", ".join(entry.ips) if entry.ips else _dns_empty_text(entry),
            ", ".join(entry.ipv6) if entry.ipv6 else "-",
            _dns_ms_text(entry.ms)))
    add("")
    add("### 远端解析（DoH，加密查询，不受 UDP 53 干扰）")
    add("")
    add("> 远端解析给出的 IP 只是候选，仍须通过证书校验才算真实 IP。")
    add("")
    add("| 端点 | 结果（A） | 结果（AAAA） | 耗时 |")
    add("|---|---|---|---|")
    for entry in report.doh:
        add("| %s | %s | %s | %s |" % (
            entry.name,
            ", ".join(entry.ips) if entry.ips else _dns_empty_text(entry),
            ", ".join(entry.ipv6) if entry.ipv6 else "-",
            _dns_ms_text(entry.ms)))
    add("")

    # ---- 逐 IP
    add("## 逐 IP 探测")
    add("")
    has_proxy_col = any(p.http_proxy for p in report.probes)
    if has_proxy_col:
        add("| IP | 来源 | TCP | TLS | 证书 | 匹配 | HTTP 直连 | HTTP 代理 |")
        add("|---|---|---|---|---|---|---|---|")
    else:
        add("| IP | 来源 | TCP | TLS | 证书 | 匹配 | HTTP |")
        add("|---|---|---|---|---|---|---|")
    for probe in report.probes:
        cn = (probe.tls.cn[:28] if probe.tls and probe.tls.cn else "-")
        row = "| %s | %s | %s | %s | %s | %s | %s" % (
            probe.ip, probe.source, _tcp_text(probe.tcp), _tls_text(probe),
            cn, _match_text(probe), _http_text(probe))
        if has_proxy_col:
            proxy_text = "-"
            if probe.http_proxy:
                proxy_text = (str(probe.http_proxy.code)
                              if probe.http_proxy.usable
                              else probe.http_proxy.status.value)
            row += " | %s" % proxy_text
        add(row + " |")
    add("")

    if report.sni_control:
        add("> **SNI 对照实验**：%s" % report.sni_control.text)
        add("")

    # ---- hosts 现状
    add("## 本机 hosts 现状")
    add("")
    if report.hosts:
        for line_no, ip in report.hosts:
            add("- 第 %d 行：`%s %s`" % (line_no, ip, report.domain))
    else:
        add("- 无该域名的 hosts 条目")
    return "\n".join(lines)


def _dns_empty_text(entry: Any) -> str:
    from .models import DnsStatus
    base = {
        DnsStatus.NXDOMAIN: "NXDOMAIN",
        DnsStatus.EMPTY: "无记录",
        DnsStatus.TIMEOUT: "超时",
        DnsStatus.ERROR: "错误",
    }.get(entry.status, "无记录")
    # error 字段装着具体原因（连接失败 / HTTP 状态 / 超时），过去被丢掉只显示
    # \"错误\"，用户无法判断是端点抖动还是被拦。这里带出来，但压到一行短文本。
    err = (getattr(entry, "error", "") or "").strip()
    if err and entry.status in (DnsStatus.ERROR, DnsStatus.TIMEOUT):
        short = " ".join(err.split())[:60]
        return "%s（%s）" % (base, short)
    return base


def render_summary(report: Report) -> str:
    """单行摘要，供 GUI 横幅使用。"""
    if not report.verdict:
        return "未完成检测"
    return "%s　|　阻断点：%s" % (report.verdict.headline, _layer_label(report.verdict.layer))


# ---------------------------------------------------------------- JSON

def _jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {k: _jsonable(v) for k, v in dataclasses.asdict(value).items()}
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    return value


def render_json(report: Report, indent: int = 2) -> str:
    return json.dumps(_jsonable(report), ensure_ascii=False, indent=indent)


# ---------------------------------------------------------------- HTML

def _esc(text: Any) -> str:
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;"))


def _layer_color(layer: Layer) -> str:
    if layer is Layer.SUCCESS:
        return "#1d9e75"
    if layer in (Layer.TLS_BLOCKED, Layer.DNS_POISONED):
        return "#c0392b"
    if layer is Layer.INCONCLUSIVE:
        return "#6b4fa8"
    return "#b26a00"


def render_html(report: Report, compact: bool = False) -> str:
    """生成供 QTextBrowser / 浏览器显示的 HTML。只用最基础的标签，兼容 Qt 富文本。

    compact=True 时结论区压为一行一段（GUI 用）；导出的报告默认
    compact=False 保留完整依据。所有段落都在，只缩短文案。
    """
    verdict = report.verdict
    out: list[str] = []
    add = out.append

    add("<div style='font-family:\"Microsoft YaHei UI\",sans-serif;font-size:10pt;color:#1a1d21;'>")

    # 结论块
    if verdict:
        color = _layer_color(verdict.layer)
        add("<div style='background:%s;color:#ffffff;padding:10px 12px;"
            "border-radius:5px;margin-bottom:8px;'>" % color)
        add("<div style='font-size:12pt;font-weight:bold;'>%s</div>" % _esc(verdict.headline))
        if compact:
            add("<div style='font-size:9pt;opacity:0.9;margin-top:2px;'>阻断点：%s</div>"
                % _esc(_layer_label(verdict.layer)))
        else:
            add("<div style='font-size:9pt;opacity:0.9;margin-top:2px;'>阻断点：%s（%s）</div>"
                % (_esc(verdict.layer.value), _esc(_layer_label(verdict.layer))))
        add("</div>")

        if verdict.evidence:
            evidence = (_compact_text(verdict.evidence, 120,
                                      ("对照实验", "已证实", "证书确认", "污染"))
                        if compact else verdict.evidence)
            add("<div style='background:#f7f8fa;border-left:3px solid %s;"
                "padding:8px 10px;margin-bottom:8px;font-size:9.5pt;color:#4a5058;'>"
                "%s</div>" % (color, _esc(evidence)))

        hosts_advice = (_compact_hosts_advice(verdict, report) if compact
                        else verdict.hosts_advice)
        if hosts_advice:
            add("<div style='margin-bottom:10px;font-size:9.5pt;'>"
                "<b>hosts 建议：</b>%s</div>"
                % _esc(hosts_advice).replace("\n", "<br>"))

        conf = _confidence_text(verdict, compact=compact)
        if conf:
            add("<div style='margin-bottom:10px;font-size:9pt;color:#6b7280;'>"
                "<b>证据强度：</b>%s</div>" % _esc(conf))

        if verdict.fix_hint:
            add("<div style='background:#eef4fb;border-left:3px solid #2b6cf0;"
                "padding:8px 10px;margin-bottom:10px;font-size:9.5pt;"
                "color:#243447;'><b>下一步：</b>%s</div>"
                % _esc(verdict.fix_hint).replace("\n", "<br>"))

    # 链路抖动：同一 IP 结论冲突，单次失败不能当稳定故障
    if report.flaky_evidence:
        add("<div style='background:#fdf6e8;border-left:3px solid #b8860b;"
            "padding:8px 10px;margin-bottom:10px;font-size:9.5pt;color:#6b4c0a;'>"
            "<b>链路抖动警告：</b>同一 IP 在不同探测阶段得出相反结论，"
            "本次失败可能是暂时丢包，不建议据此判定为稳定故障或据此改 hosts。")
        for item in report.flaky_evidence:
            add("<div style='margin-top:4px;'>- %s</div>" % _esc(item))
        add("</div>")

    # 证书归属 / 解析一致性：两个维度分开，避免失败时统一说"真实 IP 未确认"
    if report.real_ips:
        add("<div style='background:#eaf1fa;color:#1e4e8c;padding:7px 10px;"
            "border-radius:5px;margin-bottom:10px;font-size:9.5pt;'>"
            "<b>证书归属：已确认</b>　%s 通过 TLS 证书校验，归属该站。</div>"
            % _esc("、".join(report.real_ips)))
    else:
        cert_note = ("握手未完成，证书读不到（不代表 IP 不存在 / DNS 有问题）"
                     if compact else
                     "TLS 握手未完成，无法读取证书；这不等于 IP 不存在，也不代表 DNS 有问题。")
        add("<div style='background:#fdeeec;color:#a32d2d;padding:7px 10px;"
            "border-radius:5px;margin-bottom:10px;font-size:9.5pt;'>"
            "<b>证书归属：未能验证</b>　<span style='color:#8a4b46;'>%s</span></div>"
            % cert_note)
        consistency = _resolution_consistency(report)
        if consistency:
            if compact and len(consistency) > 45:
                consistency = _compact_text(consistency, 45)
            add("<div style='font-size:9pt;color:#5a6b7d;margin-bottom:10px;'>"
                "<b>解析一致性：</b>%s</div>" % _esc(consistency))

    # 证书备用域名：同站域名 + 逐个探测结论，跨品牌域名已过滤
    if report.alt_domains:
        add("<h3 style='margin:14px 0 6px;font-size:11pt;'>证书备用域名</h3>")
        add("<div style='font-size:8.5pt;color:#5a6b7d;margin-bottom:6px;'>"
            "这张证书还覆盖下列同站域名，已逐个探测本机可达性（跨品牌共享证书域名已过滤）。"
            "每个域名只探测一次，标为「不可用」可能是暂时抖动，建议复测确认。</div>")
        add("<table cellspacing='0' cellpadding='5' width='100%' "
            "style='border-collapse:collapse;font-size:8.5pt;'>")
        add("<tr style='background:#f0f2f5;'>"
            "<th align='left' style='border:1px solid #e3e7ec;'>备用域名</th>"
            "<th align='left' style='border:1px solid #e3e7ec;'>可用性</th>"
            "<th align='left' style='border:1px solid #e3e7ec;'>解析 IP</th>"
            "<th align='left' style='border:1px solid #e3e7ec;'>说明</th></tr>")
        for alt in report.alt_domains:
            color = "#1a7f37" if alt.usable is True else (
                "#a32d2d" if alt.usable is False else "#8a6d1a")
            add("<tr>"
                "<td style='border:1px solid #e3e7ec;'>%s</td>"
                "<td style='border:1px solid #e3e7ec;color:%s;'><b>%s</b></td>"
                "<td style='border:1px solid #e3e7ec;'>%s</td>"
                "<td style='border:1px solid #e3e7ec;'>%s</td></tr>" % (
                    _esc(alt.domain), color, _esc(alt.status_text),
                    _esc(alt.ip or "-"), _esc(alt.detail or "-")))
        add("</table>")
        usable = [a.domain for a in report.alt_domains if a.usable is True]
        if usable:
            add("<div style='margin:6px 0 10px;font-size:9.5pt;'>"
                "<b>可用的备用地址：</b>%s</div>" % _esc("、".join(usable)))

    # 补充信息（诊断类 / 优化类）
    if report.tips:
        add("<h3 style='margin:14px 0 6px;font-size:11pt;'>补充信息</h3>")
        add("<ul style='margin:0 0 0 18px;padding:0;'>")
        for tip in report.tips:
            add("<li style='margin-bottom:3px;font-size:9.5pt;'>%s</li>" % _esc(tip))
        add("</ul>")

    # 本机环境
    add("<h3 style='margin:14px 0 6px;font-size:11pt;'>本机环境</h3>")
    add("<table cellspacing='0' cellpadding='5' width='100%' "
        "style='border-collapse:collapse;font-size:9pt;'>")
    # 系统解析结果与下方 DNS 表高度重复，这里只标注"是否与 DNS 一致"，
    # 有差异时才列出具体 IP，避免同一份地址在报告里出现两遍。
    dns_ips = {ip for e in report.dns if e.ok for ip in e.all_ips}
    sys_ips_set = set(report.sys_ips)
    if sys_ips_set and dns_ips and sys_ips_set == dns_ips:
        sys_text = "与下方 DNS 解析结果一致（含 hosts 影响）"
    else:
        sys_text = _fmt_ips(report.sys_ips)
    v6_text = {True: "有出口", False: "无出口（AAAA 不可达属环境限制）",
               None: "未检测"}.get(report.ipv6_outbound, "未检测")
    env_rows = [
        ("代理", _proxy_text(report)),
        ("系统解析", sys_text),
        ("IPv6 出口", v6_text),
        ("hosts 条目", ("第 %s 行" % "、".join(str(n) for n, _ in report.hosts))
         if report.hosts else "无该域名条目"),
    ]
    for key, val in env_rows:
        add("<tr><td width='90' style='background:#fafbfc;border:1px solid #e3e7ec;"
            "color:#7c848e;'>%s</td><td style='border:1px solid #e3e7ec;'>%s</td></tr>"
            % (_esc(key), _esc(val)))
    add("</table>")

    # 控制组
    add("<h3 style='margin:14px 0 6px;font-size:11pt;'>控制组（探测可信度）</h3>")
    add("<div style='font-size:9pt;'>")
    for item in report.control:
        mark = ("<span style='color:#1d9e75;font-weight:bold;'>通</span>"
                if item.ok else
                "<span style='color:#c0392b;font-weight:bold;'>不通</span>")
        detail = "" if item.ok else "　<span style='color:#7c848e;'>%s</span>" % _esc(item.detail)
        add("<div>%s（%s）：%s%s</div>" % (_esc(item.host), _esc(item.ip), mark, detail))
    add("</div>")
    if report.control_all_failed:
        add("<div style='background:#fdf3e3;border-left:3px solid #b26a00;"
            "padding:7px 10px;margin-top:6px;font-size:9pt;color:#7a4c00;'>"
            "控制组全部不通，本机出网受限，本次「连不上」类结论不可信。</div>")

    # DNS 表：本机 UDP 与远端 DoH 分区，来源一眼可辨
    def _dns_table(entries: list, heading: str, col_name: str) -> None:
        add("<h3 style='margin:14px 0 6px;font-size:11pt;'>%s</h3>" % _esc(heading))
        add("<table cellspacing='0' cellpadding='5' width='100%' "
            "style='border-collapse:collapse;font-size:8.5pt;'>")
        add("<tr style='background:#f0f2f5;'>"
            "<th align='left' style='border:1px solid #e3e7ec;'>%s</th>"
            "<th align='left' style='border:1px solid #e3e7ec;'>A</th>"
            "<th align='left' style='border:1px solid #e3e7ec;'>AAAA</th>"
            "<th align='left' style='border:1px solid #e3e7ec;'>耗时</th></tr>"
            % _esc(col_name))
        for entry in entries:
            add("<tr>"
                "<td style='border:1px solid #e3e7ec;'>%s</td>"
                "<td style='border:1px solid #e3e7ec;'>%s</td>"
                "<td style='border:1px solid #e3e7ec;'>%s</td>"
                "<td style='border:1px solid #e3e7ec;'>%s</td></tr>" % (
                    _esc(entry.name),
                    _esc(", ".join(entry.ips) if entry.ips else _dns_empty_text(entry)),
                    _esc(", ".join(entry.ipv6) if entry.ipv6 else "-"),
                    _esc(_dns_ms_text(entry.ms))))
        add("</table>")

    _dns_table(report.dns, "DNS 解析 · 本机（UDP，走本机网络）", "服务器")
    add("<div style='background:#f7f8fa;border-left:3px solid #2b6cf0;"
        "padding:6px 10px;margin:8px 0 0;font-size:9pt;color:#4a5058;'>"
        "远端 DoH 加密查询，不受 UDP 53 干扰；给出的 IP 只是候选，"
        "仍须通过证书校验才算真实 IP。</div>")
    _dns_table(report.doh, "DNS 解析 · 远端（DoH，加密查询）", "端点")

    # 逐 IP
    add("<h3 style='margin:14px 0 6px;font-size:11pt;'>逐 IP 探测</h3>")
    has_proxy = any(p.http_proxy for p in report.probes)
    add("<table cellspacing='0' cellpadding='5' width='100%' "
        "style='border-collapse:collapse;font-size:8.5pt;'>")
    headers = ["IP", "来源", "TCP", "TLS", "证书", "匹配", "HTTP"]
    if has_proxy:
        headers.append("HTTP(代理)")
    add("<tr style='background:#f0f2f5;'>" + "".join(
        "<th align='left' style='border:1px solid #e3e7ec;'>%s</th>" % h
        for h in headers) + "</tr>")
    for probe in report.probes:
        cells = [
            probe.ip, probe.source, _tcp_text(probe.tcp), _tls_text(probe),
            (probe.tls.cn[:26] if probe.tls and probe.tls.cn else "-"),
            _match_text(probe), _http_text(probe),
        ]
        if has_proxy:
            cells.append(str(probe.http_proxy.code) if probe.http_proxy
                         and probe.http_proxy.usable
                         else (probe.http_proxy.status.value if probe.http_proxy else "-"))
        add("<tr>" + "".join(
            "<td style='border:1px solid #e3e7ec;'>%s</td>" % _esc(c) for c in cells
        ) + "</tr>")
    add("</table>")

    # SNI 对照实验：把"推断"升级为"已证实"的证据展示出来
    if report.sni_control:
        sc = report.sni_control
        bg = "#eaf5ee" if sc.proves_domain_block else "#fdf3e3"
        border = "#1d9e75" if sc.proves_domain_block else "#b26a00"
        add("<div style='background:%s;border-left:3px solid %s;"
            "padding:7px 10px;margin-top:8px;font-size:9pt;color:#3d4852;'>"
            "<b>SNI 对照实验：</b>%s</div>" % (bg, border, _esc(sc.text)))

    # hosts 现状
    add("<h3 style='margin:14px 0 6px;font-size:11pt;'>本机 hosts 现状</h3>")
    if report.hosts:
        add("<div style='font-size:9pt;'>")
        for line_no, ip in report.hosts:
            add("<div>第 %d 行：<code>%s %s</code></div>"
                % (line_no, _esc(ip), _esc(report.domain)))
        add("</div>")
    else:
        add("<div style='font-size:9pt;color:#7c848e;'>无该域名的 hosts 条目</div>")

    add("<div style='margin-top:14px;font-size:8pt;color:#9aa2ac;'>"
        "检测时间 %s　|　sitecheck v%s</div>"
        % (_esc(report.time), _esc(report.version or "-")))
    add("</div>")
    return "".join(out)
