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


# ---------------------------------------------------------------- Markdown

def render_markdown(report: Report) -> str:
    verdict = report.verdict
    lines: list[str] = []
    add = lines.append

    add("# 网站直连检测：%s" % report.domain)
    add("")
    if report.real_ips:
        add("**真实 IP：%s**　（已通过 TLS 证书校验，确认归属该站）"
            % "、".join(report.real_ips))
    else:
        add("**真实 IP：未能确认**　（所有候选 IP 均未通过证书校验或不可达）")
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
    add("")

    # ---- 优化建议
    if report.tips:
        add("## 优化建议")
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
    if report.sys_ips:
        add("- **系统解析结果**（含 hosts 影响）：%s" % _fmt_ips(report.sys_ips))
    else:
        add("- **系统解析结果**：无")
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

    # ---- DNS
    add("## DNS 解析")
    add("")
    add("| 服务器 | 结果（A） | 结果（AAAA） | 耗时 |")
    add("|---|---|---|---|")
    for entry in report.dns:
        add("| %s %s | %s | %s | %.0f ms |" % (
            entry.name, entry.server,
            ", ".join(entry.ips) if entry.ips else _dns_empty_text(entry),
            ", ".join(entry.ipv6) if entry.ipv6 else "-",
            entry.ms))
    for entry in report.doh:
        add("| %s | %s | %s | %.0f ms |" % (
            entry.name,
            ", ".join(entry.ips) if entry.ips else _dns_empty_text(entry),
            ", ".join(entry.ipv6) if entry.ipv6 else "-",
            entry.ms))
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
    return {
        DnsStatus.NXDOMAIN: "NXDOMAIN",
        DnsStatus.EMPTY: "无记录",
        DnsStatus.TIMEOUT: "超时",
        DnsStatus.ERROR: "错误",
    }.get(entry.status, "无记录")


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


def render_html(report: Report) -> str:
    """生成供 QTextBrowser / 浏览器显示的 HTML。只用最基础的标签，兼容 Qt 富文本。"""
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
        add("<div style='font-size:9pt;opacity:0.9;margin-top:2px;'>阻断点：%s（%s）</div>"
            % (_esc(verdict.layer.value), _esc(_layer_label(verdict.layer))))
        add("</div>")

        if verdict.evidence:
            add("<div style='background:#f7f8fa;border-left:3px solid %s;"
                "padding:8px 10px;margin-bottom:8px;font-size:9.5pt;color:#4a5058;'>"
                "%s</div>" % (color, _esc(verdict.evidence)))

        add("<div style='margin-bottom:10px;font-size:9.5pt;'>"
            "<b>hosts 建议：</b>%s</div>"
            % _esc(verdict.hosts_advice).replace("\n", "<br>"))

    # 真实 IP
    if report.real_ips:
        add("<div style='background:#eaf1fa;color:#1e4e8c;padding:7px 10px;"
            "border-radius:5px;margin-bottom:10px;font-size:9.5pt;'>"
            "<b>真实 IP：</b>%s　<span style='color:#5a6b7d;'>"
            "已通过 TLS 证书校验</span></div>" % _esc("、".join(report.real_ips)))
    else:
        add("<div style='background:#fdeeec;color:#a32d2d;padding:7px 10px;"
            "border-radius:5px;margin-bottom:10px;font-size:9.5pt;'>"
            "<b>真实 IP：</b>未能确认　<span style='color:#8a4b46;'>"
            "候选 IP 均未通过证书校验</span></div>")

    # 优化建议
    if report.tips:
        add("<h3 style='margin:14px 0 6px;font-size:11pt;'>优化建议</h3>")
        add("<ul style='margin:0 0 0 18px;padding:0;'>")
        for tip in report.tips:
            add("<li style='margin-bottom:3px;font-size:9.5pt;'>%s</li>" % _esc(tip))
        add("</ul>")

    # 本机环境
    add("<h3 style='margin:14px 0 6px;font-size:11pt;'>本机环境</h3>")
    add("<table cellspacing='0' cellpadding='5' width='100%' "
        "style='border-collapse:collapse;font-size:9pt;'>")
    env_rows = [
        ("代理", _proxy_text(report)),
        ("系统解析", _fmt_ips(report.sys_ips)),
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

    # DNS 表
    add("<h3 style='margin:14px 0 6px;font-size:11pt;'>DNS 解析</h3>")
    add("<table cellspacing='0' cellpadding='5' width='100%' "
        "style='border-collapse:collapse;font-size:8.5pt;'>")
    add("<tr style='background:#f0f2f5;'>"
        "<th align='left' style='border:1px solid #e3e7ec;'>服务器</th>"
        "<th align='left' style='border:1px solid #e3e7ec;'>A</th>"
        "<th align='left' style='border:1px solid #e3e7ec;'>AAAA</th>"
        "<th align='left' style='border:1px solid #e3e7ec;'>耗时</th></tr>")
    for entry in report.dns + report.doh:
        add("<tr>"
            "<td style='border:1px solid #e3e7ec;'>%s</td>"
            "<td style='border:1px solid #e3e7ec;'>%s</td>"
            "<td style='border:1px solid #e3e7ec;'>%s</td>"
            "<td style='border:1px solid #e3e7ec;'>%.0f ms</td></tr>" % (
                _esc(entry.name),
                _esc(", ".join(entry.ips) if entry.ips else _dns_empty_text(entry)),
                _esc(", ".join(entry.ipv6) if entry.ipv6 else "-"),
                entry.ms))
    add("</table>")

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
