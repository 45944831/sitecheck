# -*- coding: utf-8 -*-
"""判定引擎：把探测结果翻译成"能不能访问、卡在哪一层、要不要改 hosts"。

本模块是纯函数 —— 不 import 任何 IO 模块，只吃 Report dataclass。
这样判定逻辑可以完全脱离网络做单元测试，这是 v1.0 最缺的东西。

判定顺序（每一步都对应一类明确证据）：
    0. 控制组全不通        -> INCONCLUSIVE     环境不可信，其余结论作废
    1. 有 IP 拿到 2xx/3xx  -> SUCCESS
    2. 有 IP 拿到 4xx/5xx  -> HTTP_REJECT      链路通，服务端拒绝
    3. 直连无响应、代理可通 -> PROXY_REQUIRED    本机代理配置问题
    4. 证书匹配但 HTTP 无响应 -> HTTP_NO_RESPONSE 应用层不通
    5. TCP+TLS 通、证书不匹配 -> DNS_POISONED
    6. TCP 通、握手被切断   -> TLS_BLOCKED      SNI 层，改 hosts 无效
    7. 全部 TCP 不通        -> TCP_BLOCKED
    8. 无任何解析结果       -> DNS_FAIL
    9. 其余                 -> UNKNOWN
"""
from __future__ import annotations

from typing import Optional

from .models import DnsStatus, HttpStatus, Layer, ProbeResult, Report, TcpStatus, TlsStatus, Verdict

# ---------------------------------------------------------------- 辅助

def _fmt_ips(ips: list[str], limit: int = 4) -> str:
    if not ips:
        return "无"
    shown = "、".join(ips[:limit])
    return shown + ("…" if len(ips) > limit else "")


def dns_union(report: Report) -> list[str]:
    """所有 UDP DNS 服务器解析出的 IP 并集 —— 即"DNS 给的 IP"。"""
    out: list[str] = []
    for entry in report.dns:
        if not entry.ok:
            continue
        for ip in entry.all_ips:
            if ip not in out:
                out.append(ip)
    return out


def doh_union(report: Report) -> list[str]:
    out: list[str] = []
    for entry in report.doh:
        if not entry.ok:
            continue
        for ip in entry.all_ips:
            if ip not in out:
                out.append(ip)
    return out


def dns_consistency(report: Report) -> dict:
    """解析一致性分析。

    用集合比较而不是列表全等：CDN 轮询时不同 DNS 返回不同节点是正常的，
    v1.0 用 tuple 全等比较会把这种情况误报成"不一致 / 疑似污染"。
    """
    udp_sets = [frozenset(e.all_ips) for e in report.dns if e.ok and e.all_ips]
    doh_sets = [frozenset(e.all_ips) for e in report.doh if e.ok and e.all_ips]

    udp_union = frozenset().union(*udp_sets) if udp_sets else frozenset()
    doh_union_set = frozenset().union(*doh_sets) if doh_sets else frozenset()

    all_udp_agree = len(set(udp_sets)) <= 1 and bool(udp_sets)
    doh_disjoint = bool(udp_union and doh_union_set
                        and not (udp_union & doh_union_set))

    return {
        "udp_sets": udp_sets,
        "doh_sets": doh_sets,
        "udp_union": set(udp_union),
        "doh_union": set(doh_union_set),
        "all_udp_agree": all_udp_agree,
        "doh_disjoint": doh_disjoint,
    }


def _best_probe(probes: list[ProbeResult]) -> Optional[ProbeResult]:
    """挑一个最适合作为结论依据的 IP：优先有 HTTP 结果的、TCP 快的。"""
    if not probes:
        return None
    return sorted(
        probes,
        key=lambda p: (
            0 if p.serves_http else 1,
            0 if p.tcp is TcpStatus.OK else 1,
            p.tcp_ms,
        ),
    )[0]


# ---------------------------------------------------------------- 主判定

def judge(report: Report) -> Verdict:
    """产出最终结论。所有文案都在这里，渲染层只负责排版。"""
    dns_ips = dns_union(report)
    doh_ips = doh_union(report)
    hosts_ips = report.hosts_ips
    genuine = report.genuine_probes
    domain = report.domain

    # ---- 0. 环境可信度优先：控制组全不通时，其余结论一律作废
    if report.control_all_failed:
        failed = "、".join("%s(%s)" % (c.host, c.ip) for c in report.control)
        return Verdict(
            layer=Layer.INCONCLUSIVE,
            headline="无法判定：本机出网通道异常",
            evidence=("控制组全部不通（%s）。这说明当前网络本身无法正常访问外网，"
                      "本次所有「连不上」的结论都不可信。请先确认本机能打开任意网站，"
                      "或检查代理 / 防火墙设置后重新检测。" % failed),
            hosts_advice="不适用：请先恢复本机正常出网，再判断目标站点。",
        )

    # ---- 1. 完整访问成功
    served = [p for p in genuine if p.http and p.http.status is HttpStatus.OK]
    if served:
        best = _best_probe(served)
        assert best is not None and best.http is not None
        via_dns = best.ip in dns_ips
        via_hosts = best.ip in hosts_ips
        suffix = ""
        if not via_dns and via_hosts:
            suffix = "，经由 hosts 中已有条目"
        elif not via_dns:
            suffix = "，经由非 DNS 解析的 IP"

        verdict = Verdict(
            layer=Layer.SUCCESS,
            headline="可以直连（HTTP %s）%s" % (best.http.code_str, suffix),
            evidence=_success_evidence(best, dns_ips, hosts_ips, report),
        )
        verdict.hosts_advice, verdict.hosts_write_needed, verdict.hosts_entry_ips = \
            _hosts_advice_for_success(best, dns_ips, hosts_ips, domain)
        report.tips = build_tips(report, best)
        return verdict

    # ---- 2. 链路通，但服务端拒绝
    rejected = [p for p in genuine if p.http and p.http.status is HttpStatus.REJECT]
    if rejected:
        best = _best_probe(rejected)
        assert best is not None and best.http is not None
        via_dns = best.ip in dns_ips
        return Verdict(
            layer=Layer.HTTP_REJECT,
            headline="链路可连通（HTTP %s），服务端拒绝了本次请求" % best.http.code_str,
            evidence=("TCP 连通、TLS 握手成功、证书匹配、拿到了合法的 HTTP %s 响应 —— "
                      "网络层完全正常。本工具发的是极简请求头，4xx/5xx 通常来自"
                      "反爬 / 地域限制 / WAF 策略，浏览器带完整请求头访问往往是正常的。%s"
                      % (best.http.code_str,
                         "" if via_dns else "（当前经由非 DNS 解析的 IP）")),
            hosts_advice="无需修改 hosts：问题在服务端内容策略，与 DNS 和 hosts 无关。",
        )

    # ---- 3. 直连无响应，但经代理能通
    proxy_ok = [p for p in genuine
                if p.http_proxy and p.http_proxy.status is HttpStatus.OK]
    if proxy_ok:
        best = _best_probe(proxy_ok)
        assert best is not None and best.http_proxy is not None
        return Verdict(
            layer=Layer.PROXY_REQUIRED,
            headline="直连不通，但经代理可以访问（HTTP %s）" % best.http_proxy.code_str,
            evidence=("对 %s 的直连 HTTP 请求没有收到任何响应，而经 %s 访问返回 HTTP %s。"
                      "说明问题出在本机到该站之间的直连路径上，而不是站点本身。"
                      "你的浏览器走代理，所以浏览器里应该是正常的。"
                      % (best.ip, report.proxy.url, best.http_proxy.code_str)),
            hosts_advice=("不要改 hosts：改 hosts 只影响 DNS 解析，无法绕过直连路径上的阻断。"
                          "本机已配置代理（%s），保持浏览器走代理即可。" % report.proxy.url),
            proxy_note="直连与代理路径结果不同，浏览器走代理时不受影响。",
        )

    # ---- 4. 证书匹配、但 HTTP 层无响应
    silent = [p for p in genuine
              if p.http and p.http.status in (HttpStatus.NO_RESPONSE, HttpStatus.MALFORMED)]
    if silent:
        best = _best_probe(silent)
        assert best is not None and best.http is not None
        detail = best.http.detail or "未收到合法响应"
        proxy_hint = ""
        if report.proxy.present:
            proxy_hint = ("本机配置了代理（%s），直连探测结果可能与浏览器实际体验不一致，"
                          "请以浏览器为准。" % report.proxy.url)
        return Verdict(
            layer=Layer.HTTP_NO_RESPONSE,
            headline="TLS 与证书均正常，但 HTTP 层无响应",
            evidence=("对 %s 的 TLS 握手成功、证书确认属于该站，但 HTTP 请求没有得到有效响应"
                      "（%s）。这说明连接在应用层中断 —— 不是 DNS 问题，也不是证书问题。"
                      "%s" % (best.ip, detail, proxy_hint)),
            hosts_advice=("不要改 hosts：DNS 解析和证书都已确认正确。"
                          "建议检查本机代理 / 防火墙设置，或用浏览器实测确认。"),
        )

    # ---- 5. TCP + TLS 都通，但证书不匹配 -> 污染
    mismatched = [p for p in report.probes
                  if p.tls and p.tls.handshake_ok and not p.tls.cert_match]
    if mismatched:
        best = mismatched[0]
        got_cn = best.tls.cn if best.tls and best.tls.cn else "（无 CN）"
        return Verdict(
            layer=Layer.DNS_POISONED,
            headline="解析到的 IP 上不是目标站点（证书主体不匹配）",
            evidence=("连接到 %s 时 TLS 握手成功，但服务器出示的证书是 %s，"
                      "不包含 %s。这是 DNS 污染的典型特征：域名被解析到了别家的 IP。"
                      % (best.ip, got_cn, domain)),
            hosts_advice=("确认是 DNS 污染，但本次未找到能匹配证书的真实 IP。"
                          "请从可信渠道获取该站真实 IP 后，用 --ip 参数验证一次；"
                          "只有证书能匹配上域名的 IP 才值得写进 hosts。"),
        )

    # ---- 6. TCP 通、TLS 握手被切断 -> SNI 层
    blocked = [p for p in report.probes
               if p.tcp is TcpStatus.OK and p.tls
               and p.tls.status is TlsStatus.BLOCKED]
    if blocked:
        detail = blocked[0].tls.detail if blocked[0].tls else ""
        return Verdict(
            layer=Layer.TLS_BLOCKED,
            headline="TCP 能连通，但 TLS 握手被切断",
            evidence=("对 %d 个 IP 的 443 端口 TCP 连接均成功，但 TLS 握手阶段被中断（%s）。"
                      "阻断发生在 SNI 层：客户端发出明文域名后才被切断。"
                      % (len(blocked), detail or "RST 或无响应")),
            hosts_advice=("添加 hosts 无效。hosts 只影响 DNS 解析，够不到 SNI 这一层。"
                          "这类阻断需要代理 / 加密隧道才能绕过。"),
        )

    # ---- 7. 全部 TCP 不通
    if report.probes and all(p.tcp is not TcpStatus.OK for p in report.probes):
        reasons: dict[str, int] = {}
        for p in report.probes:
            reasons[p.tcp.value] = reasons.get(p.tcp.value, 0) + 1
        detail = "、".join("%s×%d" % (k, v) for k, v in reasons.items())
        return Verdict(
            layer=Layer.TCP_BLOCKED,
            headline="所有候选 IP 的 443 端口均不可达",
            evidence=("共探测 %d 个候选 IP，443 端口无一连通（%s）。"
                      "控制组正常，说明本机出网没问题，问题在这一目标上。"
                      % (len(report.probes), detail)),
            hosts_advice=("不适用：连 TCP 都连不上，改 hosts 和换 IP 都解决不了。"
                          "可能是服务器下线、端口被封，或需要代理才能访问。"),
        )

    # ---- 8. 完全没有解析结果
    if not dns_ips and not doh_ips and not report.probes:
        all_nx = all(e.status is DnsStatus.NXDOMAIN for e in report.dns if e.status)
        if all_nx:
            return Verdict(
                layer=Layer.DNS_FAIL,
                headline="域名不存在（所有 DNS 均返回 NXDOMAIN）",
                evidence="所有 DNS 服务器一致返回 NXDOMAIN，说明该域名未注册或已过期。",
                hosts_advice="不适用：域名本身不存在，改 hosts 也无意义。",
            )
        return Verdict(
            layer=Layer.DNS_FAIL,
            headline="解析失败：所有 DNS 均无 A / AAAA 记录",
            evidence="所有 UDP DNS 与 DoH 端点都未能返回该域名的地址记录。",
            hosts_advice="不适用：请先确认域名拼写正确，且域名未过期。",
        )

    # ---- 9. 兜底
    return Verdict(
        layer=Layer.UNKNOWN,
        headline="未能完成直连，原因需结合本机网络进一步确认",
        evidence=("已探测 %d 个 IP，均未形成完整证据链。建议：用 --ip 手动指定"
                  "可信 IP 重试，或在网络正常的环境复测。" % len(report.probes)),
        hosts_advice="暂无法判定，不建议此时修改 hosts。",
    )


# ---------------------------------------------------------------- hosts 建议

def _success_evidence(best: ProbeResult, dns_ips: list[str],
                      hosts_ips: list[str], report: Report) -> str:
    tls = best.tls
    parts = ["TCP 建连 %.0f ms" % best.tcp_ms]
    if tls:
        parts.append("协议 %s" % (tls.version or "未知"))
        if tls.alpn:
            parts.append("ALPN %s" % tls.alpn)
        parts.append("证书匹配 %s" % (tls.cn or "SAN"))
    if best.http:
        parts.append("HTTP %s" % best.http.code_str)
        if best.http.ttfb_ms:
            parts.append("首字节 %.0f ms" % best.http.ttfb_ms)
    evidence = "、".join(parts) + "。"
    if best.ip in dns_ips:
        evidence += "该 IP 来自 DNS 正常解析。"
    elif best.ip in hosts_ips:
        evidence += "该 IP 来自 hosts 已有条目（DNS 未返回它）。"
    if best.family == 6:
        evidence += "本次经由 IPv6 访问。"
    return evidence


def _hosts_advice_for_success(best: ProbeResult, dns_ips: list[str],
                              hosts_ips: list[str],
                              domain: str) -> tuple[str, bool, list[str]]:
    """成功场景下，hosts 该不该动。"""
    if best.ip in dns_ips:
        tip = ""
        if hosts_ips:
            tip = ("　（hosts 里已有的 %s 属于冗余，删掉也不影响访问）"
                   % "、".join(hosts_ips))
        return "DNS 解析正常且可连通，无需添加 hosts。" + tip, False, []

    if best.ip in hosts_ips:
        return ("该站需要靠 hosts 才能访问，而你 hosts 里已经有这条并且可用 —— "
                "保持现状即可，无需改动：\n\n```\n%s    %s\n```"
                % (best.ip, domain), False, [])

    return ("DNS 当前返回的 IP 不可用，但以下 IP 能完成 TLS 握手、证书匹配"
            "且有 HTTP 响应，添加 hosts 可解决：\n\n```\n%s    %s\n```"
            % (best.ip, domain), True, [best.ip])


# ---------------------------------------------------------------- 优化建议

def build_tips(report: Report, best: Optional[ProbeResult]) -> list[str]:
    """可连接时给出的优化建议。只讲有证据的事。"""
    tips: list[str] = []

    ok_dns = [e for e in report.dns if e.ok]
    if ok_dns:
        ranked = sorted(ok_dns, key=lambda e: e.ms)
        fastest, slowest = ranked[0], ranked[-1]
        tips.append("DNS 延迟：最快 %s（%s）%.0f ms，最慢 %s %.0f ms"
                    % (fastest.name, fastest.server, fastest.ms,
                       slowest.name, slowest.ms))
        if fastest.ms < 20 and slowest.ms > 80:
            tips.append("不同 DNS 延迟差距较大，改用最快的那家可缩短首屏等待")

    consistency = dns_consistency(report)
    if consistency["doh_disjoint"]:
        tips.append("[!] UDP DNS 与加密 DNS 返回完全不同的 IP，存在污染迹象，"
                    "建议启用 DoH（加密 DNS）")
    elif not consistency["all_udp_agree"] and consistency["udp_sets"]:
        tips.append("不同 DNS 返回了不同 IP，属于 CDN 就近调度，通常无需处理")

    if report.proxy.present:
        tips.append("本机检测到代理（%s，来源：%s），直连探测结果与浏览器实际路径可能不同"
                    % (report.proxy.url, report.proxy.source))

    if best is None:
        return tips

    tls = best.tls
    if tls:
        if tls.alpn == "h2":
            tips.append("服务端支持 HTTP/2（ALPN 协商成功），协议层无需优化")
        elif tls.alpn:
            tips.append("当前协商协议 %s，服务端未提供 HTTP/2" % tls.alpn)

        if tls.version == "TLSv1.3":
            tips.append("TLS 1.3 已启用，握手开销最低")
        elif tls.version:
            tips.append("当前 %s，建议服务端升级到 TLS 1.3" % tls.version)

        if not tls.chain_trusted:
            tips.append("[!] 证书链不受信任（%s），浏览器会显示安全警告"
                        % (tls.chain_error or "自签或私有 CA"))

        if tls.days_left is not None:
            if tls.days_left < 0:
                tips.append("[!] 证书已过期 %d 天" % abs(tls.days_left))
            elif tls.days_left < 14:
                tips.append("[!] 证书将在 %d 天后过期，建议提前续期" % tls.days_left)
            elif tls.days_left < 30:
                tips.append("证书剩余 %d 天，可留意续期时间" % tls.days_left)

    if best.http:
        if best.http.status is HttpStatus.OK and best.http.code and 300 <= best.http.code < 400:
            if best.http.location:
                tips.append("首页返回 %d 跳转到 %s，可把书签直接指向最终地址省一次往返"
                            % (best.http.code, best.http.location[:80]))
        if best.http.ttfb_ms > 800:
            tips.append("首字节 %.0f ms 偏高，可能是服务端响应慢或链路绕行"
                        % best.http.ttfb_ms)

    if best.tcp_ms > 200:
        tips.append("TCP 建连 %.0f ms 偏高，链路质量一般，可考虑就近节点" % best.tcp_ms)

    if best.family == 6:
        tips.append("本次经由 IPv6 访问，若同时有 A 记录可对比两条路径的速度")

    if report.hosts:
        lines = "、".join(str(line) for line, _ip in report.hosts)
        tips.append("hosts 中已有该域名条目（第 %s 行），若与当前可用 IP 不一致建议更新"
                    % lines)

    return tips
