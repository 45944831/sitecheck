# -*- coding: utf-8 -*-
"""检测调度：并发跑完 DNS → 控制组 → 逐 IP 探测，产出 Report。

相对 v1.0 的性能改动：
    v1.0 三层全串行，单个死 IP 就吃掉 8 秒超时，实测 6 个候选 IP 耗时 53 秒。
    这里全部并发，并在探测阶段先并发 TCP 筛掉死的 IP，再并发做 TLS+HTTP，
    把总耗时压到个位数秒。
"""
from __future__ import annotations

import ipaddress
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Optional

from . import dns as dnsmod
from . import hosts as hostsmod
from . import probe as probemod
from . import proxy as proxymod
from . import verdict as verdictmod
from .models import (
    ControlResult,
    DnsResult,
    HttpStatus,
    ProbeResult,
    ProxyInfo,
    Report,
    TcpStatus,
)

DEFAULT_TIMEOUT = 8.0
MAX_WORKERS = 12

# 控制组：验证本机出网是否可信。
# 用多个不同运营商的站点，任一 TLS 握手成功即认为出网正常。
# v1.0 把 GitHub 的 IP 硬编码成 20.205.243.166，该 IP 早已失效，
# 控制组形同虚设 —— 这里改为运行时解析，不写死任何 IP。
CONTROLS: list[tuple[str, str]] = [
    ("www.baidu.com", "百度"),
    ("www.qq.com", "腾讯"),
    ("www.cloudflare.com", "Cloudflare"),
]

# 进度回调：(阶段名, 描述, 已完成, 总数)
ProgressFn = Callable[[str, str, int, int], None]


def _noop(stage: str, msg: str, done: int, total: int) -> None:
    return None


def normalize_domain(raw: str) -> str:
    """把用户输入的各种形式统一成纯域名。"""
    value = (raw or "").strip()
    value = value.replace("https://", "").replace("http://", "")
    value = value.split("/")[0].split("?")[0].split("#")[0]
    value = value.split("@")[-1]          # 去掉 user:pass@
    if value.startswith("["):             # [::1]:443
        value = value[1:].split("]")[0]
    elif value.count(":") == 1:           # host:443
        value = value.split(":")[0]
    return value.strip().strip(".").lower()


# ---------------------------------------------------------------- DNS 阶段

def _resolve_all(domain: str, timeout: float, progress: ProgressFn,
                 stage: str) -> tuple[list[DnsResult], list[DnsResult]]:
    servers = dnsmod.UDP_RESOLVERS
    endpoints = dnsmod.DOH_ENDPOINTS
    total = len(servers) + len(endpoints)

    udp_results: list[DnsResult] = []
    doh_results: list[DnsResult] = []
    done = 0

    with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, total)) as pool:
        udp_futures = {
            pool.submit(dnsmod.query_server, srv, name, domain, timeout): ("udp", srv, name)
            for srv, name in servers
        }
        doh_futures = {
            pool.submit(dnsmod.query_doh, ep, name, domain, timeout * 1.5): ("doh", ep, name)
            for ep, name in endpoints
        }

        for future in as_completed(list(udp_futures) + list(doh_futures)):
            kind, addr, name = (udp_futures | doh_futures)[future]
            done += 1
            try:
                result = future.result(timeout=timeout * 3)
            except Exception as exc:                       # noqa: BLE001 - 单个服务器失败不影响整体
                result = DnsResult(server=addr, name=name,
                                   status=dnsmod.DnsStatus.ERROR,
                                   transport=kind, error=str(exc)[:60])
            if kind == "udp":
                udp_results.append(result)
            else:
                doh_results.append(result)
            progress(stage, "查询 DNS：%s" % name, done, total)

    udp_results.sort(key=lambda r: (not r.ok, r.ms))
    doh_results.sort(key=lambda r: (not r.ok, r.ms))
    return udp_results, doh_results


# ---------------------------------------------------------------- 控制组

def _check_control(domain: str, timeout: float, progress: ProgressFn,
                   stage: str) -> list[ControlResult]:
    """控制组：DNS → TLS 握手。TLS 能完成才说明出网通道完整（含 SNI 未被拦）。"""
    results: list[ControlResult] = []
    total = len(CONTROLS)
    done = 0

    def check_one(host: str, label: str) -> ControlResult:
        try:
            result = dnsmod.query_server("223.5.5.5", "阿里", host, timeout)
            if not result.all_ips:
                return ControlResult(host=host, ip="-", ok=False,
                                     detail="解析失败")
            ip = result.all_ips[0]
            tls = probemod.tls_probe(ip, host, 443,
                                     min(timeout, probemod.TLS_TIMEOUT_CAP))
            ok = tls.handshake_ok
            return ControlResult(host=host, ip=ip, ok=ok,
                                 detail=tls.detail or tls.status.value)
        except Exception as exc:                          # noqa: BLE001
            return ControlResult(host=host, ip="-", ok=False,
                                 detail=str(exc)[:50])

    with ThreadPoolExecutor(max_workers=total) as pool:
        futures = {pool.submit(check_one, h, label): (h, label)
                   for h, label in CONTROLS}
        for future in as_completed(futures):
            host, label = futures[future]
            done += 1
            try:
                results.append(future.result(timeout=timeout * 2))
            except Exception as exc:                      # noqa: BLE001
                results.append(ControlResult(host=host, ip="-", ok=False,
                                             detail=str(exc)[:50]))
            progress(stage, "控制组：%s" % label, done, total)

    order = {h: i for i, (h, _l) in enumerate(CONTROLS)}
    results.sort(key=lambda r: order.get(r.host, 99))
    return results


# ---------------------------------------------------------------- 候选 IP

def collect_candidates(report: Report, extra_ips: list[str]) -> list[tuple[str, str]]:
    """汇总候选 IP 并标注来源。返回 [(ip, 来源)]。

    来源优先级：手动 > hosts > 解析 > 候选。
    v1.0 把 hosts 已有条目也纳入探测是对的 —— 用户真正想问的
    往往是"我现在 hosts 里这条还能不能用"。
    """
    manual: list[str] = []
    for raw in extra_ips:
        try:
            manual.append(str(ipaddress.ip_address(str(raw).strip())))
        except ValueError:
            continue

    from_dns: list[str] = []
    for entry in report.dns + report.doh:
        if not entry.ok:
            continue
        for ip in entry.all_ips:
            if ip not in from_dns:
                from_dns.append(ip)

    from_hosts = report.hosts_ips

    ordered: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(ip: str, source: str) -> None:
        if ip in seen:
            return
        seen.add(ip)
        ordered.append((ip, source))

    for ip in manual:
        add(ip, "手动")
    for ip in from_hosts:
        add(ip, "hosts")
    for ip in from_dns:
        add(ip, "解析")

    # 系统解析栈的结果（会读 hosts）也纳入，标注为"候选"
    for ip in dnsmod.system_resolve(report.domain):
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        add(ip, "候选")

    return ordered


# ---------------------------------------------------------------- 探测阶段

def _probe_candidates(domain: str, candidates: list[tuple[str, str]],
                      timeout: float, progress: ProgressFn,
                      stage: str) -> list[ProbeResult]:
    """两阶段并发：先 TCP 筛活，再对活着的做 TLS + HTTP。"""
    total = len(candidates)
    results: dict[str, ProbeResult] = {}
    done = 0

    if not candidates:
        return []

    tcp_timeout = min(timeout, probemod.TCP_TIMEOUT_CAP)

    # 阶段 A：并发 TCP
    alive: list[tuple[str, str]] = []
    with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, total)) as pool:
        futures = {
            pool.submit(probemod.tcp_probe, ip, 443, tcp_timeout): (ip, source)
            for ip, source in candidates
        }
        for future in as_completed(futures):
            ip, source = futures[future]
            done += 1
            try:
                tcp_status, tcp_ms = future.result(timeout=tcp_timeout * 2)
            except Exception:                              # noqa: BLE001
                tcp_status, tcp_ms = TcpStatus.UNREACHABLE, 0.0
            results[ip] = ProbeResult(ip=ip, source=source,
                                      family=6 if ":" in ip else 4,
                                      tcp=tcp_status, tcp_ms=tcp_ms)
            if tcp_status is TcpStatus.OK:
                alive.append((ip, source))
            progress(stage, "TCP 可达性：%s" % ip, done, total)

    if not alive:
        return [results[ip] for ip, _ in candidates]

    # 阶段 B：并发 TLS + HTTP（TCP 已在阶段 A 确认，不再重测）
    # 单独起一个阶段名并重新计数：两阶段的对象不同（候选 IP / 活 IP），
    # 混用一个计数器会出现 [5/4] 这种超出总数、或分母中途变化的怪现象。
    total = len(alive)
    done = 0
    stage_b = stage + "（TLS/HTTP）"
    # 先报一次，让终端立刻出现阶段标题 —— 否则 TLS+HTTP 的等待期间
    # 一行输出都没有，看起来像卡死了。
    progress(stage_b, "并发探测 %d 个 IP（TLS + HTTP）" % total, 0, total)
    with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(alive))) as pool:
        futures = {
            pool.submit(probemod.probe_ip, ip, domain, timeout, None, True): ip
            for ip, _source in alive
        }
        for future in as_completed(futures):
            ip = futures[future]
            done += 1
            try:
                data = future.result(timeout=timeout * 3)
            except Exception:                              # noqa: BLE001
                data = {}
            base = results[ip]
            if data:
                base.tls = data.get("tls")
                base.http = data.get("http")
            progress(stage_b, "探测：%s" % ip, done, total)

    return [results[ip] for ip, _ in candidates]


def _proxy_crosscheck(domain: str, probes: list[ProbeResult],
                      proxy_info: ProxyInfo, timeout: float) -> None:
    """直连 HTTP 失败时，挑一个 IP 经代理再试一次。

    只做一次而不是每个 IP 都做：
        直连不通通常是整条路径的问题，不是单个 IP 的问题。
        每个 IP 都跑一遍代理对照，最坏耗时直接翻倍，信息量却几乎不增加。
    """
    if not proxy_info.present or not proxymod.can_tunnel(proxy_info):
        return
    targets = [p for p in probes
               if p.genuine and p.http
               and p.http.status in (HttpStatus.NO_RESPONSE, HttpStatus.MALFORMED)]
    if not targets:
        return
    best = min(targets, key=lambda p: p.tcp_ms)
    best.http_proxy = probemod.http_probe(
        best.ip, domain, timeout=min(timeout, probemod.PROXY_TIMEOUT_CAP),
        proxy_info=proxy_info, use_proxy=True)


# ---------------------------------------------------------------- 主流程

def analyze(domain: str, extra_ips: Optional[list[str]] = None,
            progress: Optional[ProgressFn] = None,
            timeout: float = DEFAULT_TIMEOUT,
            version: str = "") -> Report:
    """完整检测。返回 Report，结论在 report.verdict 里。"""
    progress = progress or _noop
    extra_ips = extra_ips or []
    domain = normalize_domain(domain)

    report = Report(
        domain=domain,
        time=datetime.now().strftime("%Y-%m-%d %H:%M"),
        version=version,
        extra_ips=extra_ips,
    )

    # 本机状态
    report.proxy = proxymod.detect()
    report.hosts = hostsmod.find_entries(domain)
    report.sys_ips = dnsmod.system_resolve(domain)

    # DNS
    report.dns, report.doh = _resolve_all(domain, timeout, progress, "DNS 解析")

    # 控制组
    # 不跟 DNS 并行：两者都要往进度流里写字，并发会让 ▸ 阶段标题来回跳，
    # 而并行只省下不到 1 秒，不值得牺牲输出的可读性。
    report.control = _check_control(domain, timeout, progress, "出网校验")

    # 候选 IP
    candidates = collect_candidates(report, extra_ips)

    # 逐 IP 探测
    report.probes = _probe_candidates(domain, candidates, timeout,
                                      progress, "逐 IP 探测")

    # 直连 HTTP 失败时，经代理补一次对照（只做一次）
    _proxy_crosscheck(domain, report.probes, report.proxy, timeout)

    # 真实 IP：证书匹配才算
    report.real_ips = [p.ip for p in report.probes if p.genuine]

    # 判定
    report.verdict = verdictmod.judge(report)
    if not report.tips:
        report.tips = verdictmod.build_tips(report, _primary(report))
    return report


def _primary(report: Report) -> Optional[ProbeResult]:
    served = [p for p in report.probes
              if p.genuine and p.http and p.http.status is HttpStatus.OK]
    pool = served or report.genuine_probes
    if not pool:
        return None
    return sorted(pool, key=lambda p: p.tcp_ms)[0]


def analyze_and_judge(domain: str, extra_ips: Optional[list[str]] = None,
                      progress: Optional[ProgressFn] = None,
                      timeout: float = DEFAULT_TIMEOUT,
                      version: str = "") -> Report:
    """analyze 的别名，语义更明确（结论已包含在 report.verdict）。"""
    return analyze(domain, extra_ips, progress, timeout, version)
