# -*- coding: utf-8 -*-
"""检测调度：并发跑完 DNS → 控制组 → 逐 IP 探测，产出 Report。

相对 v1.0 的性能改动：
    v1.0 三层全串行，单个死 IP 就吃掉 8 秒超时，实测 6 个候选 IP 耗时 53 秒。
    这里全部并发，并在探测阶段先并发 TCP 筛掉死的 IP，再并发做 TLS+HTTP，
    把总耗时压到个位数秒。
"""
from __future__ import annotations

import ipaddress
import time
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
# 整体上限：单层超时再宽松，一次检测也不能无限拖下去。
# 正常场景实测 3~8 秒；45 秒只用来兜住"多层同时超时"的最坏情况。
DEFAULT_TOTAL_TIMEOUT = 45.0
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
StopFn = Callable[[], bool]


def _noop(stage: str, msg: str, done: int, total: int) -> None:
    return None


def _stop_reason(deadline: Optional[float], should_stop: Optional[StopFn]) -> str:
    """返回停止原因：用户取消 / 整体超时 / 空串表示继续。"""
    if should_stop is not None:
        try:
            if should_stop():
                return "用户取消"
        except Exception:                                  # noqa: BLE001
            pass
    if deadline is not None and time.monotonic() >= deadline:
        return "整体超时"
    return ""


def _remaining(deadline: Optional[float], cap: float) -> float:
    """本阶段可用的时间：不超过单层上限，也不超过整体剩余。"""
    if deadline is None:
        return cap
    return max(0.0, min(cap, deadline - time.monotonic()))


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

def _control_ips(host: str, timeout: float) -> list[str]:
    """给控制组解析 IP：阿里 DNS → 系统解析 → DoH。

    v2.0.0 只查阿里一台 DNS。UDP 53 被拦时控制组会整体误判为
    "本机出网异常"，把结论带偏 —— 这里加两级回退。
    """
    result = dnsmod.query_server("223.5.5.5", "阿里", host, timeout)
    if result.all_ips:
        return result.all_ips

    ips = dnsmod.system_resolve(host)
    if ips:
        return ips

    doh = dnsmod.query_doh("https://223.5.5.5/dns-query", "DoH", host, timeout)
    return doh.all_ips


def _check_control(domain: str, timeout: float, progress: ProgressFn,
                   stage: str,
                   proxy_info: Optional[ProxyInfo] = None) -> list[ControlResult]:
    """控制组：DNS → TLS 握手。TLS 能完成才说明出网通道完整（含 SNI 未被拦）。

    直连不通但配置了可隧道的代理时，再经代理复核一次：浏览器走代理
    能打开控制站点，就说明"本机出网"本身没问题，不该判成环境异常。
    """
    results: list[ControlResult] = []
    total = len(CONTROLS)
    done = 0

    def check_one(host: str, label: str) -> ControlResult:
        try:
            ips = _control_ips(host, timeout)
            if not ips:
                return ControlResult(host=host, ip="-", ok=False,
                                     detail="解析失败")
            ip = ips[0]
            tls = probemod.tls_probe(ip, host, 443,
                                     min(timeout, probemod.TLS_TIMEOUT_CAP))
            if tls.handshake_ok:
                return ControlResult(host=host, ip=ip, ok=True,
                                     detail="")
            if (proxy_info and proxy_info.present
                    and proxymod.can_tunnel(proxy_info)
                    and not proxymod.is_bypassed(proxy_info, host)):
                via = probemod.tls_probe(
                    ip, host, 443, min(timeout, probemod.TLS_TIMEOUT_CAP),
                    proxy_info=proxy_info)
                if via.handshake_ok:
                    return ControlResult(host=host, ip=ip, ok=True,
                                         detail="经代理")
            return ControlResult(host=host, ip=ip, ok=False,
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
                      stage: str,
                      deadline: Optional[float] = None,
                      should_stop: Optional[StopFn] = None
                      ) -> tuple[list[ProbeResult], bool]:
    """两阶段并发：先 TCP 筛活，再对活着的做 TLS + HTTP。

    返回 (结果, 是否被取消/超时截断)。截断时只返回真正探测过的 IP，
    调用方据此把结论标成"不完整"，而不是把没测的 IP 当成不通。
    """
    total = len(candidates)
    results: dict[str, ProbeResult] = {}
    done = 0
    truncated = False

    if not candidates:
        return [], False

    tcp_timeout = min(timeout, probemod.TCP_TIMEOUT_CAP)

    # 阶段 A：并发 TCP
    alive: list[tuple[str, str]] = []
    pool = ThreadPoolExecutor(max_workers=min(MAX_WORKERS, total))
    futures = {
        pool.submit(probemod.tcp_probe, ip, 443, tcp_timeout): (ip, source)
        for ip, source in candidates
    }
    try:
        for future in as_completed(futures):
            if _stop_reason(deadline, should_stop):
                truncated = True
                break
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
    finally:
        pool.shutdown(wait=not truncated, cancel_futures=truncated)

    if truncated or not alive:
        return [results[ip] for ip, _ in candidates if ip in results], truncated

    # 阶段 B：并发 TLS + HTTP（TCP 已在阶段 A 确认，不再重测）
    # 单独起一个阶段名并重新计数：两阶段的对象不同（候选 IP / 活 IP），
    # 混用一个计数器会出现 [5/4] 这种超出总数、或分母中途变化的怪现象。
    total = len(alive)
    done = 0
    stage_b = stage + "（TLS/HTTP）"
    # 先报一次，让终端立刻出现阶段标题 —— 否则 TLS+HTTP 的等待期间
    # 一行输出都没有，看起来像卡死了。
    progress(stage_b, "并发探测 %d 个 IP（TLS + HTTP）" % total, 0, total)
    pool = ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(alive)))
    futures = {
        pool.submit(probemod.probe_ip, ip, domain, timeout, None, True): ip
        for ip, _source in alive
    }
    try:
        for future in as_completed(futures):
            if _stop_reason(deadline, should_stop):
                truncated = True
                break
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
    finally:
        pool.shutdown(wait=not truncated, cancel_futures=truncated)

    return [results[ip] for ip, _ in candidates if ip in results], truncated


def _proxy_crosscheck(domain: str, probes: list[ProbeResult],
                      proxy_info: ProxyInfo, timeout: float) -> None:
    """直连失败时，经代理再试一次，用来区分"站点挂了"和"本机必须走代理"。

    两种触发场景：
        1. 直连完成 TLS 且证书匹配，但 HTTP 无响应 / 响应异常；
        2. 直连连 TCP/TLS 都没完成 —— 这正是"必须走代理"环境里最常见的形态，
           v2.0.0 只在场景 1 触发，导致 PROXY_REQUIRED 永远到不了。
    最多试两个 IP：直连失败通常是整条路径的问题，多试几个信息量有限。
    """
    if not proxy_info.present or not proxymod.can_tunnel(proxy_info):
        return
    if proxymod.is_bypassed(proxy_info, domain):
        return

    silent = [p for p in probes
              if p.genuine and p.http
              and p.http.status in (HttpStatus.NO_RESPONSE, HttpStatus.MALFORMED)]
    if silent:
        targets = sorted(silent, key=lambda p: p.tcp_ms)[:1]
    elif not any(p.genuine for p in probes):
        priority = {"手动": 0, "hosts": 1, "解析": 2, "候选": 3}
        targets = sorted(probes, key=lambda p: (priority.get(p.source, 9),
                                                p.tcp_ms))[:2]
    else:
        return

    for target in targets:
        target.http_proxy = probemod.http_probe(
            target.ip, domain, timeout=min(timeout, probemod.PROXY_TIMEOUT_CAP),
            proxy_info=proxy_info, use_proxy=True)


# ---------------------------------------------------------------- 主流程

def analyze(domain: str, extra_ips: Optional[list[str]] = None,
            progress: Optional[ProgressFn] = None,
            timeout: float = DEFAULT_TIMEOUT,
            version: str = "",
            total_timeout: Optional[float] = DEFAULT_TOTAL_TIMEOUT,
            should_stop: Optional[StopFn] = None) -> Report:
    """完整检测。返回 Report，结论在 report.verdict 里。

    total_timeout 为整体上限（秒，None 表示不限）；should_stop 每阶段检查一次，
    用于 GUI 取消。被中断时 report.incomplete 记录原因，判定只会给
    INCONCLUSIVE，不会把"没测到"当成"不通"。
    """
    progress = progress or _noop
    extra_ips = extra_ips or []
    domain = normalize_domain(domain)

    report = Report(
        domain=domain,
        time=datetime.now().strftime("%Y-%m-%d %H:%M"),
        version=version,
        extra_ips=extra_ips,
    )
    deadline = (time.monotonic() + total_timeout
                if total_timeout and total_timeout > 0 else None)
    aborted = _stop_reason(deadline, should_stop)

    # 本机状态
    report.proxy = proxymod.detect()
    report.hosts = hostsmod.find_entries(domain)
    report.sys_ips = dnsmod.system_resolve(domain)

    # DNS
    if not aborted:
        budget = _remaining(deadline, timeout)
        if budget > 0.1:
            report.dns, report.doh = _resolve_all(domain, budget, progress,
                                                  "DNS 解析")
        else:
            aborted = _stop_reason(deadline, should_stop) or "整体超时"

    # 控制组
    # 不跟 DNS 并行：两者都要往进度流里写字，并发会让 ▸ 阶段标题来回跳，
    # 而并行只省下不到 1 秒，不值得牺牲输出的可读性。
    if not aborted:
        budget = _remaining(deadline, timeout)
        if budget > 0.1:
            report.control = _check_control(domain, budget, progress,
                                            "出网校验", report.proxy)
        else:
            aborted = _stop_reason(deadline, should_stop) or "整体超时"

    # 候选 IP
    candidates = collect_candidates(report, extra_ips)

    # 逐 IP 探测
    if not aborted:
        budget = _remaining(deadline, timeout)
        if budget > 0.1:
            report.probes, truncated = _probe_candidates(
                domain, candidates, budget, progress, "逐 IP 探测",
                deadline, should_stop)
            if truncated:
                aborted = _stop_reason(deadline, should_stop) or "整体超时"
        else:
            aborted = _stop_reason(deadline, should_stop) or "整体超时"

    # 直连失败时，经代理补一次对照
    if not aborted:
        budget = _remaining(deadline, timeout)
        if budget > 0.1:
            _proxy_crosscheck(domain, report.probes, report.proxy, budget)

    report.incomplete = aborted
    if aborted:
        progress("收尾", "检测中断：%s" % aborted, 0, 0)

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
                      version: str = "",
                      total_timeout: Optional[float] = DEFAULT_TOTAL_TIMEOUT,
                      should_stop: Optional[StopFn] = None) -> Report:
    """analyze 的别名，语义更明确（结论已包含在 report.verdict）。"""
    return analyze(domain, extra_ips, progress, timeout, version,
                   total_timeout, should_stop)
