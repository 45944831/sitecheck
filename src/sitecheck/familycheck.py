# -*- coding: utf-8 -*-
"""域名族轻量核验：只回答两个问题。

    1. 这个域名当前系统解析到的 IP 能用吗（证书匹配 + 可服务）？
    2. 有没有别的可用 IP 可以固定进 hosts？

刻意不跑完整 analyze()：那会为每个域名做 9 次 DNS + 控制组，
31 个域名并发会触发限流，而且对"要不要写 hosts"这个问题没有增量信息。
候选 IP 来自远程情报源（GitHub520），真身一律用 TLS 证书校验，
不因为"情报源说这个 IP 对"就直接写入。
"""
from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime

from . import dns as dnsmod
from . import probe as probemod
from .family import FamilyDomain

# 并发上限。远程情报源有缓存，TLS 握手才是主要开销；8 路足够快又不至于
# 被对端当作扫描。MAX_WORKERS 与 orchestrator 保持一致量级。
MAX_WORKERS = 8


@dataclass
class DomainCheck:
    domain: str
    label: str
    group: str
    fixable: bool
    sys_ips: list[str] = field(default_factory=list)
    candidate_ips: list[str] = field(default_factory=list)
    working_ips: list[str] = field(default_factory=list)   # 证书匹配且 HTTP 可用
    genuine_ips: list[str] = field(default_factory=list)   # 证书匹配（未必 HTTP 可用）
    status: str = "pending"     # ok / fixable / unusable / inconclusive
    note: str = ""

    @property
    def needs_fix(self) -> bool:
        """当前解析不可用，但找到了可固定的真实 IP。"""
        return self.status == "fixable"


@dataclass
class FamilyCheckReport:
    name: str
    time: str
    version: str
    checks: list[DomainCheck] = field(default_factory=list)

    @property
    def fixable(self) -> list[DomainCheck]:
        return [c for c in self.checks if c.needs_fix]

    @property
    def ok(self) -> list[DomainCheck]:
        return [c for c in self.checks if c.status == "ok"]

    @property
    def unusable(self) -> list[DomainCheck]:
        return [c for c in self.checks if c.status == "unusable"]


def _sys_ips(domain: str) -> list[str]:
    try:
        return dnsmod.system_resolve(domain)
    except Exception:                                  # noqa: BLE001
        return []


def _candidates(domain: str, sys_ips: list[str]) -> list[str]:
    """远程情报源 + 系统解析，去重保序。远程失败不影响本地候选。"""
    out: list[str] = []
    try:
        remote = dnsmod.fetch_remote_ips(domain, timeout=3.0)
    except Exception:                                  # noqa: BLE001
        remote = []
    for ip in remote + sys_ips:
        if ip not in out:
            out.append(ip)
    return out


def check_domain(item: FamilyDomain, timeout: float = 4.0) -> DomainCheck:
    """核验单个域名。不打网络以外的依赖，可离线用 mock 测。"""
    result = DomainCheck(
        domain=item.domain, label=item.label,
        group=item.group, fixable=item.fixable)

    result.sys_ips = _sys_ips(item.domain)
    if not result.sys_ips:
        result.status = "inconclusive"
        result.note = "系统无法解析该域名"
        return result

    result.candidate_ips = _candidates(item.domain, result.sys_ips)
    if not result.candidate_ips:
        result.status = "inconclusive"
        result.note = "没有可用候选 IP"
        return result

    # 证书校验：系统解析当前 IP + 候选 IP 都测一遍
    to_test = list(dict.fromkeys(result.sys_ips + result.candidate_ips))
    for ip in to_test:
        tls = probemod.tls_probe(ip, item.domain, 443, timeout=timeout)
        if not (tls.handshake_ok and tls.cert_match):
            continue
        if ip not in result.genuine_ips:
            result.genuine_ips.append(ip)
        http = probemod.http_probe(ip, item.domain, timeout=min(timeout, 5.0))
        if http.usable and ip not in result.working_ips:
            result.working_ips.append(ip)

    if not result.genuine_ips:
        result.status = "unusable"
        result.note = "候选 IP 均未通过证书校验"
    elif any(ip in result.sys_ips for ip in result.working_ips):
        result.status = "ok"
        result.note = "当前系统解析的 IP 可用"
    elif result.working_ips:
        result.status = "fixable" if result.fixable else "unusable"
        result.note = ("当前解析不可用，另有可用 IP" if result.fixable
                       else "当前解析不可用（第三方 CDN，不建议固定 hosts）")
    elif result.genuine_ips:
        # 证书对但 HTTP 不可用：可能是服务端拒绝，不算 network 层的"可修"
        result.status = "inconclusive"
        result.note = "证书匹配的 IP 未提供可用 HTTP 响应"
    return result


def run(name: str, domains: list[FamilyDomain], version: str = "",
        timeout: float = 4.0,
        progress: Callable[[str, int, int], None] | None = None
        ) -> FamilyCheckReport:
    """并发核验一族域名；保持输入顺序输出。"""
    report = FamilyCheckReport(
        name=name, time=datetime.now().strftime("%Y-%m-%d %H:%M"),
        version=version)
    if not domains:
        return report

    collected: dict[str, DomainCheck] = {}
    done = 0
    with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(domains))) as pool:
        futures = {pool.submit(check_domain, d, timeout): d for d in domains}
        for future in as_completed(futures):
            item = futures[future]
            done += 1
            try:
                collected[item.domain] = future.result()
            except Exception as exc:                  # noqa: BLE001
                collected[item.domain] = DomainCheck(
                    domain=item.domain, label=item.label,
                    group=item.group, fixable=item.fixable,
                    status="inconclusive", note="检测异常：%s" % str(exc)[:60])
            if progress:
                progress(item.domain, done, len(domains))

    report.checks = [collected[d.domain] for d in domains if d.domain in collected]
    return report


# ---------------------------------------------------------------- 渲染

_STATUS_MARK = {"ok": "可用", "fixable": "可修复", "unusable": "不可用",
                "inconclusive": "无法判定"}


def render_text(report: FamilyCheckReport) -> str:
    lines = [
        "# 域名族核验：%s" % report.name,
        "",
        "共 %d 个域名：%d 可用、%d 可修复、%d 不可用、%d 无法判定"
        % (len(report.checks), len(report.ok), len(report.fixable),
           len(report.unusable),
           len(report.checks) - len(report.ok) - len(report.fixable)
           - len(report.unusable)),
        "",
        "| 分组 | 域名 | 用途 | 状态 | 可用 IP | 说明 |",
        "|---|---|---|---|---|---|",
    ]
    for c in report.checks:
        lines.append("| %s | %s | %s | %s | %s | %s |" % (
            c.group, c.domain, c.label, _STATUS_MARK.get(c.status, c.status),
            "、".join(c.working_ips[:2]) or "-", c.note))
    fix = report.fixable
    if fix:
        lines += ["", "**可批量写入 hosts 的域名**（当前解析不通，但已验证到可用真实 IP）：", ""]
        for c in fix:
            lines.append("- `%s` → %s" % (c.domain, c.working_ips[0]))
        lines += ["", "执行：`sitecheck --family %s --apply-hosts`" % report.name]
    lines += ["", "检测时间：%s　|　工具版本 v%s"
              % (report.time, report.version or "-")]
    return "\n".join(lines)


def render_json(report: FamilyCheckReport, indent: int = 2) -> str:
    import dataclasses
    import json
    return json.dumps(dataclasses.asdict(report), ensure_ascii=False, indent=indent)


def render_html(report: FamilyCheckReport) -> str:
    import html
    rows = "".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
        % (html.escape(c.group), html.escape(c.domain), html.escape(c.label),
           html.escape(_STATUS_MARK.get(c.status, c.status)),
           html.escape("、".join(c.working_ips[:2]) or "-"),
           html.escape(c.note))
        for c in report.checks
    )
    return (
        "<div style='font-family:Microsoft YaHei UI,sans-serif;font-size:10pt;'>"
        "<h2>域名族核验：%s</h2>"
        "<table cellspacing='0' cellpadding='5' width='100%%' "
        "style='border-collapse:collapse;font-size:9pt;'>"
        "<tr style='background:#f0f2f5;'><th>分组</th><th>域名</th><th>用途</th>"
        "<th>状态</th><th>可用 IP</th><th>说明</th></tr>%s</table></div>"
        % (html.escape(report.name), rows)
    )
