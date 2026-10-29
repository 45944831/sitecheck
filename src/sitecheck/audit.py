# -*- coding: utf-8 -*-
"""hosts 文件体检。

合并 v1.0 的 hosts_audit.py 与 hosts-verify.py（两者功能高度重复，
命名风格还不一致）。输出每条映射是否真的可用、是否与 DNS 一致、是否重复。
"""
from __future__ import annotations

import ipaddress
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from . import dns as dnsmod
from . import hosts as hostsmod
from . import probe as probemod
from .models import HttpStatus, TcpStatus, TlsStatus

ProgressFn = Callable[[str, str, int, int], None]


def classify_ip(ip: str) -> str:
    """标注明显不该出现在 hosts 里的地址。返回空字符串表示正常公网地址。"""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "非法地址"
    if addr.is_unspecified:
        return "屏蔽条目（0.0.0.0）"
    if addr.is_loopback:
        return "回环地址"
    if addr.is_link_local:
        return "链路本地地址"
    if addr.is_multicast:
        return "组播地址"
    if addr.is_private:
        return "私有地址"
    if addr.is_reserved:
        return "保留地址"
    return ""


def run(timeout: float = 6.0,
        progress: Optional[ProgressFn] = None) -> list[dict]:
    """体检本机 hosts。返回逐条结果。"""
    progress = progress or (lambda *a: None)

    entries = hostsmod.parse_entries()
    if not entries:
        return []

    # 按域名聚合
    by_host: dict[str, list[dict]] = {}
    for entry in entries:
        by_host.setdefault(entry["host"], []).append(entry)

    hosts_list = sorted(by_host)

    # 绕过 hosts 直接问 DNS，拿到"这个域名本来该解析成什么"
    progress("DNS 对照", "正在绕过 hosts 查询真实解析 ...", 0, len(hosts_list))
    dns_map: dict[str, list[str]] = {}
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(dnsmod.query_server, "114.114.114.114", "114",
                               host, timeout): host for host in hosts_list}
        done = 0
        for future, host in futures.items():
            done += 1
            try:
                result = future.result(timeout=timeout * 2)
                dns_map[host] = result.all_ips
            except Exception:                          # noqa: BLE001
                dns_map[host] = []
            progress("DNS 对照", "解析 %d/%d：%s" % (done, len(hosts_list), host),
                     done, len(hosts_list))

    # 逐条探测
    jobs: list[tuple[str, str]] = [(e["ip"], e["host"]) for e in entries]
    total = len(jobs)
    progress("逐条探测", "共 %d 条映射 ..." % total, 0, total)

    def probe_one(job: tuple[str, str]) -> dict:
        ip, host = job
        bogus = classify_ip(ip)
        if bogus and bogus.startswith(("屏蔽", "回环", "非法")):
            return {"alive": False, "tcp": TcpStatus.UNREACHABLE,
                    "tls": TlsStatus.ERROR, "cert_match": None,
                    "http": None, "note": bogus}
        tcp_status, _ms = probemod.tcp_probe(ip, 443, timeout)
        if tcp_status is not TcpStatus.OK:
            return {"alive": False, "tcp": tcp_status, "tls": None,
                    "cert_match": None, "http": None, "note": bogus}
        tls = probemod.tls_probe(ip, host, 443,
                                 min(timeout, probemod.TLS_TIMEOUT_CAP))
        http = None
        if tls.handshake_ok and tls.cert_match:
            http = probemod.http_probe(ip, host, timeout=timeout)
        return {"alive": True, "tcp": tcp_status, "tls": tls.status,
                "cert_match": tls.cert_match, "http": http, "note": bogus,
                "tls_detail": tls.detail}

    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=12) as pool:
        futures = {pool.submit(probe_one, job): job for job in jobs}
        done = 0
        for future, (ip, host) in futures.items():
            done += 1
            try:
                data = future.result(timeout=timeout * 4)
            except Exception as exc:                   # noqa: BLE001
                data = {"alive": False, "tcp": TcpStatus.UNREACHABLE,
                        "tls": None, "cert_match": None, "http": None,
                        "note": "探测异常：%s" % str(exc)[:40]}
            results.append({"host": host, "ip": ip, "dns": dns_map.get(host, []),
                            **data})
            progress("逐条探测", "探测：%s" % host,
                     done, total)

    # 补齐行号与重复标记
    seen: dict[str, int] = {}
    for entry, row in zip(entries, results, strict=True):
        row["line"] = entry["line"]
        key = "%s|%s" % (row["host"], row["ip"])
        seen[key] = seen.get(key, 0) + 1
        row["duplicate"] = seen[key] > 1
        row["in_dns"] = row["ip"] in row["dns"]

    results.sort(key=lambda r: (r["host"], r["line"]))
    return results


def summarize(rows: list[dict]) -> dict:
    if not rows:
        return {"total": 0, "alive": 0, "dead": 0, "mismatch": 0,
                "blocked": 0, "duplicate": 0, "bogus": 0}
    return {
        "total": len(rows),
        "alive": sum(1 for r in rows if r["alive"] and r["http"]
                     and r["http"].status is HttpStatus.OK),
        "dead": sum(1 for r in rows if not r["alive"]),
        "mismatch": sum(1 for r in rows if r["cert_match"] is False),
        "blocked": sum(1 for r in rows if r["tls"] is TlsStatus.BLOCKED),
        "duplicate": sum(1 for r in rows if r["duplicate"]),
        "bogus": sum(1 for r in rows if r.get("note")),
    }


def render(rows: list[dict]) -> str:
    lines: list[str] = []
    add = lines.append

    if not rows:
        add("hosts 文件里没有任何映射条目。")
        return "\n".join(lines)

    hosts_count = len({r["host"] for r in rows})
    ips_count = len({r["ip"] for r in rows})
    add("hosts 共 %d 条映射 / %d 个域名 / %d 个唯一 IP" % (len(rows), hosts_count, ips_count))
    add("")
    add("%-6s %-30s %-17s %-9s %-13s %-6s %-6s %s"
        % ("行", "域名", "IP", "状态", "TLS", "证书", "HTTP", "备注"))
    add("-" * 118)

    for row in rows:
        if row.get("note"):
            state, tls_text, http_text = "跳过", "-", "-"
        elif not row["alive"]:
            state, tls_text, http_text = "不可达", "-", "-"
        else:
            state = "可用" if (row["http"] and row["http"].status is HttpStatus.OK) else "可达"
            tls_text = {
                TlsStatus.OK: "成功",
                TlsStatus.CHAIN_UNTRUSTED: "链不可信",
                TlsStatus.CERT_MISMATCH: "证书不匹配",
                TlsStatus.BLOCKED: "被切断",
            }.get(row["tls"], "-")
            http_text = "-"
            if row["http"]:
                if row["http"].code:
                    http_text = str(row["http"].code)
                else:
                    http_text = {
                        HttpStatus.NO_RESPONSE: "无响应",
                        HttpStatus.MALFORMED: "响应异常",
                    }.get(row["http"].status, "-")

        notes: list[str] = []
        if row.get("note"):
            notes.append(row["note"])
        if row["cert_match"] is False:
            notes.append("证书不属于该域名")
        if row["duplicate"]:
            notes.append("重复")
        if row["alive"] and row["dns"] and not row["in_dns"]:
            notes.append("不在 DNS 结果中")
        if row["alive"] and row["dns"] and row["in_dns"]:
            notes.append("与 DNS 一致")

        add("%-6d %-30s %-17s %-9s %-13s %-6s %-6s %s" % (
            row["line"], row["host"][:30], row["ip"], state, tls_text,
            ("是" if row["cert_match"] else ("否" if row["cert_match"] is False else "-")),
            http_text, "、".join(notes)))

    stats = summarize(rows)
    add("")
    add("汇总：可用 %d / 不可达 %d / 证书不匹配 %d / 被切断 %d / 重复 %d / 异常地址 %d / 共 %d"
        % (stats["alive"], stats["dead"], stats["mismatch"], stats["blocked"],
           stats["duplicate"], stats["bogus"], stats["total"]))
    return "\n".join(lines)
