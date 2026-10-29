# -*- coding: utf-8 -*-
"""DNS 基准测试：延迟 / 可用性 / 防污染 / 解析一致性。

从 v1.0 的 dns_bench.py 合并而来，修掉了硬编码绝对路径
（原代码写死 E:\\2026-10-01-22-18-18\\dns-bench.json，别人机器上直接崩）。
"""
from __future__ import annotations

import random
import statistics
from concurrent.futures import ThreadPoolExecutor

from .dns import QTYPE_A, QTYPE_AAAA, udp_query

SERVERS: list[tuple[str, str]] = [
    ("114.114.114.114", "114 DNS"),
    ("114.114.115.115", "114 DNS 备"),
    ("223.5.5.5", "阿里 AliDNS"),
    ("223.6.6.6", "阿里 AliDNS 备"),
    ("119.29.29.29", "腾讯 DNSPod"),
    ("119.28.28.28", "腾讯 DNSPod 备"),
    ("180.76.76.76", "百度 DNS"),
    ("101.226.4.6", "DNS 派 电信"),
    ("123.125.81.6", "DNS 派 联通"),
    ("117.50.10.10", "OneDNS"),
    ("8.8.8.8", "Google"),
    ("1.1.1.1", "Cloudflare"),
    ("9.9.9.9", "Quad9"),
    ("208.67.222.222", "OpenDNS"),
]

COMMON_DOMAINS = [
    "www.baidu.com", "www.taobao.com", "www.qq.com", "www.jd.com",
    "www.zhihu.com", "www.bilibili.com", "github.com", "www.microsoft.com",
]


def _bench_server(server: tuple[str, str], timeout: float) -> dict:
    ip, name = server
    latencies: list[float] = []
    ok = 0
    v6_ok = 0

    for domain in COMMON_DOMAINS:
        ips, _ipv6, rcode, _tc, ms = udp_query(domain, ip, QTYPE_A, timeout)
        if ips:
            ok += 1
            latencies.append(ms)
        elif rcode == 0:
            ok += 1                          # 有响应但无 A（极少数情况）也算可用
            latencies.append(ms)

    for domain in COMMON_DOMAINS[:3]:        # AAAA 抽样，避免拖慢整体
        _ips, ipv6, rcode, _tc, _ms = udp_query(domain, ip, QTYPE_AAAA, timeout)
        if rcode == 0 and ipv6:
            v6_ok += 1

    # 防污染：随机不存在的域名，干净 DNS 应返回 NXDOMAIN(3)
    poison: list[tuple[str, int, list[str]]] = []
    for _ in range(3):
        fake = "xq%d%dzk.com" % (random.randint(100000, 999999),
                                 random.randint(10, 99))
        ips, _ipv6, rcode, _tc, _ms = udp_query(fake, ip, QTYPE_A, timeout)
        poison.append((fake, rcode, ips))

    return {
        "ip": ip, "name": name, "ok": ok, "total": len(COMMON_DOMAINS),
        "latencies": latencies, "v6_ok": v6_ok, "v6_total": 3, "poison": poison,
    }


def _verdict_of(row: dict) -> str:
    if not row["latencies"]:
        return "不可达"
    nx = sum(1 for _f, rcode, _ips in row["poison"] if rcode == 3)
    fake_ip = sum(1 for _f, _rcode, ips in row["poison"] if ips)
    timeout_n = sum(1 for _f, rcode, _ips in row["poison"] if rcode == -1)
    if fake_ip:
        return "!! 污染（不存在域名返回了伪造 IP）"
    if nx == 3:
        return "干净 (3/3 NXDOMAIN)"
    if timeout_n:
        return "有丢包 (%d/3 超时，非污染)" % timeout_n
    return "存疑 (NX %d/3)" % nx


def run(timeout: float = 3.0, servers: list[tuple[str, str]] | None = None) -> list[dict]:
    servers = servers or SERVERS
    with ThreadPoolExecutor(max_workers=12) as pool:
        raw = list(pool.map(lambda s: _bench_server(s, timeout), servers))

    rows: list[dict] = []
    for item in raw:
        lat = item["latencies"]
        row = dict(item)
        row["avg"] = statistics.mean(lat) if lat else None
        row["median"] = statistics.median(lat) if lat else None
        row["min"] = min(lat) if lat else None
        row["verdict"] = _verdict_of(row)
        rows.append(row)

    rows.sort(key=lambda r: (r["avg"] is None, r["avg"] or 0))
    return rows


def render(rows: list[dict]) -> str:
    lines: list[str] = []
    add = lines.append
    add("测试 %d 个 DNS，每个查 %d 个常用域名 + 3 次随机域名防污染检测"
        % (len(rows), len(COMMON_DOMAINS)))
    add("")
    add("%-16s %-16s %-8s %-10s %-10s %-8s %s"
        % ("IP", "名称", "成功", "平均延迟", "中位延迟", "IPv6", "防污染"))
    add("-" * 104)
    for row in rows:
        status = "%d/%d" % (row["ok"], row["total"])
        avg = "%.1f ms" % row["avg"] if row["avg"] is not None else "-"
        med = "%.1f ms" % row["median"] if row["median"] is not None else "-"
        v6 = "%d/%d" % (row["v6_ok"], row["v6_total"])
        add("%-16s %-16s %-8s %-10s %-10s %-8s %s"
            % (row["ip"], row["name"], status, avg, med, v6, row["verdict"]))

    add("")
    add("=== 防污染细节 ===")
    for row in rows:
        if not row["latencies"]:
            continue
        detail = "; ".join(
            "%s→rcode=%s%s" % (fake[:16], rcode,
                               (" " + ",".join(ips)) if ips else "")
            for fake, rcode, ips in row["poison"])
        add("  %-16s %-16s %s" % (row["ip"], row["name"], detail))
    return "\n".join(lines)


def to_json(rows: list[dict]) -> str:
    import json
    clean = []
    for row in rows:
        item = {k: v for k, v in row.items() if k != "poison"}
        item["poison"] = [
            {"domain": fake, "rcode": rcode, "ips": ips}
            for fake, rcode, ips in row["poison"]
        ]
        clean.append(item)
    return json.dumps(clean, ensure_ascii=False, indent=2)
