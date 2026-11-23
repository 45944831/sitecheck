# -*- coding: utf-8 -*-
"""CDN / Anycast 归属识别：给「换 IP 无效」这类建议提供证据。

纯计算模块，只依赖标准库 ipaddress。识别结果只用于报告里的解释性提示，
不参与判定 —— 判定仍然只认证书匹配，CDN 归属不能当真伪依据。
"""
from __future__ import annotations

import ipaddress

# 常见 CDN 的官方 IP 段。Anycast 意味着这些 IP 全球复用，
# 换一个同段 IP 通常还是同一个边缘节点，改 hosts 意义不大。
_CDN_NETS: list[tuple[str, str]] = [
    ("Cloudflare", "104.16.0.0/12"),
    ("Cloudflare", "172.64.0.0/13"),
    ("Cloudflare", "173.245.48.0/20"),
    ("Cloudflare", "188.114.96.0/20"),
    ("Cloudflare", "190.93.240.0/20"),
    ("Cloudflare", "197.234.240.0/22"),
    ("Cloudflare", "198.41.128.0/17"),
    ("Cloudflare", "162.158.0.0/15"),
    ("Cloudflare", "2606:4700::/32"),
    ("Cloudflare", "2400:cb00::/32"),
    ("GitHub Pages", "185.199.108.0/22"),
    ("GitHub Pages", "2606:50c0::/32"),
    ("GitHub", "140.82.112.0/20"),
    ("GitHub", "192.30.252.0/22"),
    ("Fastly", "151.101.0.0/16"),
    ("Fastly", "199.232.0.0/16"),
    ("Fastly", "2a04:4e42::/32"),
]

_NETS = [(name, ipaddress.ip_network(cidr)) for name, cidr in _CDN_NETS]


def cdn_name(ip: str) -> str:
    """返回 CDN 名称；不在已知段内返回空串。"""
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return ""
    for name, net in _NETS:
        if addr in net:
            return name
    return ""


def cdn_note(ip: str) -> str:
    """给报告用的一句话提示；非 CDN IP 返回空串。"""
    name = cdn_name(ip)
    if not name:
        return ""
    return ("%s 属于 %s 的 Anycast 段，同一段内换 IP 通常仍命中同一个边缘节点，"
            "改 hosts 意义不大" % (ip, name))
