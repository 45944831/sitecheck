# -*- coding: utf-8 -*-
"""sitecheck 的数据模型。

设计约束：
    本模块不 import 任何 IO 模块（socket / ssl / urllib / pathlib），
    只定义纯数据结构。这样 verdict.py 可以完全脱离网络做单元测试。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

# ---------------------------------------------------------------- 状态枚举

class DnsStatus(str, Enum):
    OK = "ok"
    NXDOMAIN = "nxdomain"      # 域名不存在（干净 DNS 的正常回答）
    EMPTY = "empty"            # NOERROR 但无 A/AAAA 记录
    TIMEOUT = "timeout"
    ERROR = "error"


class TcpStatus(str, Enum):
    OK = "ok"
    REFUSED = "refused"
    TIMEOUT = "timeout"
    RESET = "reset"
    UNREACHABLE = "unreachable"


class TlsStatus(str, Enum):
    OK = "ok"                          # 握手成功 + 证书链可信
    CHAIN_UNTRUSTED = "chain_untrusted"  # 握手成功，但证书链不受信任（自签/私有 CA）
    CERT_MISMATCH = "cert_mismatch"    # 握手成功，证书 SAN 不匹配目标域名
    BLOCKED = "blocked"                # TCP 通但握手超时 / RST —— SNI 层特征
    ERROR = "error"


class HttpStatus(str, Enum):
    OK = "ok"                   # 2xx / 3xx
    REJECT = "reject"           # 4xx / 5xx，且拿到了合法状态行
    NO_RESPONSE = "no_response"  # 一个字节都没收到
    MALFORMED = "malformed"     # 收到数据但不是合法 HTTP 响应
    SKIPPED = "skipped"         # 前置条件不满足，未发起请求


class Layer(str, Enum):
    """阻断点。值沿用 v1.0 的命名，保证报告和历史记录可对照。"""
    SUCCESS = "SUCCESS"
    HTTP_REJECT = "HTTP_REJECT"
    PROXY_REQUIRED = "PROXY_REQUIRED"    # 直连不通，但经代理可访问
    HTTP_NO_RESPONSE = "HTTP_NO_RESPONSE"
    DNS_POISONED = "DNS 污染"
    TLS_BLOCKED = "TLS/SNI"
    TCP_BLOCKED = "TCP"
    DNS_FAIL = "DNS"
    INCONCLUSIVE = "INCONCLUSIVE"
    UNKNOWN = "未知"


class ProxyKind(str, Enum):
    NONE = "none"
    ENV = "env"
    WININET = "wininet"
    PAC = "pac"


# ---------------------------------------------------------------- 探测结果

@dataclass
class DnsResult:
    """单个 DNS 服务器（或 DoH 端点）的一次查询结果。"""
    server: str                      # "223.5.5.5" 或 "https://dns.alidns.com/dns-query"
    name: str                        # 人类可读名："阿里" / "DoH 阿里"
    status: DnsStatus
    ips: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    ms: float = 0.0
    rcode: int = -1
    transport: str = "udp"           # udp / doh
    error: str = ""

    @property
    def all_ips(self) -> list[str]:
        return list(self.ips) + list(self.ipv6)

    @property
    def ok(self) -> bool:
        return self.status is DnsStatus.OK


@dataclass
class TlsResult:
    status: TlsStatus
    cn: str = ""
    san: list[str] = field(default_factory=list)
    cert_match: Optional[bool] = None
    version: str = ""
    alpn: str = ""
    cipher: str = ""
    not_after: str = ""
    days_left: Optional[int] = None
    chain_trusted: bool = True
    chain_error: str = ""
    ms: float = 0.0
    detail: str = ""

    @property
    def handshake_ok(self) -> bool:
        """握手是否完成（无论证书链是否可信）。"""
        return self.status in (TlsStatus.OK, TlsStatus.CHAIN_UNTRUSTED,
                               TlsStatus.CERT_MISMATCH)


@dataclass
class HttpResult:
    status: HttpStatus
    code: Optional[int] = None
    location: str = ""
    title: str = ""
    bytes_read: int = 0
    ttfb_ms: float = 0.0
    total_ms: float = 0.0
    via: str = "direct"              # direct / proxy
    detail: str = ""

    @property
    def code_str(self) -> str:
        return str(self.code) if self.code else "-"

    @property
    def usable(self) -> bool:
        """是否说明 HTTP 层真的通了（拿到合法状态行）。"""
        return self.status in (HttpStatus.OK, HttpStatus.REJECT)


@dataclass
class ProbeResult:
    """单个 IP 的完整探测结果。"""
    ip: str
    source: str = "候选"             # 手动 / hosts / 解析 / 候选
    family: int = 4                  # 4 或 6
    tcp: TcpStatus = TcpStatus.UNREACHABLE
    tcp_ms: float = 0.0
    tls: Optional[TlsResult] = None
    http: Optional[HttpResult] = None
    http_proxy: Optional[HttpResult] = None   # 经代理的对照结果

    @property
    def cert_ok(self) -> bool:
        """证书确认了这个 IP 确实属于目标站。"""
        return bool(self.tls and self.tls.cert_match)

    @property
    def genuine(self) -> bool:
        """TLS 握手完成且证书匹配 —— 判定"真实 IP"的唯一依据。"""
        return bool(self.tls and self.tls.handshake_ok and self.tls.cert_match)

    @property
    def serves_http(self) -> bool:
        return bool(self.http and self.http.usable)


@dataclass
class ControlResult:
    """控制组：验证本机出网是否可信。"""
    host: str
    ip: str
    ok: bool
    detail: str = ""


@dataclass
class ProxyInfo:
    kind: ProxyKind = ProxyKind.NONE
    url: str = ""
    source: str = ""
    no_proxy: str = ""

    @property
    def present(self) -> bool:
        return self.kind is not ProxyKind.NONE and bool(self.url)

    @property
    def host_port(self) -> Optional[tuple[str, int]]:
        """把 http://127.0.0.1:9754 拆成 (host, port)，供 CONNECT 隧道使用。"""
        if not self.present:
            return None
        url = self.url
        for prefix in ("http://", "https://"):
            if url.lower().startswith(prefix):
                url = url[len(prefix):]
                break
        url = url.split("/")[0]
        if not url:
            return None
        if ":" in url:
            h, _, p = url.rpartition(":")
            try:
                return h, int(p)
            except ValueError:
                return None
        return url, 8080


@dataclass
class Verdict:
    """最终结论。每条结论必须带 evidence，渲染时展示"为什么这么判"。"""
    layer: Layer
    headline: str
    evidence: str = ""
    hosts_advice: str = ""
    hosts_write_needed: bool = False
    hosts_entry_ips: list[str] = field(default_factory=list)
    proxy_note: str = ""


@dataclass
class Report:
    """一次完整检测的全部结果。"""
    domain: str
    time: str = ""
    version: str = ""
    dns: list[DnsResult] = field(default_factory=list)
    doh: list[DnsResult] = field(default_factory=list)
    hosts: list[tuple[int, str]] = field(default_factory=list)   # [(行号, IP)]
    control: list[ControlResult] = field(default_factory=list)
    probes: list[ProbeResult] = field(default_factory=list)
    proxy: ProxyInfo = field(default_factory=ProxyInfo)
    sys_ips: list[str] = field(default_factory=list)
    real_ips: list[str] = field(default_factory=list)
    tips: list[str] = field(default_factory=list)
    verdict: Optional[Verdict] = None
    extra_ips: list[str] = field(default_factory=list)

    @property
    def genuine_probes(self) -> list[ProbeResult]:
        return [p for p in self.probes if p.genuine]

    @property
    def hosts_ips(self) -> list[str]:
        return [ip for _, ip in self.hosts]

    @property
    def control_ok(self) -> bool:
        return any(c.ok for c in self.control)

    @property
    def control_all_failed(self) -> bool:
        """控制组全部不通 —— 只有在真的探测过的情况下才算。"""
        return bool(self.control) and not any(c.ok for c in self.control)
