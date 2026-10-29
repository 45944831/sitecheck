# -*- coding: utf-8 -*-
"""测试公共工具：构造 Report / ProbeResult，不打任何网络。"""
from __future__ import annotations

import pytest

from sitecheck.models import (
    ControlResult,
    DnsResult,
    DnsStatus,
    HttpResult,
    HttpStatus,
    ProbeResult,
    ProxyInfo,
    ProxyKind,
    Report,
    TcpStatus,
    TlsResult,
    TlsStatus,
)


def dns_ok(ips: list[str] | None = None, ipv6: list[str] | None = None,
           server: str = "223.5.5.5", name: str = "阿里",
           ms: float = 10.0) -> DnsResult:
    return DnsResult(server=server, name=name, status=DnsStatus.OK,
                     ips=list(ips or []), ipv6=list(ipv6 or []), ms=ms, rcode=0)


def dns_nx(server: str = "223.5.5.5", name: str = "阿里") -> DnsResult:
    return DnsResult(server=server, name=name, status=DnsStatus.NXDOMAIN, rcode=3)


def dns_empty(server: str = "223.5.5.5", name: str = "阿里") -> DnsResult:
    return DnsResult(server=server, name=name, status=DnsStatus.EMPTY, rcode=0)


def tls_ok(cert_match: bool = True, cn: str = "example.com",
           alpn: str = "h2", version: str = "TLSv1.3",
           chain_trusted: bool = True, days_left: int = 90) -> TlsResult:
    return TlsResult(status=TlsStatus.OK, cn=cn, san=[cn], cert_match=cert_match,
                     version=version, alpn=alpn, chain_trusted=chain_trusted,
                     days_left=days_left)


def tls_blocked() -> TlsResult:
    return TlsResult(status=TlsStatus.BLOCKED, detail="握手过程中连接被重置（RST）")


def tls_mismatch(cn: str = "other.example.net") -> TlsResult:
    return TlsResult(status=TlsStatus.CERT_MISMATCH, cn=cn, san=[cn],
                     cert_match=False)


def http_ok(code: int = 200, location: str = "") -> HttpResult:
    return HttpResult(status=HttpStatus.OK, code=code, location=location,
                      bytes_read=1024, ttfb_ms=120.0, total_ms=300.0)


def http_reject(code: int = 403) -> HttpResult:
    return HttpResult(status=HttpStatus.REJECT, code=code, bytes_read=512)


def http_silent() -> HttpResult:
    return HttpResult(status=HttpStatus.NO_RESPONSE, detail="连接建立后未收到任何字节")


def http_malformed() -> HttpResult:
    return HttpResult(status=HttpStatus.MALFORMED, detail="响应首行不是合法 HTTP 状态行")


def probe(ip: str, tcp: TcpStatus = TcpStatus.OK,
          tls: TlsResult | None = None, http: HttpResult | None = None,
          source: str = "解析", tcp_ms: float = 50.0,
          http_proxy: HttpResult | None = None, family: int = 4) -> ProbeResult:
    return ProbeResult(ip=ip, source=source, family=family, tcp=tcp,
                       tcp_ms=tcp_ms, tls=tls, http=http, http_proxy=http_proxy)


def control(ok: bool = True, host: str = "www.baidu.com",
            ip: str = "1.2.3.4") -> ControlResult:
    return ControlResult(host=host, ip=ip, ok=ok)


def proxy(url: str = "http://127.0.0.1:8080") -> ProxyInfo:
    return ProxyInfo(kind=ProxyKind.ENV, url=url, source="环境变量 https_proxy")


def report(domain: str = "example.com", **kwargs) -> Report:
    defaults = dict(domain=domain, time="2026-10-29 12:00", version="2.0.0",
                    dns=[dns_ok(["1.2.3.4"])], doh=[dns_ok(["1.2.3.4"], name="DoH 阿里")],
                    control=[control(True)], probes=[], hosts=[], proxy=ProxyInfo())
    defaults.update(kwargs)
    return Report(**defaults)


@pytest.fixture
def clean_report():
    return report()
