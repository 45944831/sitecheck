# -*- coding: utf-8 -*-
"""证书备用域名：过滤规则、可用性探测与报告呈现。全部不打网络。"""
from __future__ import annotations

from sitecheck import altdomains as alt
from sitecheck import render
from sitecheck.models import AltDomain, TlsResult, TlsStatus

from .conftest import http_ok, probe, report, tls_ok

# 实测样本：www.baidu.com 的证书挂了 53 条 SAN，含大量跨品牌域名
BAIDU_SAN = [
    "baidu.com", "click.hm.baidu.com", "baifubao.com", "www.baidu.cn",
    "www.baidu.com.cn", "mct.y.nuomi.com", "apollo.auto", "dwz.cn",
    "update.pan.baidu.com", "wn.pos.baidu.com", "cm.pos.baidu.com",
    "log.hm.baidu.com", "*.baidu.com", "baidu.com.cn",
]


def test_extract_github_san_is_clean():
    got = alt.extract_alt_domains("github.com", ["github.com", "www.github.com"])
    assert got == ["www.github.com"]


def test_extract_filters_cross_brand_san():
    """共享证书上的陌生品牌绝不能当备用地址推荐。"""
    got = alt.extract_alt_domains("www.baidu.com", BAIDU_SAN)
    assert "baidu.com" in got
    assert "baifubao.com" not in got
    assert "apollo.auto" not in got
    assert "dwz.cn" not in got
    assert "mct.y.nuomi.com" not in got
    assert "www.baidu.cn" not in got      # 不同注册域，保守排除
    assert not any("*" in d for d in got)


def test_extract_drops_self_wildcard_and_ip():
    got = alt.extract_alt_domains(
        "example.com",
        ["example.com", "EXAMPLE.COM.", "*.example.com", "1.2.3.4",
         "2001:db8::1", "a.example.com", "b.example.com"],
    )
    assert got == ["a.example.com", "b.example.com"]


def test_extract_hosting_suffix_not_treated_as_same_site():
    """foo.github.io 与 bar.github.io 是不同站点。"""
    got = alt.extract_alt_domains(
        "foo.github.io", ["foo.github.io", "bar.github.io", "www.foo.github.io"])
    assert "bar.github.io" not in got
    assert "www.foo.github.io" in got


def test_extract_limits_count():
    san = ["s%d.example.com" % i for i in range(10)]
    assert len(alt.extract_alt_domains("example.com", san)) == alt.MAX_ALT_DOMAINS


def test_probe_alt_domain_ok(monkeypatch):
    monkeypatch.setattr(alt.dnsmod, "system_resolve", lambda host: ["9.9.9.9"])
    monkeypatch.setattr(alt.probemod, "tls_probe",
                        lambda ip, host, timeout: tls_ok(cn=host))
    monkeypatch.setattr(alt.probemod, "http_probe",
                        lambda ip, host, timeout: http_ok())
    got = alt.probe_alt_domain("www.example.com")
    assert got.usable is True
    assert got.ip == "9.9.9.9"
    assert "200" in got.detail


def test_probe_alt_domain_tls_blocked(monkeypatch):
    monkeypatch.setattr(alt.dnsmod, "system_resolve", lambda host: ["9.9.9.9"])
    blocked = TlsResult(status=TlsStatus.BLOCKED, detail="连接被重置（RST）")
    monkeypatch.setattr(alt.probemod, "tls_probe",
                        lambda ip, host, timeout: blocked)
    got = alt.probe_alt_domain("www.example.com")
    assert got.usable is False
    assert "RST" in got.detail


def test_probe_alt_domain_unresolvable(monkeypatch):
    monkeypatch.setattr(alt.dnsmod, "system_resolve", lambda host: [])
    got = alt.probe_alt_domain("www.example.com")
    assert got.usable is None
    assert got.status_text == "无法判定"


def test_probe_alt_domain_cert_mismatch(monkeypatch):
    monkeypatch.setattr(alt.dnsmod, "system_resolve", lambda host: ["9.9.9.9"])
    mismatch = TlsResult(status=TlsStatus.CERT_MISMATCH, cert_match=False)
    monkeypatch.setattr(alt.probemod, "tls_probe",
                        lambda ip, host, timeout: mismatch)
    got = alt.probe_alt_domain("www.example.com")
    assert got.usable is False
    assert "证书不匹配" in got.detail


def test_probe_alt_domains_keeps_original_order(monkeypatch):
    def fake_resolve(host):
        return ["1.1.1.1"]
    def fake_tls(ip, host, timeout):
        return tls_ok(cn=host)
    def fake_http(ip, host, timeout):
        return http_ok()
    monkeypatch.setattr(alt.dnsmod, "system_resolve", fake_resolve)
    monkeypatch.setattr(alt.probemod, "tls_probe", fake_tls)
    monkeypatch.setattr(alt.probemod, "http_probe", fake_http)
    got = alt.probe_alt_domains(
        "example.com", ["a.example.com", "b.example.com", "c.example.com"])
    assert [a.domain for a in got] == [
        "a.example.com", "b.example.com", "c.example.com"]


def test_render_alt_domains_markdown_and_html():
    rep = report(probes=[probe("1.2.3.4", tls=tls_ok(), http=http_ok())])
    rep.alt_domains = [
        AltDomain("www.example.com", True, "1.2.3.4", "HTTPS 正常，HTTP 200"),
        AltDomain("m.example.com", False, "5.6.7.8", "TLS 握手失败"),
    ]
    md = render.render_markdown(rep)
    assert "## 证书备用域名" in md
    assert "www.example.com" in md
    assert "可用的备用地址：www.example.com" in md
    html = render.render_html(rep)
    assert "证书备用域名" in html
    assert "www.example.com" in html
    assert "无法判定" not in html


def test_render_no_alt_domains_says_nothing():
    rep = report(probes=[probe("1.2.3.4", tls=tls_ok(), http=http_ok())])
    assert "证书备用域名" not in render.render_markdown(rep)
    assert "证书备用域名" not in render.render_html(rep)
