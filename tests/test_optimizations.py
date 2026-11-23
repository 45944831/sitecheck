# -*- coding: utf-8 -*-
"""v2.0.4 优化项的回归测试：全部离线，不打网络。"""
from __future__ import annotations

import json

from sitecheck import cdn, render, verdict
from sitecheck.models import (
    DnsResult,
    DnsStatus,
    Layer,
    SniControl,
    TcpStatus,
    TlsStatus,
)

from .conftest import (
    dns_ok,
    http_ok,
    probe,
    tls_blocked,
    tls_ok,
)
from .conftest import report as make_report

# ---------------------------------------------------------------- fix_hint 分流

def test_fix_hint_has_no_cli_command():
    """报告/GUI 用的 fix_hint 绝不能出现 CLI 参数。"""
    for p in (probe("9.9.9.9", tls=tls_ok(), http=http_ok()),
              probe("1.2.3.4", tls=tls_blocked())):
        rep = make_report(probes=[p])
        v = verdict.judge(rep)
        assert "--" not in v.fix_hint


def test_blocked_layer_has_no_misleading_ip_hint():
    """SNI/TCP 阻断已证实换 IP 无效，不能再给 --ip 命令误导用户。"""
    rep = make_report(probes=[probe("1.2.3.4", tls=tls_blocked())])
    v = verdict.judge(rep)
    assert v.cli_hint == ""


def test_rendered_report_has_no_cli_command():
    """三种渲染结果里都不该出现 --report / --json 这类命令行参数。"""
    rep = make_report(probes=[probe("9.9.9.9", tls=tls_ok(), http=http_ok())])
    rep.verdict = verdict.judge(rep)
    for text in (render.render_markdown(rep), render.render_html(rep),
                 render.render_json(rep)):
        assert "--report" not in text
        assert "--json" not in text


# ---------------------------------------------------------------- tips 按层过滤

def test_failed_layer_drops_optimization_tips():
    """SNI 阻断时不再出现「DNS 延迟」这类会误导的优化建议。"""
    rep = make_report(
        dns=[dns_ok(["1.2.3.4"], ms=29), dns_ok(["1.2.3.4"], server="8.8.8.8",
                                                name="Google", ms=1500)],
        probes=[probe("1.2.3.4", tls=tls_blocked())])
    rep.verdict = verdict.judge(rep)
    assert rep.verdict.layer is Layer.TLS_BLOCKED
    tips = verdict.build_tips(rep, None, Layer.TLS_BLOCKED)
    assert not any("DNS 延迟" in t for t in tips)
    assert not any("改用最快" in t for t in tips)


def test_success_layer_keeps_optimization_tips():
    rep = make_report(
        dns=[dns_ok(["1.2.3.4"], ms=29)],
        probes=[probe("1.2.3.4", tls=tls_ok(), http=http_ok())])
    tips = verdict.build_tips(rep, rep.probes[0], Layer.SUCCESS)
    assert any("DNS 延迟" in t for t in tips)


# ---------------------------------------------------------------- 证据强度

def test_confidence_strong_for_cert_match():
    rep = make_report(probes=[probe("9.9.9.9", tls=tls_ok(), http=http_ok())])
    v = verdict.judge(rep)
    assert v.confidence == "strong"
    assert "证书" in render.render_markdown(make_report(
        probes=rep.probes, verdict=v)) or "证据强度" in render.render_markdown(
        make_report(probes=rep.probes, verdict=v))


def test_confidence_weak_for_inconclusive():
    rep = make_report(incomplete="整体超时", control=[], probes=[])
    v = verdict.judge(rep)
    assert v.confidence == "weak"
    assert "建议复测" in v.confidence_note


def test_confidence_strong_when_sni_proves_domain_block():
    rep = make_report(probes=[probe("1.2.3.4", tls=tls_blocked())])
    rep.sni_control = SniControl(ip="1.2.3.4", sni="www.baidu.com",
                                 handshake_ok=True, status=TlsStatus.CERT_MISMATCH)
    v = verdict.judge(rep)
    assert v.layer is Layer.TLS_BLOCKED
    assert v.confidence == "strong"
    assert "SNI" in v.evidence


def test_confidence_moderate_when_sni_shows_ip_block():
    rep = make_report(probes=[probe("1.2.3.4", tls=tls_blocked())])
    rep.sni_control = SniControl(ip="1.2.3.4", sni="www.baidu.com",
                                 handshake_ok=False, status=TlsStatus.BLOCKED,
                                 detail="RST")
    v = verdict.judge(rep)
    assert v.confidence == "moderate"
    assert "IP / 路径" in v.evidence


# ---------------------------------------------------------------- 真实 IP 拆分

def test_cert_unverified_shows_resolution_consistency():
    """SNI 阻断时报告要说清 DNS 正常，而不是笼统写「真实 IP 未能确认」。"""
    rep = make_report(
        dns=[dns_ok(["1.2.3.4"], server="223.5.5.5"),
             dns_ok(["1.2.3.4"], server="8.8.8.8", name="Google")],
        doh=[dns_ok(["1.2.3.4"], name="DoH 腾讯")],
        probes=[probe("1.2.3.4", tls=tls_blocked())])
    rep.verdict = verdict.judge(rep)
    md = render.render_markdown(rep)
    assert "证书归属：未能验证" in md
    assert "解析一致性" in md
    assert "完全一致" in md
    assert "真实 IP：未能确认" not in md
    html = render.render_html(rep)
    assert "证书归属：未能验证" in html


# ---------------------------------------------------------------- DoH 错误原因

def test_doh_error_shows_reason():
    err = DnsResult(server="https://dns.alidns.com/dns-query", name="DoH 阿里",
                    status=DnsStatus.ERROR,
                    error="HTTP Error 400: Bad Request", transport="doh")
    rep = make_report(doh=[err], probes=[])
    md = render.render_markdown(rep)
    assert "错误（HTTP Error 400" in md
    assert "Bad Request" in md


# ---------------------------------------------------------------- CDN 归属

def test_cdn_detection():
    assert cdn.cdn_name("104.21.49.126") == "Cloudflare"
    assert cdn.cdn_name("172.67.163.1") == "Cloudflare"
    assert cdn.cdn_name("185.199.108.1") == "GitHub Pages"
    assert cdn.cdn_name("1.2.3.4") == ""
    assert "Anycast" in cdn.cdn_note("104.21.49.126")


def test_cdn_note_in_tls_blocked_advice():
    rep = make_report(probes=[probe("104.21.49.126", tls=tls_blocked())])
    v = verdict.judge(rep)
    assert v.layer is Layer.TLS_BLOCKED
    assert "Cloudflare" in v.hosts_advice
    assert "Anycast" in v.hosts_advice


# ---------------------------------------------------------------- IPv6 归因

def test_ipv6_no_outbound_tip():
    rep = make_report(
        ipv6_outbound=False,
        probes=[probe("2606:4700::1", tcp=TcpStatus.UNREACHABLE, family=6)])
    tips = verdict.build_tips(rep, None, Layer.TLS_BLOCKED)
    assert any("IPv6" in t and "环境限制" in t for t in tips)
    md = render.render_markdown(rep)
    assert "无出口" in md


def test_ipv6_outbound_shown_in_html():
    rep = make_report(ipv6_outbound=True)
    assert "IPv6 出口" in render.render_html(rep)
    assert "有出口" in render.render_html(rep)


# ---------------------------------------------------------------- SNI 对照展示

def test_sni_control_shown_in_renders():
    rep = make_report(probes=[probe("1.2.3.4", tls=tls_blocked())])
    rep.sni_control = SniControl(ip="1.2.3.4", sni="www.baidu.com",
                                 handshake_ok=True, status=TlsStatus.CERT_MISMATCH)
    rep.verdict = verdict.judge(rep)
    for text in (render.render_markdown(rep), render.render_html(rep)):
        assert "SNI 对照实验" in text
        assert "已证实" in text


# ---------------------------------------------------------------- schema

def test_schema_version_bumped():
    rep = make_report()
    assert json.loads(render.render_json(rep))["schema_version"] == 5
