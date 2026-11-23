# -*- coding: utf-8 -*-
"""链路抖动降级、hosts 现状建议、证据强度文案。全部不打网络。"""
from __future__ import annotations

from sitecheck import orchestrator, render, verdict
from sitecheck.models import AltDomain, HttpResult, HttpStatus, Layer

from .conftest import http_silent, probe, report, tls_blocked, tls_ok


def test_http_no_response_confidence_mentions_certificate():
    """HTTP_NO_RESPONSE 已做证书匹配，不能再写「未做证书级交叉验证」。"""
    rep = report(probes=[probe("9.9.9.9", tls=tls_ok(), http=http_silent())])
    v = verdict.judge(rep)
    assert v.layer is Layer.HTTP_NO_RESPONSE
    assert v.confidence == "strong"
    assert "未做证书级交叉验证" not in v.confidence_note
    assert "证书" in v.confidence_note


def test_hosts_advice_with_bad_entries_says_clean_first():
    """hosts 有失效条目时，必须提示先清理，不能只说「不要改 hosts」。"""
    rep = report(
        hosts=[(25, "20.27.177.113"), (26, "140.82.121.3")],
        probes=[
            probe("20.27.177.113", tls=tls_blocked()),
            probe("9.9.9.9", tls=tls_ok(), http=http_silent()),
        ],
    )
    v = verdict.judge(rep)
    assert v.layer is Layer.HTTP_NO_RESPONSE
    assert "先清理" in v.hosts_advice
    assert "20.27.177.113" in v.hosts_advice
    assert "不要改 hosts" not in v.hosts_advice
    assert "清理" in v.fix_hint
    assert "hosts --restore" in v.cli_hint


def test_hosts_advice_without_entries_keeps_original():
    rep = report(probes=[probe("9.9.9.9", tls=tls_ok(), http=http_silent())])
    v = verdict.judge(rep)
    assert "不要改 hosts" in v.hosts_advice
    assert "hosts --restore" not in v.cli_hint


def test_flakiness_detected_when_same_ip_conflicts():
    rep = report(
        probes=[probe("20.6.7.17", tls=tls_ok(), http=http_silent())],
        alt_domains=[AltDomain(
            "www.example.com", False, "20.6.7.17",
            "TLS 握手失败：超时（单次采样，可能是暂时抖动）")],
    )
    evidence = orchestrator._detect_flakiness(rep)
    assert len(evidence) == 1
    assert "20.6.7.17" in evidence[0]
    assert "相反" not in evidence[0] or "主探测" in evidence[0]


def test_flakiness_ignores_different_ip():
    """不同 IP 的正常差异不能误报成抖动。"""
    rep = report(
        probes=[probe("20.6.7.17", tls=tls_ok(), http=http_silent())],
        alt_domains=[AltDomain("www.example.com", False, "1.2.3.4",
                               "TLS 握手失败：超时")],
    )
    assert orchestrator._detect_flakiness(rep) == []


def test_flakiness_ignores_indeterminate_alt():
    """备用域名「无法判定」不是反证。"""
    rep = report(
        probes=[probe("20.6.7.17", tls=tls_ok(), http=http_silent())],
        alt_domains=[AltDomain("www.example.com", None, "20.6.7.17",
                               "探测超时，未得出结论")],
    )
    assert orchestrator._detect_flakiness(rep) == []


def test_flakiness_downgrades_confidence_and_headline():
    rep = report(
        probes=[probe("20.6.7.17", tls=tls_ok(), http=http_silent())],
        alt_domains=[AltDomain("www.example.com", False, "20.6.7.17",
                               "TLS 握手失败：超时（单次采样）")],
    )
    rep.flaky_evidence = orchestrator._detect_flakiness(rep)
    v = verdict.judge(rep)
    assert v.confidence == "weak"
    assert "抖动" in v.confidence_note
    assert "抖动" in v.headline
    assert "链路抖动反证" in v.evidence


def test_flakiness_rendered_in_both_formats():
    rep = report(probes=[probe("9.9.9.9", tls=tls_ok(), http=http_silent())])
    rep.flaky_evidence = ["同一 IP 9.9.9.9：主探测 TLS 成功，备用探测 TLS 超时"]
    rep.verdict = verdict.judge(rep)
    md = render.render_markdown(rep)
    assert "链路抖动警告" in md
    assert "主探测 TLS 成功" in md
    html = render.render_html(rep)
    assert "链路抖动警告" in html


def test_alt_domain_single_sample_disclaimer():
    rep = report(probes=[probe("9.9.9.9", tls=tls_ok(), http=http_silent())])
    rep.alt_domains = [AltDomain("www.example.com", False, "9.9.9.9",
                                 "TLS 握手失败：超时（单次采样，可能是暂时抖动）")]
    rep.verdict = verdict.judge(rep)
    md = render.render_markdown(rep)
    assert "每个域名只探测一次" in md
    assert "单次采样" in md


def _http_tls_timeout(detail: str = "TLS 建立失败：handshake operation timed out"):
    return HttpResult(status=HttpStatus.NO_RESPONSE, detail=detail)


def test_flakiness_detected_from_http_detail_without_alt_domains():
    """备用域名全部可用、只有 http.detail 反证时，也要能发现抖动。

    这就是 14:53 报告的场景：主探测 TLS 成功，HTTP 阶段重新建连却握手超时，
    而备用域名 www.github.com 可用 —— 旧逻辑只看 alt_domains 会漏报。
    """
    rep = report(
        probes=[probe("140.82.121.3", tls=tls_ok(), http=_http_tls_timeout())],
        alt_domains=[],
    )
    evidence = orchestrator._detect_flakiness(rep)
    assert len(evidence) == 1
    assert "140.82.121.3" in evidence[0]
    assert "HTTP 阶段重新建连" in evidence[0]


def test_flakiness_http_detail_does_not_flag_plain_timeout():
    """TLS 成功之后的「等待响应超时」不冲突，不能误报成抖动。"""
    rep = report(probes=[probe(
        "9.9.9.9", tls=tls_ok(),
        http=_http_tls_timeout("等待响应超时：the read operation timed out"))])
    assert orchestrator._detect_flakiness(rep) == []


def test_flakiness_http_detail_requires_main_tls_success():
    """主探测 TLS 本身失败时，HTTP 阶段同样失败不算反证。"""
    rep = report(probes=[probe(
        "1.2.3.4", tls=tls_blocked(), http=_http_tls_timeout())])
    assert orchestrator._detect_flakiness(rep) == []


def test_flakiness_http_detail_downgrades_verdict():
    """HTTP 阶段反证注入后，整条结论应降级为 weak 并带抖动标题。"""
    rep = report(probes=[probe("9.9.9.9", tls=tls_ok(), http=_http_tls_timeout())])
    rep.flaky_evidence = orchestrator._detect_flakiness(rep)
    v = verdict.judge(rep)
    assert v.confidence == "weak"
    assert "抖动" in v.headline
    assert "链路抖动反证" in v.evidence
