# -*- coding: utf-8 -*-
"""GUI 精简渲染的回归测试：段落全留、硬证据不丢、导出版不受影响。"""
from __future__ import annotations

from sitecheck import render, verdict
from sitecheck.models import SniControl, TlsStatus

from .conftest import probe, tls_blocked
from .conftest import report as make_report


def _tls_blocked_report(with_sni_control: bool = False):
    rep = make_report(
        probes=[probe("104.21.49.126", tls=tls_blocked()),
                probe("172.67.163.1", tls=tls_blocked())])
    if with_sni_control:
        rep.sni_control = SniControl(
            ip="104.21.49.126", sni="www.baidu.com",
            handshake_ok=True, status=TlsStatus.OK,
            detail="换用 www.baidu.com 作 SNI 后握手成功，"
                   "证明阻断与目标域名绑定（域名级 SNI 阻断，已证实）。")
    rep.verdict = verdict.judge(rep)
    return rep


def test_compact_keeps_all_sections():
    """精简版必须保留全段落，只是文案短——不能靠删区块换清爽。"""
    html = render.render_html(_tls_blocked_report(), compact=True)
    for label in ("阻断点", "hosts 建议", "证据强度", "下一步",
                  "证书归属", "解析一致性", "DNS 解析", "逐 IP 探测"):
        assert label in html, "精简版丢失段落：%s" % label


def test_compact_shorter_than_full():
    html_full = render.render_html(_tls_blocked_report())
    html_compact = render.render_html(_tls_blocked_report(), compact=True)
    assert len(html_compact) < len(html_full)


def test_compact_drops_english_layer_value():
    """GUI 里阻断点只给中文标签，不再附带英文枚举值（完整版仍带）。"""
    html = render.render_html(_tls_blocked_report(), compact=True)
    assert "阻断点：TLS/SNI 被切断</div>" in html
    full = render.render_html(_tls_blocked_report())
    assert "阻断点：TLS/SNI（TLS/SNI 被切断）" in full


def test_compact_confidence_drops_repeated_note():
    """证据强度只留标签——note 复述 evidence，是重复的主要来源。"""
    rep = _tls_blocked_report()
    html = render.render_html(rep, compact=True)
    note = rep.verdict.confidence_note
    if note:
        assert note not in html or len(note) < 10
    full = render.render_html(rep)
    assert note in full or not note


def test_compact_keeps_sni_control_evidence():
    """对照实验是硬证据，精简时也必须在依据里出现，不能当成废话压掉。"""
    rep = _tls_blocked_report(with_sni_control=True)
    evidence = rep.verdict.evidence
    assert "对照实验" in evidence or "换用" in evidence
    compact = render.render_html(rep, compact=True)
    assert "对照实验" in compact or "换用" in compact


def test_compact_hosts_advice_keeps_failed_ips():
    """已有 hosts 条目时，失效 IP 比长解释有用——精简版必须留。"""
    rep = make_report(
        hosts=[(25, "20.27.177.113"), (26, "140.82.121.3")],
        probes=[probe("20.27.177.113", tls=tls_blocked()),
                probe("140.82.121.3", tls=tls_blocked())])
    rep.verdict = verdict.judge(rep)
    html = render.render_html(rep, compact=True)
    assert "hosts 建议" in html
    assert "20.27.177.113" in html


def test_full_version_unchanged_by_compact_flag():
    """compact 只在界面生效；默认调用（导出/CLI）仍是完整版。"""
    rep = _tls_blocked_report()
    default = render.render_html(rep)
    explicit = render.render_html(rep, compact=False)
    assert default == explicit
