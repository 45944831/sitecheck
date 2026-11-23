# -*- coding: utf-8 -*-
"""fix_hint：每条结论都必须带可执行的下一步。"""
from __future__ import annotations

import json

from sitecheck import render
from sitecheck.models import Layer, TcpStatus
from sitecheck.verdict import build_fix_hint, judge

from .conftest import (
    control,
    dns_ok,
    http_ok,
    http_silent,
    probe,
    tls_blocked,
    tls_mismatch,
    tls_ok,
)
from .conftest import (
    report as make_report,
)


def test_every_judged_verdict_has_fix_hint():
    cases = [
        make_report(probes=[probe("9.9.9.9", tls=tls_ok(), http=http_ok())]),
        make_report(probes=[probe("1.2.3.4", tls=tls_ok(), http=http_ok(403))]),
        make_report(probes=[probe("1.2.3.4", tls=tls_ok(), http=http_silent())]),
        make_report(probes=[probe("1.2.3.4", tls=tls_mismatch())]),
        make_report(probes=[probe("1.2.3.4", tls=tls_blocked())]),
        make_report(probes=[probe("1.2.3.4", tcp=TcpStatus.TIMEOUT)]),
        make_report(dns=[], doh=[], control=[control(True)], probes=[]),
        make_report(control=[control(False)]),
    ]
    for case in cases:
        verdict = judge(case)
        assert verdict.fix_hint, verdict.layer.value


def test_success_with_hosts_advice_gives_concrete_command():
    report = make_report(probes=[probe("9.9.9.9", tls=tls_ok(), http=http_ok())])
    verdict = judge(report)
    assert verdict.layer is Layer.SUCCESS
    assert verdict.hosts_write_needed
    # 命令只在 cli_hint，fix_hint 是纯动作，绝不出现在报告 / GUI 里
    assert "--ip 9.9.9.9 --apply-hosts" in verdict.cli_hint
    assert "--restore" in verdict.cli_hint
    assert "--" not in verdict.fix_hint
    assert "9.9.9.9" in verdict.fix_hint


def test_incomplete_hint_raises_deadline():
    report = make_report(incomplete="整体超时", probes=[])
    verdict = judge(report)
    assert "--deadline 90" in verdict.cli_hint
    assert "--" not in verdict.fix_hint


def test_dns_poisoned_hint_requires_verification():
    report = make_report(probes=[probe("1.2.3.4", tls=tls_mismatch())])
    verdict = judge(report)
    assert verdict.layer is Layer.DNS_POISONED
    assert "--ip" in verdict.cli_hint
    assert "证书" in verdict.fix_hint


def test_tls_blocked_hint_says_hosts_is_useless():
    report = make_report(probes=[probe("1.2.3.4", tls=tls_blocked())])
    verdict = judge(report)
    assert "hosts" in verdict.fix_hint
    assert "无效" in verdict.fix_hint or "不要" in verdict.fix_hint


def test_fix_hint_survives_all_renderers():
    report = make_report(probes=[probe("9.9.9.9", tls=tls_ok(), http=http_ok())])
    report.verdict = judge(report)
    hint = report.verdict.fix_hint
    assert hint in render.render_markdown(report)
    assert hint in render.render_html(report)
    assert json.loads(render.render_json(report))["verdict"]["fix_hint"] == hint


def test_build_fix_hint_does_not_mutate_verdict():
    report = make_report()
    verdict = judge(report)
    before = verdict.fix_hint
    build_fix_hint(report, verdict)
    assert verdict.fix_hint == before


def test_build_fix_hint_is_pure():
    report = make_report(dns=[dns_ok(["1.2.3.4"])])
    verdict = judge(report)
    first = build_fix_hint(report, verdict)
    second = build_fix_hint(report, verdict)
    assert first == second
