# -*- coding: utf-8 -*-
"""整体超时 / 取消的接线测试：全部打桩，不打网络。

判定层已经保证"未完成 -> 无法判定"，这里只验调度层有没有把
should_stop / total_timeout 真的接上，以及中断原因有没有写进 report。
"""
from __future__ import annotations

from sitecheck import orchestrator
from sitecheck.models import Layer, ProxyInfo


def _offline(monkeypatch, resolved=(([], []),)):
    """把 analyze 里所有会出网的步骤换成空实现。"""
    monkeypatch.setattr(orchestrator.proxymod, "detect", lambda: ProxyInfo())
    monkeypatch.setattr(orchestrator.hostsmod, "find_entries", lambda domain: [])
    monkeypatch.setattr(orchestrator.dnsmod, "system_resolve", lambda domain: [])
    monkeypatch.setattr(orchestrator, "_resolve_all", lambda *a, **k: resolved[0])
    monkeypatch.setattr(orchestrator, "_check_control", lambda *a, **k: [])


def test_should_stop_short_circuits_before_dns(monkeypatch):
    _offline(monkeypatch)
    called: list[int] = []
    monkeypatch.setattr(orchestrator, "_resolve_all",
                        lambda *a, **k: called.append(1) or ([], []))

    report = orchestrator.analyze("example.com", total_timeout=30,
                                  should_stop=lambda: True)

    assert called == []
    assert report.incomplete == "用户取消"
    assert report.verdict.layer is Layer.INCONCLUSIVE
    assert "用户取消" in report.verdict.headline


def test_unlimited_deadline_still_judges(monkeypatch):
    """total_timeout=0 表示不限时，不应被当成"已经超时"。"""
    _offline(monkeypatch)

    report = orchestrator.analyze("example.com", total_timeout=0)

    assert report.incomplete == ""
    assert report.verdict is not None
    assert report.verdict.layer is Layer.DNS_FAIL


def test_stop_reason_reports_deadline(monkeypatch):
    assert orchestrator._stop_reason(None, None) == ""
    assert orchestrator._stop_reason(0.0, None) == "整体超时"
    assert orchestrator._stop_reason(None, lambda: True) == "用户取消"
    # 回调自己抛异常时不能让整个检测崩掉
    def boom() -> bool:
        raise RuntimeError("boom")
    assert orchestrator._stop_reason(None, boom) == ""
