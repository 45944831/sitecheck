# -*- coding: utf-8 -*-
"""服务画像的聚合判定与并发执行测试（不打网络）。"""
from __future__ import annotations

import json

import pytest

from sitecheck.models import Layer, Verdict
from sitecheck.profile import (
    BUILTIN_PROFILES,
    ProfileTarget,
    aggregate,
    exit_code_for_profile,
    render_html,
    render_json,
    render_text,
    run,
)

from .conftest import report as make_report


def target(label: str, layer: Layer, code: int, **kwargs) -> ProfileTarget:
    return ProfileTarget(label=label, domain=label + ".example.com",
                         layer=layer.value, headline=layer.value,
                         code=code, **kwargs)


def test_all_ok():
    targets = [target("A", Layer.SUCCESS, 0), target("B", Layer.SUCCESS, 0)]
    p = aggregate("github", targets)
    assert p.summary == "all_ok"
    assert exit_code_for_profile(p) == 0


def test_partial():
    targets = [target("A", Layer.SUCCESS, 0),
               target("B", Layer.TCP_BLOCKED, 15)]
    p = aggregate("github", targets)
    assert p.summary == "partial"
    assert "B" in p.headline
    assert exit_code_for_profile(p) == 20


def test_all_failed():
    targets = [target("A", Layer.DNS_POISONED, 13),
               target("B", Layer.TLS_BLOCKED, 14)]
    p = aggregate("github", targets)
    assert p.summary == "all_failed"
    assert exit_code_for_profile(p) == 13


def test_inconclusive_beats_success():
    targets = [target("A", Layer.SUCCESS, 0),
               target("B", Layer.INCONCLUSIVE, 3)]
    p = aggregate("github", targets)
    assert p.summary == "inconclusive"
    assert exit_code_for_profile(p) == 3


def test_incomplete_marks_inconclusive():
    targets = [target("A", Layer.TCP_BLOCKED, 15, incomplete="整体超时")]
    p = aggregate("github", targets)
    assert p.summary == "inconclusive"


def test_empty_targets():
    p = aggregate("github", [])
    assert p.summary == "inconclusive"


def test_unknown_profile_raises():
    with pytest.raises(ValueError):
        run("does-not-exist", lambda domain: make_report(domain=domain))


def test_run_checks_every_target():
    seen = []

    def analyze(domain):
        seen.append(domain)
        return make_report(domain=domain,
                           verdict=Verdict(layer=Layer.SUCCESS, headline="ok"))

    result = run("github", analyze, version="2.1.0")
    assert sorted(seen) == sorted(d for _label, d in BUILTIN_PROFILES["github"])
    assert len(result.targets) == 4
    assert result.summary == "all_ok"


def test_run_captures_exception_without_crashing():
    def analyze(domain):
        if domain == "api.github.com":
            raise OSError("simulated")
        return make_report(domain=domain,
                           verdict=Verdict(layer=Layer.SUCCESS, headline="ok"))

    result = run("github", analyze)
    api = next(t for t in result.targets if t.domain == "api.github.com")
    assert api.layer == "INCONCLUSIVE"
    assert result.summary == "inconclusive"


def test_renderers_include_aggregate_headline():
    p = aggregate("github", [target("A", Layer.SUCCESS, 0)])
    assert p.headline in render_text(p)
    assert p.headline in render_html(p)
    data = json.loads(render_json(p))
    assert data["summary"] == p.summary
    assert len(data["targets"]) == 1
