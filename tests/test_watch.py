# -*- coding: utf-8 -*-
"""--watch 状态机与时间线的回归测试（不打网络）。"""
from __future__ import annotations

import json

from sitecheck.models import Layer, Verdict
from sitecheck.watch import MAX_EVENTS, Tracker, WatchEvent, WatchTimeline, run

from .conftest import report as make_report


def _report(layer: Layer):
    return make_report(verdict=Verdict(layer=layer, headline=layer.value))


def _sequence(layers):
    it = iter(layers)

    def analyze():
        return _report(next(it))

    return analyze


def test_first_observation_is_initial():
    tracker = Tracker(confirm=2)
    assert tracker.observe(Layer.SUCCESS) == (Layer.SUCCESS, "initial")


def test_same_state_does_not_emit_event():
    tracker = Tracker(confirm=2)
    tracker.observe(Layer.SUCCESS)
    assert tracker.observe(Layer.SUCCESS) is None
    assert tracker.observe(Layer.SUCCESS) is None


def test_single_glitch_is_suppressed():
    tracker = Tracker(confirm=2)
    tracker.observe(Layer.SUCCESS)
    assert tracker.observe(Layer.TCP_BLOCKED) is None
    assert tracker.observe(Layer.SUCCESS) is None
    assert tracker.confirmed is Layer.SUCCESS


def test_two_consecutive_changes_confirm_failure():
    tracker = Tracker(confirm=2)
    tracker.observe(Layer.SUCCESS)
    assert tracker.observe(Layer.TCP_BLOCKED) is None
    assert tracker.observe(Layer.TCP_BLOCKED) == (Layer.TCP_BLOCKED, "fail")


def test_recovery_is_labeled_distinctly():
    tracker = Tracker(confirm=2)
    tracker.observe(Layer.SUCCESS)
    tracker.observe(Layer.TCP_BLOCKED)
    tracker.observe(Layer.TCP_BLOCKED)
    assert tracker.observe(Layer.SUCCESS) is None
    assert tracker.observe(Layer.SUCCESS) == (Layer.SUCCESS, "recover")


def test_confirm_one_disables_suppression():
    tracker = Tracker(confirm=1)
    tracker.observe(Layer.SUCCESS)
    assert tracker.observe(Layer.DNS_POISONED) == (Layer.DNS_POISONED, "fail")


def test_change_between_two_failures_is_change():
    tracker = Tracker(confirm=1)
    tracker.observe(Layer.TCP_BLOCKED)
    assert tracker.observe(Layer.DNS_POISONED) == (Layer.DNS_POISONED, "change")


def test_run_records_timeline_and_returns_last_code(tmp_path):
    layers = [Layer.SUCCESS, Layer.TCP_BLOCKED, Layer.TCP_BLOCKED,
              Layer.SUCCESS, Layer.SUCCESS]
    out = tmp_path / "timeline.json"
    code = run("example.com", _sequence(layers), count=5, confirm=2,
               json_path=str(out), quiet=True, sleep_fn=lambda _: None)

    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["total"] == 5
    assert [e["kind"] for e in data["events"]] == ["initial", "fail", "recover"]
    assert [e["seq"] for e in data["events"]] == [1, 2, 3]
    assert code == 0


def test_run_returns_last_semantic_code():
    layers = [Layer.SUCCESS, Layer.DNS_POISONED]
    code = run("example.com", _sequence(layers), count=2, confirm=1,
               quiet=True, sleep_fn=lambda _: None)
    assert code == 13


def test_timeline_is_bounded():
    timeline = WatchTimeline(domain="example.com", started_at="now")
    for seq in range(MAX_EVENTS + 5):
        timeline.record(WatchEvent(time="t", layer="SUCCESS", headline="ok",
                                   code=0, kind="change", seq=seq))
    assert len(timeline.events) == MAX_EVENTS
    assert timeline.events[0].seq == 5
