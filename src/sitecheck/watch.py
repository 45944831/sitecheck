# -*- coding: utf-8 -*-
"""间歇故障监控：周期性复检并记录状态变化时间线。

设计取舍：
    * 只观察，不自动写 hosts —— 与 sitecheck "不擅自改系统配置"的原则一致。
    * 复用 orchestrator.analyze()，不碰判定树：每次检测产出独立 Report，
      这里只做跨次的状态机与时间线。
    * 抖动抑制：连续 N 次相同的新状态才确认变化，避免网络瞬时抖动
      在时间线上制造大量假事件。
"""
from __future__ import annotations

import dataclasses
import json
import time as _time
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Optional

from .exitcodes import exit_code_for_report
from .models import Layer, Report

DEFAULT_INTERVAL = 60.0
DEFAULT_CONFIRM = 2
MAX_EVENTS = 20


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


@dataclasses.dataclass
class WatchEvent:
    time: str
    layer: str
    headline: str
    code: int
    kind: str                     # initial / fail / recover / change
    seq: int = 0


@dataclasses.dataclass
class WatchTimeline:
    domain: str
    started_at: str
    events: list[WatchEvent] = dataclasses.field(default_factory=list)
    total: int = 0
    finished_at: str = ""

    def record(self, event: WatchEvent) -> None:
        self.events.append(event)
        if len(self.events) > MAX_EVENTS:     # 有界：长期挂着也不会无限增长
            self.events = self.events[-MAX_EVENTS:]

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(dataclasses.asdict(self), ensure_ascii=False,
                          indent=indent)


class Tracker:
    """抖动抑制状态机。纯逻辑，可脱离网络测试。"""

    def __init__(self, confirm: int = DEFAULT_CONFIRM):
        self.confirm = max(1, confirm)
        self.confirmed: Optional[Layer] = None
        self.pending: Optional[Layer] = None
        self.pending_count = 0
        self.total = 0

    def observe(self, layer: Layer) -> Optional[tuple[Layer, str]]:
        """喂入一次检测结论；变化被确认时返回 (layer, kind)，否则 None。"""
        self.total += 1
        if self.confirmed is None:
            self.confirmed = layer
            return layer, "initial"
        if layer is self.confirmed:
            self.pending = None
            self.pending_count = 0
            return None
        if layer is self.pending:
            self.pending_count += 1
        else:
            self.pending = layer
            self.pending_count = 1
        if self.pending_count < self.confirm:
            return None
        old = self.confirmed
        self.confirmed = layer
        self.pending = None
        self.pending_count = 0
        if layer is Layer.SUCCESS:
            kind = "recover"
        elif old is Layer.SUCCESS:
            kind = "fail"
        else:
            kind = "change"
        return layer, kind


def run(domain: str,
        analyze_fn: Callable[[], Report],
        interval: float = DEFAULT_INTERVAL,
        count: int = 0,
        confirm: int = DEFAULT_CONFIRM,
        json_path: str = "",
        quiet: bool = False,
        sleep_fn: Callable[[float], None] = _time.sleep) -> int:
    """反复检测并打印时间线。返回最后一次检测的语义化退出码。"""
    timeline = WatchTimeline(domain=domain, started_at=_now())
    tracker = Tracker(confirm)
    last_code = 0
    seq = 0

    while count <= 0 or tracker.total < count:
        try:
            report = analyze_fn()
        except KeyboardInterrupt:
            break
        code = exit_code_for_report(report)
        last_code = code
        layer = (report.verdict.layer if report.verdict
                 else Layer.INCONCLUSIVE)
        headline = (report.verdict.headline if report.verdict
                    else "无结论")
        change = tracker.observe(layer)
        timeline.total = tracker.total

        if change:
            seq += 1
            changed_layer, kind = change
            timeline.record(WatchEvent(
                time=_now(), layer=changed_layer.value, headline=headline,
                code=code, kind=kind, seq=seq))
            if not quiet:
                print("[%d] ! %s  %s  %s" % (seq, kind, changed_layer.value,
                                             headline))
        if not quiet:
            marker = "!" if change else " "
            print("%s [%d] %s  %s  %s" % (marker, tracker.total, _now(),
                                          layer.value, headline), flush=True)

        if count > 0 and tracker.total >= count:
            break
        try:
            sleep_fn(max(0.0, interval))
        except KeyboardInterrupt:
            break

    timeline.finished_at = _now()
    if json_path:
        try:
            Path(json_path).write_text(timeline.to_json(), encoding="utf-8")
            if not quiet:
                print("时间线已写入 %s" % Path(json_path).resolve())
        except OSError as exc:
            print("时间线写入失败：%s" % exc)
    return last_code
