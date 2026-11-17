# -*- coding: utf-8 -*-
"""语义化退出码与 JSON schema 的回归测试。"""
from __future__ import annotations

import json

import pytest

from sitecheck import render
from sitecheck.exitcodes import (
    EXIT_INCONCLUSIVE,
    EXIT_OK,
    EXIT_UNKNOWN,
    exit_code_for_layer,
    exit_code_for_report,
)
from sitecheck.models import SCHEMA_VERSION, Layer, Verdict

from .conftest import report as make_report


def _with_layer(layer: Layer, **report_kwargs):
    verdict = Verdict(layer=layer, headline=layer.value)
    return make_report(verdict=verdict, **report_kwargs)


def test_success_is_zero():
    assert exit_code_for_report(_with_layer(Layer.SUCCESS)) == EXIT_OK


@pytest.mark.parametrize("layer,expected", [
    (Layer.HTTP_REJECT, 10),
    (Layer.PROXY_REQUIRED, 11),
    (Layer.HTTP_NO_RESPONSE, 12),
    (Layer.DNS_POISONED, 13),
    (Layer.TLS_BLOCKED, 14),
    (Layer.TCP_BLOCKED, 15),
    (Layer.DNS_FAIL, 16),
    (Layer.INCONCLUSIVE, EXIT_INCONCLUSIVE),
])
def test_failure_layers_have_distinct_codes(layer, expected):
    assert exit_code_for_layer(layer) == expected
    assert exit_code_for_report(_with_layer(layer)) == expected


def test_no_verdict_is_inconclusive():
    assert exit_code_for_report(make_report(verdict=None)) == EXIT_INCONCLUSIVE


def test_incomplete_never_reports_a_failure_layer():
    report = _with_layer(Layer.TCP_BLOCKED, incomplete="整体超时")
    assert exit_code_for_report(report) == EXIT_INCONCLUSIVE


def test_success_stays_zero_even_if_incomplete_flag_set():
    report = _with_layer(Layer.SUCCESS, incomplete="用户取消")
    assert exit_code_for_report(report) == EXIT_OK


def test_unknown_layer_falls_back():
    assert exit_code_for_layer(Layer.UNKNOWN) == EXIT_UNKNOWN


def test_json_carries_schema_version():
    data = json.loads(render.render_json(make_report()))
    assert data["schema_version"] == SCHEMA_VERSION
