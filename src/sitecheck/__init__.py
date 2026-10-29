# -*- coding: utf-8 -*-
"""sitecheck —— 网站直连检测工具。

输入一个域名，逐层定位"为什么打不开"，并只在 hosts 真的能解决时才建议改 hosts。

公开 API：
    analyze(domain)         完整检测，返回 Report
    judge(report)           从 Report 得出结论
    render_markdown/json/html(report)   三种输出格式
"""
from __future__ import annotations

__all__ = [
    "__version__",
    "analyze",
    "judge",
    "normalize_domain",
    "render_markdown",
    "render_json",
    "render_html",
    "render_summary",
    "Report",
    "Verdict",
    "Layer",
]

try:                                            # 正常安装时从包元数据取版本
    from importlib.metadata import PackageNotFoundError
    from importlib.metadata import version as _pkg_version
    try:
        __version__ = _pkg_version("sitecheck")
    except PackageNotFoundError:
        __version__ = "2.0.1"
except ImportError:                             # pragma: no cover
    __version__ = "2.0.1"

from .models import Layer, Report, Verdict  # noqa: E402
from .orchestrator import analyze, normalize_domain  # noqa: E402
from .render import render_html, render_json, render_markdown, render_summary  # noqa: E402
from .verdict import judge  # noqa: E402
