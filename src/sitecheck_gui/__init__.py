# -*- coding: utf-8 -*-
"""sitecheck 的图形界面包。

无参数启动 -> 打开 GUI；带参数启动 -> 转发给命令行（行为与 v1.0 一致）。
"""
from __future__ import annotations

__all__ = ["main"]


def main() -> int:
    from .app import run
    return run()
