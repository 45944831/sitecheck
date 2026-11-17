# -*- coding: utf-8 -*-
"""无控制台（windowed 打包）回归测试。

GUI 提权写入 hosts 时会重启成 `sitecheck.exe hosts --write ...`：
这是 windowed 进程，UAC 提权后没有父控制台可挂，sys.stdout/stderr 均为 None。
print() 对 None 安全，但显式的 .isatty()/.write()/flush() 会抛
AttributeError，导致 "Unhandled exception in script" 崩溃弹窗。
"""
from __future__ import annotations

import io
import sys
from unittest.mock import patch

from sitecheck import cli


def test_enable_ansi_with_no_stdout():
    with patch.object(sys, "stdout", None):
        assert cli._enable_ansi() is False


def test_reconfigure_streams_with_no_streams():
    with patch.object(sys, "stdout", None), patch.object(sys, "stderr", None):
        cli._reconfigure_streams()  # 不应抛异常


def test_progress_with_no_stderr(tmp_path):
    style = cli.Style(False)
    progress = cli._make_progress(style, quiet=False)
    with patch.object(sys, "stderr", None):
        progress("解析", "查询 DNS", 1, 3)  # 不应抛异常


def test_progress_still_writes_when_available():
    style = cli.Style(False)
    progress = cli._make_progress(style, quiet=False)
    buf = io.StringIO()
    with patch.object(sys, "stderr", buf):
        progress("解析", "查询 DNS", 1, 3)
    assert "解析" in buf.getvalue()
    assert "查询 DNS" in buf.getvalue()


def test_cmd_hosts_noop_with_no_console():
    """无控制台下 hosts 子命令的参数解析与 style 构造不崩。"""
    with patch.object(sys, "stdout", None), patch.object(sys, "stderr", None):
        rc = cli.main(["hosts"])  # 无任何动作参数，只打印用法
    assert isinstance(rc, int)
