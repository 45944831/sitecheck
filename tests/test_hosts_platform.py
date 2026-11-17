# -*- coding: utf-8 -*-
"""hosts 跨平台分派测试。Windows 主路径的回归由 test_hosts.py 覆盖。"""
from __future__ import annotations

from sitecheck import hosts as H


def test_default_path_windows(monkeypatch):
    monkeypatch.setattr(H, "_is_windows", lambda: True)
    assert str(H.default_hosts_path()) == r"C:\Windows\System32\drivers\etc\hosts"


def test_default_path_posix(monkeypatch):
    monkeypatch.setattr(H, "_is_windows", lambda: False)
    assert H.default_hosts_path().as_posix() == "/etc/hosts"


def test_backup_dir_uses_xdg_on_posix(monkeypatch, tmp_path):
    monkeypatch.setattr(H, "_is_windows", lambda: False)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    assert H.backup_dir() == tmp_path / "sitecheck" / "backups"


def test_backup_dir_falls_back_to_home(monkeypatch, tmp_path):
    monkeypatch.setattr(H, "_is_windows", lambda: False)
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.setattr(H.Path, "home", staticmethod(lambda: tmp_path))
    assert H.backup_dir() == tmp_path / ".local" / "share" / "sitecheck" / "backups"


def test_backup_dir_keeps_windows_layout(monkeypatch, tmp_path):
    monkeypatch.setattr(H, "_is_windows", lambda: True)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    assert H.backup_dir() == tmp_path / "sitecheck" / "backups"


def test_ebusy_is_in_use_on_posix(monkeypatch):
    monkeypatch.setattr(H, "_is_windows", lambda: False)
    exc = PermissionError(16, "device busy")
    assert H._blocked_reason(exc) == "in-use"


def test_eacces_without_privilege_is_need_admin(monkeypatch):
    monkeypatch.setattr(H, "_is_windows", lambda: False)
    monkeypatch.setattr(H, "is_admin", lambda: False)
    exc = PermissionError(13, "permission denied")
    assert H._blocked_reason(exc) == "need-admin"


def test_eacces_with_privilege_is_in_use(monkeypatch):
    monkeypatch.setattr(H, "_is_windows", lambda: False)
    monkeypatch.setattr(H, "is_admin", lambda: True)
    exc = PermissionError(13, "permission denied")
    assert H._blocked_reason(exc) == "in-use"


def test_winerror_still_wins_on_windows(monkeypatch):
    monkeypatch.setattr(H, "_is_windows", lambda: True)
    exc = PermissionError(5, "denied")
    exc.winerror = 32
    assert H._blocked_reason(exc) == "in-use"


def test_admin_hint_is_platform_specific(monkeypatch):
    monkeypatch.setattr(H, "_is_windows", lambda: True)
    assert "管理员" in H.admin_hint("github.com --apply-hosts")
    monkeypatch.setattr(H, "_is_windows", lambda: False)
    assert "sudo" in H.admin_hint("github.com --apply-hosts")


def test_flush_dns_posix_is_non_fatal(monkeypatch):
    monkeypatch.setattr(H, "_is_windows", lambda: False)
    monkeypatch.setattr(H, "_platform_name", lambda: "linux")

    def fail(*_args, **_kwargs):
        raise FileNotFoundError("resolvectl not installed")

    monkeypatch.setattr(H.subprocess, "run", fail)
    ok, detail = H.flush_dns()
    assert ok is True
    assert "即时生效" in detail
