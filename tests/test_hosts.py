# -*- coding: utf-8 -*-
"""hosts 读写的回归测试。

覆盖 v1.0 的三个真实风险：
    1. utf-8-sig 读、utf-8 写 -> GBK 注释被写成乱码，不可逆
    2. 直接覆盖写 -> 中途失败会留下半截 hosts
    3. --ip 不校验 -> 任意字符串都能写进 hosts
"""
from __future__ import annotations

import pytest

from sitecheck import hosts as H

SAMPLE = """# 本地测试 hosts
127.0.0.1    localhost

# 以下为测试条目
1.2.3.4      example.com
5.6.7.8      example.com   # 旧条目
9.9.9.9      other.test
"""


@pytest.fixture
def hosts_file(tmp_path, monkeypatch):
    path = tmp_path / "hosts"
    path.write_text(SAMPLE, encoding="utf-8")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "appdata"))
    return path


# ---------------------------------------------------------------- 解析

def test_parse_entries(hosts_file):
    entries = H.parse_entries(hosts_file)
    assert len(entries) == 4
    assert entries[0] == {"line": 2, "ip": "127.0.0.1", "host": "localhost"}


def test_find_entries(hosts_file):
    found = H.find_entries("example.com", hosts_file)
    assert [ip for _line, ip in found] == ["1.2.3.4", "5.6.7.8"]


def test_find_entries_ignores_comments(hosts_file):
    assert H.find_entries("localhost", hosts_file) == [(2, "127.0.0.1")]


def test_find_entries_no_match(hosts_file):
    assert H.find_entries("absent.com", hosts_file) == []


# ---------------------------------------------------------------- 编码

def test_read_gbk_preserves_encoding(tmp_path, monkeypatch):
    """GBK 编码的 hosts 必须能被正确读取，并按原编码写回。"""
    path = tmp_path / "hosts"
    content = "# 中文注释测试\n1.2.3.4  example.com\n"
    path.write_bytes(content.encode("gbk"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "appdata"))

    text, encoding = H.read_text(path)
    assert encoding == "gbk"
    assert "中文注释测试" in text

    H.apply("example.com", ["5.6.7.8"], path)
    assert "中文注释测试" in path.read_bytes().decode("gbk")


def test_detect_encoding_utf8_sig(tmp_path):
    path = tmp_path / "hosts"
    path.write_bytes(b"\xef\xbb\xbf# bom\n")
    assert H.detect_encoding(path.read_bytes()) == "utf-8-sig"


# ---------------------------------------------------------------- 写入

def test_apply_replaces_old_entries(hosts_file):
    message, backup = H.apply("example.com", ["8.8.8.8"], hosts_file)
    text = hosts_file.read_text(encoding="utf-8")
    assert "1.2.3.4" not in text
    assert "5.6.7.8" not in text
    assert "8.8.8.8    example.com" in text
    assert "9.9.9.9      other.test" in text       # 其他条目不受影响
    assert "已写入 1 条" in message
    assert backup is not None and backup.exists()


def test_apply_keeps_newline_style(tmp_path, monkeypatch):
    path = tmp_path / "hosts"
    path.write_bytes(b"1.2.3.4  a.test\n")         # 纯 LF
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "appdata"))
    H.apply("a.test", ["5.6.7.8"], path)
    raw = path.read_bytes()
    assert b"\r\n" not in raw


def test_apply_is_atomic_no_leftover_tmp(hosts_file):
    H.apply("example.com", ["8.8.8.8"], hosts_file)
    leftovers = list(hosts_file.parent.glob("*.sitecheck.tmp"))
    assert leftovers == []


def test_apply_multiple_ips(hosts_file):
    H.apply("example.com", ["1.1.1.1", "2.2.2.2"], hosts_file)
    found = H.find_entries("example.com", hosts_file)
    assert [ip for _l, ip in found] == ["1.1.1.1", "2.2.2.2"]


def test_plan_shows_removals(hosts_file):
    removed, added = H.plan("example.com", ["8.8.8.8"], hosts_file)
    assert len(removed) == 2
    assert removed[0][0] == 5
    assert added == ["8.8.8.8    example.com"]


# ---------------------------------------------------------------- 校验

@pytest.mark.parametrize("bad", [
    "not-an-ip",
    "1.2.3.4\n0.0.0.0 evil.com",     # 换行注入
    "1.2.3.4 evil.com",              # 空格注入
    "999.1.1.1",
    "",
])
def test_validate_ips_rejects_injection(bad):
    with pytest.raises(H.HostsError):
        H.validate_ips([bad])


def test_validate_ips_accepts_ipv6():
    assert H.validate_ips(["::1"]) == ["::1"]


def test_apply_rejects_injection(hosts_file):
    original = hosts_file.read_text(encoding="utf-8")
    with pytest.raises(H.HostsError):
        H.apply("example.com", ["1.2.3.4\n0.0.0.0 evil.com"], hosts_file)
    assert hosts_file.read_text(encoding="utf-8") == original


# ---------------------------------------------------------------- 备份还原

def test_backup_and_restore(hosts_file):
    before = hosts_file.read_text(encoding="utf-8")
    _msg, backup = H.apply("example.com", ["8.8.8.8"], hosts_file)
    assert "8.8.8.8" in hosts_file.read_text(encoding="utf-8")

    H.restore(backup, hosts_file)
    assert hosts_file.read_text(encoding="utf-8") == before


def test_restore_missing_backup(tmp_path):
    with pytest.raises(H.HostsError):
        H.restore(tmp_path / "nope.bak", tmp_path / "hosts")


def test_list_backups_sorted_newest_first(hosts_file):
    H.apply("example.com", ["8.8.8.8"], hosts_file)
    H.apply("example.com", ["9.9.9.9"], hosts_file)
    backups = H.list_backups()
    assert len(backups) >= 2
    assert backups[0].stat().st_mtime >= backups[-1].stat().st_mtime


def test_backup_pruning(hosts_file):
    for i in range(H.MAX_BACKUPS + 4):
        H.apply("example.com", ["10.0.0.%d" % (i + 1)], hosts_file)
    assert len(H.list_backups()) <= H.MAX_BACKUPS
