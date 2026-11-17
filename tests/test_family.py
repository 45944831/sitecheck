# -*- coding: utf-8 -*-
"""域名族发现与批量检测测试（不依赖网络）。"""
from __future__ import annotations

import json

from sitecheck import family, familycheck
from sitecheck.models import HttpResult, HttpStatus, TlsResult, TlsStatus

# ---------------------------------------------------------------- 清单

def test_github_family_has_core_domains():
    domains = {d.domain for d in family.domains_for("github")}
    for must in ("github.com", "api.github.com", "raw.githubusercontent.com",
                 "codeload.github.com", "github.githubassets.com",
                 "avatars.githubusercontent.com",
                 "objects.githubusercontent.com"):
        assert must in domains


def test_cdn_domains_are_not_fixable():
    by_name = {d.domain: d for d in family.domains_for("github")}
    for cdn in ("github.blog", "github-cloud.s3.amazonaws.com",
                "github.global.ssl.fastly.net"):
        assert by_name[cdn].fixable is False


def test_core_domains_are_fixable():
    by_name = {d.domain: d for d in family.domains_for("github")}
    assert by_name["github.com"].fixable is True
    assert by_name["api.github.com"].fixable is True


def test_unknown_family_returns_empty():
    assert family.domains_for("unknown-service") == []
    assert "github" in family.available_families()


def test_groups_cover_all_domains():
    groups = family.groups_of("github")
    assert "核心" in groups and "图片" in groups and "CDN" in groups


# ---------------------------------------------------------------- 单域名判定

def _tls(cn: str, match: bool = True) -> TlsResult:
    return TlsResult(status=TlsStatus.OK, cn=cn, san=[cn], cert_match=match)


def _http() -> HttpResult:
    return HttpResult(status=HttpStatus.OK, code=200)


def _patch(monkeypatch, *, sys_ips, tls_map, http_map=None):
    """tls_map: {ip: TlsResult}；不在表里的 IP 返回不匹配。"""
    import sitecheck.familycheck as fc
    monkeypatch.setattr(fc.dnsmod, "system_resolve", lambda _h: sys_ips)
    monkeypatch.setattr(fc.dnsmod, "fetch_remote_ips", lambda _d, **_k: [])
    http_map = http_map or {}

    def fake_tls(ip, host, *args, **kwargs):
        return tls_map.get(ip, _tls("wrong.example", match=False))

    def fake_http(ip, host, *args, **kwargs):
        return http_map.get(ip, HttpResult(status=HttpStatus.NO_RESPONSE))

    monkeypatch.setattr(fc.probemod, "tls_probe", fake_tls)
    monkeypatch.setattr(fc.probemod, "http_probe", fake_http)


def test_sys_ip_working_is_ok(monkeypatch):
    item = family.FamilyDomain("github.com", "主站", "核心", True)
    _patch(monkeypatch, sys_ips=["1.2.3.4"],
           tls_map={"1.2.3.4": _tls("github.com")},
           http_map={"1.2.3.4": _http()})
    r = familycheck.check_domain(item)
    assert r.status == "ok"
    assert r.working_ips == ["1.2.3.4"]
    assert not r.needs_fix


def test_remote_ip_fixable_when_sys_blocked(monkeypatch):
    item = family.FamilyDomain("github.com", "主站", "核心", True)
    # 系统解析 IP 证书不匹配，远程源给另一个可用 IP
    def fake_remote(_d, **_k):
        return ["5.6.7.8"]
    import sitecheck.familycheck as fc
    _patch(monkeypatch, sys_ips=["1.1.1.1"],
           tls_map={"5.6.7.8": _tls("github.com")},
           http_map={"5.6.7.8": _http()})
    monkeypatch.setattr(fc.dnsmod, "fetch_remote_ips", fake_remote)
    r = familycheck.check_domain(item)
    assert r.status == "fixable"
    assert r.needs_fix
    assert r.working_ips == ["5.6.7.8"]


def test_no_genuine_ip_is_unusable(monkeypatch):
    item = family.FamilyDomain("github.com", "主站", "核心", True)
    _patch(monkeypatch, sys_ips=["1.1.1.1"], tls_map={})
    r = familycheck.check_domain(item)
    assert r.status == "unusable"


def test_no_sys_resolution_is_inconclusive(monkeypatch):
    item = family.FamilyDomain("github.com", "主站", "核心", True)
    _patch(monkeypatch, sys_ips=[], tls_map={})
    r = familycheck.check_domain(item)
    assert r.status == "inconclusive"
    assert "无法解析" in r.note


def test_cdn_with_broken_sys_is_not_fixable(monkeypatch):
    """CDN 域名即使有可用 IP，也不标记为可写入。"""
    item = family.FamilyDomain("github.blog", "博客", "CDN", False)
    def fake_remote(_d, **_k):
        return ["5.6.7.8"]
    import sitecheck.familycheck as fc
    _patch(monkeypatch, sys_ips=["1.1.1.1"],
           tls_map={"5.6.7.8": _tls("github.blog")},
           http_map={"5.6.7.8": _http()})
    monkeypatch.setattr(fc.dnsmod, "fetch_remote_ips", fake_remote)
    r = familycheck.check_domain(item)
    assert r.status == "unusable"
    assert not r.needs_fix


# ---------------------------------------------------------------- 聚合与渲染

def test_run_preserves_order_and_reports(monkeypatch):
    domains = [
        family.FamilyDomain("a.github.com", "A", "核心", True),
        family.FamilyDomain("b.github.com", "B", "图片", True),
    ]
    monkeypatch.setattr(familycheck, "check_domain",
                        lambda d, timeout=4.0: familycheck.DomainCheck(
                            domain=d.domain, label=d.label, group=d.group,
                            fixable=d.fixable, status="ok"))
    report = familycheck.run("github", domains, version="2.0.2")
    assert [c.domain for c in report.checks] == ["a.github.com", "b.github.com"]
    assert len(report.ok) == 2


def test_render_includes_fix_command():
    report = familycheck.FamilyCheckReport(
        name="github", time="2026-11-17 10:00", version="2.0.2")
    report.checks = [familycheck.DomainCheck(
        domain="github.com", label="主站", group="核心", fixable=True,
        status="fixable", working_ips=["1.2.3.4"])]
    text = familycheck.render_text(report)
    assert "github.com" in text
    assert "--apply-hosts" in text
    data = json.loads(familycheck.render_json(report))
    assert data["checks"][0]["status"] == "fixable"
    assert "github.com" in familycheck.render_html(report)


# ---------------------------------------------------------------- 批量写入

def test_apply_family_hosts_writes_and_skips_cdn(tmp_path, monkeypatch):
    """批量写入只写 fixable 域名，用隔离 hosts 路径，不碰系统文件。"""
    from sitecheck import cli
    hosts_file = tmp_path / "hosts"
    hosts_file.write_text("127.0.0.1 localhost\n1.1.1.1 github.com\n", encoding="utf-8")
    monkeypatch.setenv("SITECHECK_HOSTS", str(hosts_file))
    # 重新加载让 HOSTS_PATH 生效
    import importlib

    import sitecheck.hosts as hostsmod
    importlib.reload(hostsmod)
    monkeypatch.setattr(cli, "hostsmod", hostsmod)
    monkeypatch.setattr(hostsmod, "flush_dns", lambda: (True, "test"))
    monkeypatch.setattr(cli.hostsmod, "backup_dir", lambda: tmp_path / "bk")

    r = familycheck.FamilyCheckReport(name="github", time="now", version="t")
    r.checks = [
        familycheck.DomainCheck(domain="github.com", label="主站", group="核心",
                                fixable=True, working_ips=["140.82.116.4"],
                                status="fixable"),
        familycheck.DomainCheck(domain="github.blog", label="博客", group="CDN",
                                fixable=False, working_ips=["9.9.9.9"],
                                status="unusable"),
    ]
    args = type("A", (), {"yes": True})()
    rc = cli._apply_family_hosts(r, args, cli.Style(False))
    content = hosts_file.read_text(encoding="utf-8")
    assert rc == 0
    assert "140.82.116.4" in content
    assert "9.9.9.9" not in content          # CDN 域名未写入
    assert "1.1.1.1" not in content          # 旧条目被替换
