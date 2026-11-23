# -*- coding: utf-8 -*-
"""远程 hosts 情报源的解析、降级与候选接入测试。"""
from __future__ import annotations

from sitecheck import dns as dnsmod
from sitecheck import orchestrator, render

from .conftest import report as make_report


def test_parse_hosts_mapping_reads_multiple_names():
    text = "\n".join([
        "# GitHub520 Host Start",
        "140.82.112.4 github.com",
        "140.82.113.3 github.com api.github.com",
        "",
        "# comment with 1.2.3.4 inside",
    ])
    mapping = dnsmod.parse_hosts_mapping(text)
    assert mapping["github.com"] == ["140.82.112.4", "140.82.113.3"]
    assert mapping["api.github.com"] == ["140.82.113.3"]


def test_parse_hosts_mapping_skips_garbage():
    text = "\n".join([
        "57.155.223.240",                 # 裸 IP：上次在真实 hosts 里挖到的垃圾行
        "not-an-ip example.com",
        "999.1.1.1 bad.example.com",
        "1.2.3.4 good.example.com # trailing",
    ])
    mapping = dnsmod.parse_hosts_mapping(text)
    assert mapping == {"good.example.com": ["1.2.3.4"]}


def test_parse_hosts_mapping_deduplicates():
    mapping = dnsmod.parse_hosts_mapping("1.2.3.4 a.com\n1.2.3.4 a.com\n")
    assert mapping == {"a.com": ["1.2.3.4"]}


def test_fetch_failure_is_silent():
    dnsmod._remote_cache.clear()
    ips = dnsmod.fetch_remote_ips("example.com", timeout=0.5,
                                  url="http://127.0.0.1:1/nothing")
    assert ips == []


def test_fetch_uses_cache(monkeypatch):
    dnsmod._remote_cache.clear()
    calls: list[int] = []

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _size):
            return b"1.2.3.4 example.com\n"

    def fake_urlopen(_req, timeout):          # noqa: ARG001
        calls.append(1)
        return FakeResponse()

    monkeypatch.setattr(dnsmod.urllib.request, "urlopen", fake_urlopen)
    assert dnsmod.fetch_remote_ips("example.com", url="https://fake.invalid") == ["1.2.3.4"]
    assert dnsmod.fetch_remote_ips("example.com", url="https://fake.invalid") == ["1.2.3.4"]
    assert len(calls) == 1


def test_empty_url_disables_feature():
    assert dnsmod.fetch_remote_ips("example.com", url="") == []


def test_collect_candidates_includes_remote_source(monkeypatch):
    monkeypatch.setattr(dnsmod, "fetch_remote_ips", lambda _domain: ["9.9.9.9"])
    monkeypatch.setattr(dnsmod, "system_resolve", lambda _host: [])
    result = make_report(dns=[], doh=[], hosts=[])
    candidates = orchestrator.collect_candidates(result, [])
    assert ("9.9.9.9", "远程源") in candidates


def test_remote_ip_does_not_override_manual(monkeypatch):
    monkeypatch.setattr(dnsmod, "fetch_remote_ips", lambda _domain: ["9.9.9.9"])
    monkeypatch.setattr(dnsmod, "system_resolve", lambda _host: [])
    result = make_report(dns=[], doh=[], hosts=[])
    candidates = orchestrator.collect_candidates(result, ["1.1.1.1"])
    assert candidates[0] == ("1.1.1.1", "手动")
    assert ("9.9.9.9", "远程源") in candidates


def test_doh_ips_marked_as_remote_source(monkeypatch):
    """本机 UDP 与远端 DoH 必须标成不同来源，不能都叫「解析」。"""
    from sitecheck.models import DnsResult, DnsStatus

    monkeypatch.setattr(dnsmod, "fetch_remote_ips", lambda _domain: [])
    monkeypatch.setattr(dnsmod, "system_resolve", lambda _host: [])
    udp = DnsResult(server="223.5.5.5", name="阿里", status=DnsStatus.OK,
                    ips=["1.1.1.1"], transport="udp")
    doh = DnsResult(server="https://doh.pub/dns-query", name="DoH 腾讯",
                    status=DnsStatus.OK, ips=["9.9.9.9"], transport="doh")
    result = make_report(dns=[udp], doh=[doh], hosts=[])
    candidates = orchestrator.collect_candidates(result, [])
    assert ("1.1.1.1", "解析") in candidates
    assert ("9.9.9.9", "远端 DoH") in candidates
    assert ("9.9.9.9", "解析") not in candidates


def test_reports_show_remote_dns_as_separate_section():
    """Markdown / HTML / JSON 都要把远端 DoH 与本机解析分开呈现。"""
    from sitecheck.models import DnsResult, DnsStatus

    udp = DnsResult(server="223.5.5.5", name="阿里", status=DnsStatus.OK,
                    ips=["1.1.1.1"], transport="udp")
    doh = DnsResult(server="https://doh.pub/dns-query", name="DoH 腾讯",
                    status=DnsStatus.OK, ips=["9.9.9.9"], transport="doh")
    report = make_report(dns=[udp], doh=[doh], hosts=[])

    md = render.render_markdown(report)
    assert "本机解析（UDP" in md
    assert "远端解析（DoH" in md
    assert "仍须通过证书校验才算真实 IP" in md

    html = render.render_html(report)
    assert "DNS 解析 · 本机" in html
    assert "DNS 解析 · 远端" in html

    import json
    payload = json.loads(render.render_json(report))
    assert payload["doh"][0]["transport"] == "doh"
    assert payload["dns"][0]["transport"] == "udp"
