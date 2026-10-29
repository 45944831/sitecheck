# -*- coding: utf-8 -*-
"""判定树全分支测试。

v1.0 的 verdict() 直接读一个裸 dict，无法构造边界用例，所以这些场景
从来没有被验证过 —— 其中"控制组不通"和"HTTP 无响应"两条直接导致了
线上误判。这里用纯数据构造每一个分支。
"""
from __future__ import annotations

import pytest

from sitecheck.models import Layer, TcpStatus, TlsStatus
from sitecheck.verdict import dns_consistency, judge

from .conftest import (
    control,
    dns_empty,
    dns_nx,
    dns_ok,
    http_malformed,
    http_ok,
    http_reject,
    http_silent,
    probe,
    proxy,
    report,
    tls_blocked,
    tls_mismatch,
    tls_ok,
)

# ---------------------------------------------------------------- P0 回归

def test_control_all_failed_yields_inconclusive():
    """P0 回归：控制组全不通时，不得输出"站点 TCP 不通"这类结论。

    v1.0 把控制组只写进报告，verdict() 完全不读，于是本机断网时会
    断言目标站点的 443 端口不可达。
    """
    rep = report(control=[control(False, "www.baidu.com", "1.1.1.1"),
                          control(False, "www.qq.com", "2.2.2.2")],
                 probes=[probe("1.2.3.4", tcp=TcpStatus.TIMEOUT)])
    verdict = judge(rep)
    assert verdict.layer is Layer.INCONCLUSIVE
    assert "出网" in verdict.headline
    assert "不可信" in verdict.evidence


def test_http_no_response_is_not_reject():
    """P0 回归：一个字节都没收到，不能报成"服务端反爬"。"""
    rep = report(probes=[probe("1.2.3.4", tls=tls_ok(), http=http_silent())])
    verdict = judge(rep)
    assert verdict.layer is Layer.HTTP_NO_RESPONSE
    assert "反爬" not in verdict.headline
    assert "hosts" in verdict.hosts_advice


def test_malformed_response_is_not_reject():
    rep = report(probes=[probe("1.2.3.4", tls=tls_ok(), http=http_malformed())])
    assert judge(rep).layer is Layer.HTTP_NO_RESPONSE


def test_proxy_required_when_direct_fails_but_proxy_works():
    """P0 回归：直连不通、经代理可通时，必须点明是本机代理问题。"""
    rep = report(
        proxy=proxy("http://127.0.0.1:7890"),
        probes=[probe("1.2.3.4", tls=tls_ok(), http=http_silent(),
                      http_proxy=http_ok(200))],
    )
    verdict = judge(rep)
    assert verdict.layer is Layer.PROXY_REQUIRED
    assert "代理" in verdict.headline
    assert "不要改 hosts" in verdict.hosts_advice


# ---------------------------------------------------------------- 成功分支

def test_success_via_dns():
    rep = report(probes=[probe("1.2.3.4", tls=tls_ok(), http=http_ok(200))])
    verdict = judge(rep)
    assert verdict.layer is Layer.SUCCESS
    assert "200" in verdict.headline
    assert verdict.hosts_write_needed is False
    assert "无需添加 hosts" in verdict.hosts_advice


def test_success_reports_redundant_hosts_entry():
    rep = report(hosts=[(22, "1.2.3.4")],
                 probes=[probe("1.2.3.4", tls=tls_ok(), http=http_ok(200))])
    verdict = judge(rep)
    assert verdict.layer is Layer.SUCCESS
    assert "冗余" in verdict.hosts_advice


def test_success_via_hosts_only():
    """DNS 的 IP 不通，hosts 里的 IP 可用 -> 保持现状，不要求写入。"""
    rep = report(dns=[dns_ok(["9.9.9.9"])], doh=[dns_ok(["9.9.9.9"], name="DoH")],
                 hosts=[(10, "1.2.3.4")],
                 probes=[probe("9.9.9.9", tcp=TcpStatus.TIMEOUT),
                         probe("1.2.3.4", source="hosts", tls=tls_ok(),
                               http=http_ok(200))])
    verdict = judge(rep)
    assert verdict.layer is Layer.SUCCESS
    assert verdict.hosts_write_needed is False
    assert "保持现状" in verdict.hosts_advice


def test_success_needs_hosts_write():
    """DNS 全不通，但有个证书匹配的 IP 能访问 -> 建议写入 hosts。"""
    rep = report(dns=[dns_ok(["9.9.9.9"])], doh=[dns_ok(["9.9.9.9"], name="DoH")],
                 probes=[probe("9.9.9.9", tcp=TcpStatus.TIMEOUT),
                         probe("1.2.3.4", tls=tls_ok(), http=http_ok(200))])
    verdict = judge(rep)
    assert verdict.layer is Layer.SUCCESS
    assert verdict.hosts_write_needed is True
    assert verdict.hosts_entry_ips == ["1.2.3.4"]


# ---------------------------------------------------------------- 拒绝分支

def test_http_reject_is_reachable():
    """403 说明链路是通的，不能报成网络问题。"""
    rep = report(probes=[probe("1.2.3.4", tls=tls_ok(), http=http_reject(403))])
    verdict = judge(rep)
    assert verdict.layer is Layer.HTTP_REJECT
    assert "403" in verdict.headline
    assert "无需修改 hosts" in verdict.hosts_advice


# ---------------------------------------------------------------- 失败分支

def test_dns_poisoned_when_cert_mismatch():
    rep = report(probes=[probe("1.2.3.4", tls=tls_mismatch("other.example.net"))])
    verdict = judge(rep)
    assert verdict.layer is Layer.DNS_POISONED
    assert "other.example.net" in verdict.evidence


def test_tls_blocked_says_hosts_useless():
    """SNI 层封锁：必须明确说改 hosts 无效。"""
    rep = report(probes=[probe("1.2.3.4", tls=tls_blocked())])
    verdict = judge(rep)
    assert verdict.layer is Layer.TLS_BLOCKED
    assert "hosts" in verdict.hosts_advice
    assert "无效" in verdict.hosts_advice


def test_tcp_blocked():
    rep = report(probes=[probe("1.2.3.4", tcp=TcpStatus.TIMEOUT),
                         probe("5.6.7.8", tcp=TcpStatus.REFUSED)])
    verdict = judge(rep)
    assert verdict.layer is Layer.TCP_BLOCKED
    assert "hosts" in verdict.hosts_advice


def test_dns_fail_nxdomain():
    rep = report(dns=[dns_nx()], doh=[], probes=[])
    verdict = judge(rep)
    assert verdict.layer is Layer.DNS_FAIL
    assert "NXDOMAIN" in verdict.headline


def test_dns_fail_empty():
    rep = report(dns=[dns_empty()], doh=[], probes=[])
    verdict = judge(rep)
    assert verdict.layer is Layer.DNS_FAIL


def test_unknown_fallback():
    """TLS 报错（非切断、非不匹配）落到底部兜底。"""
    from sitecheck.models import TlsResult
    rep = report(probes=[probe("1.2.3.4",
                               tls=TlsResult(status=TlsStatus.ERROR, detail="TLS 错误"))])
    assert judge(rep).layer is Layer.UNKNOWN


# ---------------------------------------------------------------- 证据字段

@pytest.mark.parametrize("probes", [
    [probe("1.2.3.4", tls=tls_ok(), http=http_ok(200))],
    [probe("1.2.3.4", tls=tls_ok(), http=http_reject(403))],
    [probe("1.2.3.4", tls=tls_ok(), http=http_silent())],
    [probe("1.2.3.4", tls=tls_mismatch())],
    [probe("1.2.3.4", tls=tls_blocked())],
    [probe("1.2.3.4", tcp=TcpStatus.TIMEOUT)],
])
def test_every_verdict_has_evidence(probes):
    """每条结论都必须说明依据 —— 这是可信工具和黑盒工具的分界线。"""
    verdict = judge(report(probes=probes))
    assert verdict.evidence, "结论缺少 evidence：%s" % verdict.layer


# ---------------------------------------------------------------- DNS 一致性

def test_dns_consistency_detects_disjoint():
    rep = report(dns=[dns_ok(["1.1.1.1"])], doh=[dns_ok(["2.2.2.2"], name="DoH")])
    info = dns_consistency(rep)
    assert info["all_udp_agree"] is True
    assert info["doh_disjoint"] is True


def test_dns_consistency_tolerates_cdn_rotation():
    """不同 DNS 返回不同 CDN 节点是正常的，不能误报成污染。"""
    rep = report(
        dns=[dns_ok(["1.1.1.1"], server="223.5.5.5", name="阿里"),
             dns_ok(["2.2.2.2"], server="119.29.29.29", name="腾讯")],
        doh=[dns_ok(["2.2.2.2"], name="DoH")],
    )
    info = dns_consistency(rep)
    assert info["all_udp_agree"] is False
    assert info["doh_disjoint"] is False      # 与腾讯有交集，不算污染


def test_dns_consistency_overlap_counts_as_clean():
    rep = report(dns=[dns_ok(["1.1.1.1", "2.2.2.2"])],
                 doh=[dns_ok(["2.2.2.2"], name="DoH")])
    assert dns_consistency(rep)["doh_disjoint"] is False


# ---------------------------------------------------------------- tips

def test_tips_mention_proxy_when_present():
    rep = report(proxy=proxy("http://127.0.0.1:7890"),
                 probes=[probe("1.2.3.4", tls=tls_ok(), http=http_ok(200))])
    judge(rep)
    assert any("代理" in tip for tip in rep.tips)


def test_tips_warn_expiring_cert():
    rep = report(probes=[probe("1.2.3.4", tls=tls_ok(days_left=5),
                               http=http_ok(200))])
    judge(rep)
    assert any("过期" in tip for tip in rep.tips)
