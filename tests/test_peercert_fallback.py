# -*- coding: utf-8 -*-
"""证书降级解码回归测试。

真实 bug：verify_mode=CERT_NONE 时 getpeercert() 返回空字典，尽管底层
已经拿到 DER。严格链校验失败后降级到 CERT_NONE 时，旧代码据此判定
"无 CN / 证书不匹配"，把证书完全正常的 GitHub IP 误判成 DNS 污染。

样本是 2026-11-17 从 140.82.116.4:443 抓取的真实证书 DER（github.com，
Sectigo 签发），保证不依赖网络也能复现该场景。
"""
from __future__ import annotations

import base64
import ssl
from unittest.mock import MagicMock

from sitecheck.probe import _extract_cert, _peercert_dict

# 真实 GitHub 证书 DER（CN=github.com，SAN 含 github.com / www.github.com）
_GITHUB_DER_B64 = (
    "MIID9DCCA5ugAwIBAgIQPh1gJrSwrqJ53KLvu87YKzAKBggqhkjOPQQDAjBgMQswCQYD"
    "VQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMTcwNQYDVQQDEy5TZWN0aWdv"
    "IFB1YmxpYyBTZXJ2ZXIgQXV0aGVudGljYXRpb24gQ0EgRFYgRTM2MB4XDTI2MTAzMDAw"
    "MDAwMFoXDTI3MDEyNzIzNTk1OVowFTETMBEGA1UEAxMKZ2l0aHViLmNvbTBZMBMGByqG"
    "SM49AgEGCCqGSM49AwEHA0IABDfKd4nH+v687AH/LbUBuI5oXVsDbbLwRkLBCDbDmYWcr"
    "pxd8+9O0uPHpIgjAQ0gBToGy66v4d70x/jgDoosK3ejggKAMIICfDAfBgNVHSMEGDAWgBQ"
    "XmagEwW/kLXCoChA9A9PpGrgmYzAdBgNVHQ4EFgQUjLAqHq7uhl0AATWx5YtpI6U+PHEw"
    "DgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwSQ"
    "YDVR0gBEIwQDA0BgsrBgEEAbIxAQICBzAlMCMGCCsGAQUFBwIBFhdodHRwczovL3NlY3Rp"
    "Z28uY29tL0NQUzAIBgZngQwBAgEwgYQGCCsGAQUFBwEBBHgwdjBPBggrBgEFBQcwAoZDa"
    "HR0cDovL2NydC5zZWN0aWdvLmNvbS9TZWN0aWdvUHVibGljU2VydmVyQXV0aGVudGljYXRp"
    "b25DQURWRTM2LmNydDAjBggrBgEFBQcwAYYXaHR0cDovL29jc3Auc2VjdGlnby5jb20wJQY"
    "DVR0RBB4wHIIKZ2l0aHViLmNvbYIOd3d3LmdpdGh1Yi5jb20wggEMBgorBgEEAdZ5AgQCB"
    "IH9BIH6APgAdQBGojlnxg22RofGbz35mZR2k6amESCEV9VV5+PQodm2RgAAAaGKLocgAAAEA"
    "wBGMEQCICIQbbpOkqdkpMHlEO4IaqjUE51GdnAX8lTdfJqayeUyAiBW+rfEnQghzD2sljP8"
    "DmiE364OeNXjRLnoS4/+EDmBMQB/AKKBABhzThduHUfglUDzgbpUZpfNY6hDUHFuuAlO2vEN"
    "AAABoYouiCYACAAABQAyHujyBAMASDBGAiEAqR77xK7WOstHFrsyltQlPHqO5UAlaD5EUGgf"
    "V+SyHngCIQCTdXIrVaNFlwq2jVoU6eq3LTDtgBbBB8AS6pKHuIF94DAKBggqhkjOPQQDAgNH"
    "ADBEAiAiIVULRbVeXo166wK3Vp15eud/nlbNTa+j4FUnKD6GYAIgBcK3WmeV05N87KRIoaIV"
    "/h97FykBOCulKBsCT9qemhg="
)
_GITHUB_DER = base64.b64decode(_GITHUB_DER_B64)


def _fake_sock(*, empty_dict: bool, der: bytes | None):
    sock = MagicMock()
    sock.getpeercert.side_effect = (lambda binary_form=False: (
        {} if (empty_dict and not binary_form) else (der if binary_form else {})
    ))
    return sock


def test_cert_none_mode_still_yields_cert_content():
    """CERT_NONE 下 getpeercert() 为空时，必须从 DER 解出 CN/SAN。"""
    sock = _fake_sock(empty_dict=True, der=_GITHUB_DER)
    cert = _peercert_dict(sock)
    info = _extract_cert(cert, "github.com")
    assert info["cn"] == "github.com"
    assert "github.com" in info["san"]
    assert info["cert_match"] is True


def test_normal_mode_prefers_parsed_dict():
    """严格模式下已有字典时，不应再走 DER 解码。"""
    parsed = {"subject": (), "subjectAltName": (("DNS", "example.com"),)}
    sock = MagicMock()
    sock.getpeercert.return_value = parsed
    assert _peercert_dict(sock) is parsed
    sock.getpeercert.assert_called_once_with()


def test_no_cert_returns_empty():
    """拿不到任何证书时安全返回空字典。"""
    sock = _fake_sock(empty_dict=True, der=None)
    assert _peercert_dict(sock) == {}


def test_malformed_der_does_not_raise():
    """DER 损坏不能让探测崩掉，返回空即可。"""
    sock = _fake_sock(empty_dict=True, der=b"\x30\x03\x01\x01\xff")
    assert _peercert_dict(sock) == {}


def test_real_der_decodes_expected_fields():
    """固定样本本身有效，防止样本损坏导致测试假通过。"""
    pem = ssl.DER_cert_to_PEM_cert(_GITHUB_DER)
    assert "BEGIN CERTIFICATE" in pem
