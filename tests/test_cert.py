# -*- coding: utf-8 -*-
"""证书 SAN 匹配回归测试。

这里的每一条都是 v1.0 的实测反例：
    v1.0 用 host.endswith(x[2:]) 判断通配符，丢掉了点，
    于是 evilexample.com 会被 *.example.com 命中。
"""
from __future__ import annotations

import pytest

from sitecheck.probe import cert_matches


@pytest.mark.parametrize("host,san,expected", [
    # 精确匹配
    ("example.com", ["example.com"], True),
    ("www.example.com", ["www.example.com"], True),
    ("example.com", ["www.example.com"], False),
    # 通配符：只匹配最左一级
    ("www.example.com", ["*.example.com"], True),
    ("a.example.com", ["*.example.com"], True),
    ("example.com", ["*.example.com"], False),        # 通配至少需要一个标签
    ("a.b.example.com", ["*.example.com"], False),    # 跨多级，不匹配
    # v1.0 的三个误判反例
    ("evilexample.com", ["*.example.com"], False),
    ("notexample.com", ["*.example.com"], False),
    ("myexample.com", ["*.example.com"], False),
    # 大小写与尾点
    ("WWW.Example.COM", ["*.example.com"], True),
    ("example.com.", ["example.com"], True),
    ("example.com", ["*.example.com."], False),
    # 多 SAN
    ("x.com", ["y.com", "x.com"], True),
    ("x.com", ["y.com", "z.com"], False),
    # 空与异常输入
    ("example.com", [], False),
    ("", ["example.com"], False),
    ("example.com", [""], False),
    # IP 字面量
    ("1.2.3.4", ["1.2.3.4"], True),
    ("1.2.3.4", ["*.3.4"], False),
])
def test_cert_matches(host: str, san: list[str], expected: bool):
    assert cert_matches(host, san) is expected


def test_wildcard_does_not_cross_label():
    """v1.0 的具体 bug：后缀匹配没有边界，能跨域命中。"""
    assert not cert_matches("evilexample.com", ["*.example.com"])
    assert not cert_matches("notexample.com", ["*.example.com"])


def test_wildcard_requires_subdomain():
    """*.example.com 不应该匹配裸域 example.com。"""
    assert not cert_matches("example.com", ["*.example.com"])
