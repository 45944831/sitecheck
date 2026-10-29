# -*- coding: utf-8 -*-
"""DNS 报文解析测试。

用构造的报文覆盖 v1.0 会出错的三类情况：
    1. 名字里"标签 + 压缩指针"混合 —— v1.0 会跳过 0xC0+1 字节直接越界
    2. TC 截断位 —— v1.0 完全忽略
    3. AAAA 记录 —— v1.0 根本不解析
"""
from __future__ import annotations

import socket
import struct

import pytest

from sitecheck.dns import build_query, parse_response


def _name(text: str) -> bytes:
    out = b""
    for label in text.split("."):
        if label:
            out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def build_response(domain: str = "example.com",
                   answers: list[tuple[int, bytes]] | None = None,
                   rcode: int = 0, truncated: bool = False,
                   answer_names: list[bytes] | None = None) -> bytes:
    """构造一个 DNS 响应报文。answers 为 [(rtype, rdata)]。"""
    answers = answers or []
    flags = 0x8180 | rcode
    if truncated:
        flags |= 0x0200
    pkt = struct.pack(">HHHHHH", 0x1234, flags, 1, len(answers), 0, 0)
    pkt += _name(domain) + struct.pack(">HH", 1, 1)

    for index, (rtype, rdata) in enumerate(answers):
        if answer_names is not None:
            pkt += answer_names[index]
        else:
            pkt += b"\xc0\x0c"                     # 指针回指 question 的名字
        pkt += struct.pack(">HHIH", rtype, 1, 300, len(rdata))
        pkt += rdata
    return pkt


# ---------------------------------------------------------------- A / AAAA

def test_single_a_record():
    parsed = parse_response(build_response(answers=[(1, socket.inet_aton("1.2.3.4"))]))
    assert parsed["ips"] == ["1.2.3.4"]
    assert parsed["ipv6"] == []
    assert parsed["rcode"] == 0


def test_multiple_a_records_dedup_and_sort():
    data = build_response(answers=[
        (1, socket.inet_aton("5.6.7.8")),
        (1, socket.inet_aton("1.2.3.4")),
        (1, socket.inet_aton("5.6.7.8")),
    ])
    assert parse_response(data)["ips"] == ["1.2.3.4", "5.6.7.8"]


def test_aaaa_record():
    raw = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
    parsed = parse_response(build_response(answers=[(28, raw)]))
    assert parsed["ipv6"] == ["2001:db8::1"]
    assert parsed["ips"] == []


def test_mixed_a_and_aaaa():
    data = build_response(answers=[
        (1, socket.inet_aton("1.2.3.4")),
        (28, socket.inet_pton(socket.AF_INET6, "2001:db8::1")),
    ])
    parsed = parse_response(data)
    assert parsed["ips"] == ["1.2.3.4"]
    assert parsed["ipv6"] == ["2001:db8::1"]


# ---------------------------------------------------------------- 状态位

def test_nxdomain():
    parsed = parse_response(build_response(rcode=3))
    assert parsed["rcode"] == 3
    assert parsed["ips"] == []


def test_truncated_flag():
    parsed = parse_response(build_response(truncated=True))
    assert parsed["truncated"] is True


def test_no_answer_is_not_error():
    parsed = parse_response(build_response())
    assert parsed["rcode"] == 0
    assert parsed["ips"] == []


# ---------------------------------------------------------------- 名字压缩

def test_cname_then_a():
    """CNAME 在前、A 在后，最终 A 必须被取到。"""
    cname_target = _name("cdn.example.net")
    data = build_response(answers=[(5, cname_target), (1, socket.inet_aton("9.9.9.9"))])
    parsed = parse_response(data)
    assert parsed["ips"] == ["9.9.9.9"]


def test_mixed_label_and_pointer_name():
    """answer 名字是 "www" + 指针 —— v1.0 在这里会错位到越界。"""
    mixed = b"\x03www\xc0\x0c"
    data = build_response(domain="example.com",
                          answers=[(1, socket.inet_aton("1.2.3.4"))],
                          answer_names=[mixed])
    parsed = parse_response(data)
    assert parsed["ips"] == ["1.2.3.4"]


def test_pointer_loop_does_not_hang():
    """自指指针必须被防环检测拦住，不能死循环。"""
    pkt = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    pkt += b"\xc0\x0c" + struct.pack(">HH", 1, 1)   # question 自己指向自己
    pkt += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 300, 4) + socket.inet_aton("1.2.3.4")
    parsed = parse_response(pkt)                     # 不抛异常、不死循环即可
    assert isinstance(parsed["ips"], list)


# ---------------------------------------------------------------- 畸形报文

def test_short_packet_raises():
    with pytest.raises(ValueError):
        parse_response(b"\x00\x01")


def test_truncated_rdata_does_not_crash():
    """声明 rdlen=4 但只给了 2 字节，必须安全退出。"""
    pkt = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    pkt += _name("a.test") + struct.pack(">HH", 1, 1)
    pkt += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 300, 4) + b"\x01\x02"
    parsed = parse_response(pkt)
    assert parsed["ips"] == []


# ---------------------------------------------------------------- 查询构造

def test_build_query_structure():
    query = build_query("example.com", qtype=1, tid=0x1234)
    assert struct.unpack(">H", query[:2])[0] == 0x1234
    assert query[12:12 + 13] == _name("example.com")[:13]
    qtype = struct.unpack(">H", query[-4:-2])[0]
    qclass = struct.unpack(">H", query[-2:])[0]
    assert qtype == 1
    assert qclass == 1


def test_build_query_aaaa():
    query = build_query("example.com", qtype=28)
    assert struct.unpack(">H", query[-4:-2])[0] == 28
