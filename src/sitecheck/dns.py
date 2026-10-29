# -*- coding: utf-8 -*-
"""DNS 解析层：UDP / TCP 回退 / DoH。

相对 v1.0 的改动：
    1. 同时查询 A 和 AAAA（v1.0 只查 A，IPv6-only 站点完全漏判）
    2. 正确处理压缩指针（v1.0 遇到"标签+指针"混合的名字会错位）
    3. 处理 TC 截断位，回退到 TCP
    4. 区分 NXDOMAIN / EMPTY / TIMEOUT / ERROR（v1.0 一律当"无记录"）
    5. DoH 强制禁用代理 —— v1.0 的 urllib 会读 HTTPS_PROXY 走代理，
       而 UDP DNS 走裸网，两者不可比，导致"是否污染"的判断失真
"""
from __future__ import annotations

import base64
import random
import socket
import struct
import time
import urllib.error
import urllib.request

from .models import DnsResult, DnsStatus

QTYPE_A = 1
QTYPE_AAAA = 28

UDP_RESOLVERS: list[tuple[str, str]] = [
    ("223.5.5.5", "阿里"),
    ("119.29.29.29", "腾讯"),
    ("114.114.114.114", "114"),
    ("180.76.76.76", "百度"),
    ("1.1.1.1", "Cloudflare"),
    ("8.8.8.8", "Google"),
]

# IP 形式的端点排在最前：系统 DNS 被污染时，域名形式的 DoH 连不上，
# 但 IP 形式不需要先解析，是唯一能自救的通道。
DOH_ENDPOINTS: list[tuple[str, str]] = [
    ("https://223.5.5.5/dns-query", "DoH 阿里 IP"),
    ("https://dns.alidns.com/dns-query", "DoH 阿里"),
    ("https://doh.pub/dns-query", "DoH 腾讯"),
]


# ---------------------------------------------------------------- wire 编解码

def build_query(host: str, qtype: int = QTYPE_A, tid: int | None = None) -> bytes:
    """构造 DNS 查询报文。"""
    tid = random.randint(0, 65535) if tid is None else tid
    pkt = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    for label in host.rstrip(".").encode("idna").split(b"."):
        if not label:
            continue
        pkt += bytes([len(label)]) + label
    return pkt + b"\x00" + struct.pack(">HH", qtype, 1)


def _read_name(data: bytes, off: int) -> tuple[str, int]:
    """读取一个 DNS 名字，返回 (name, 下一个位置的偏移)。

    必须处理压缩指针：报文里同名的后缀只存一次，其余位置用 2 字节指针回指。
    v1.0 的实现假设"要么全是标签、要么全是指针"，遇到混合形态会错位。
    """
    labels: list[str] = []
    jumped = False
    resume = off
    seen: set[int] = set()

    while 0 <= off < len(data):
        length = data[off]
        if length == 0:
            off += 1
            break
        if length & 0xC0 == 0xC0:                 # 压缩指针
            if off + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[off + 1]
            if not jumped:
                resume = off + 2
                jumped = True
            if ptr in seen or ptr >= len(data):   # 防环
                break
            seen.add(ptr)
            off = ptr
            continue
        if length & 0xC0:                         # 保留位，非法
            break
        off += 1
        if off + length > len(data):
            break
        labels.append(data[off:off + length].decode("latin-1"))
        off += length

    return ".".join(labels), (resume if jumped else off)


def parse_response(data: bytes) -> dict:
    """解析 DNS 响应，返回 rcode / truncated / ips / ipv6。"""
    if len(data) < 12:
        raise ValueError("响应过短（%d 字节）" % len(data))

    _tid, flags, qdcount, ancount, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
    rcode = flags & 0x000F
    truncated = bool(flags & 0x0200)

    off = 12
    for _ in range(qdcount):
        _name, off = _read_name(data, off)
        off += 4                                   # QTYPE + QCLASS

    ips: list[str] = []
    ipv6: list[str] = []
    for _ in range(ancount):
        if off >= len(data):
            break
        _name, off = _read_name(data, off)
        if off + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        if off + rdlen > len(data):               # 报文被截断，rdata 不完整
            break
        rdata = data[off:off + rdlen]
        off += rdlen

        if rtype == QTYPE_A and rdlen == 4:
            ips.append(socket.inet_ntoa(rdata))
        elif rtype == QTYPE_AAAA and rdlen == 16:
            try:
                ipv6.append(socket.inet_ntop(socket.AF_INET6, rdata))
            except OSError:
                pass
        # CNAME / NS 等记录跳过：只要最终解析出的 A/AAAA

    return {
        "rcode": rcode,
        "truncated": truncated,
        "ips": sorted(set(ips)),
        "ipv6": sorted(set(ipv6)),
    }


def _status_from(rcode: int, ips: list[str], ipv6: list[str]) -> DnsStatus:
    if rcode == 3:
        return DnsStatus.NXDOMAIN
    if rcode != 0:
        return DnsStatus.ERROR
    if ips or ipv6:
        return DnsStatus.OK
    return DnsStatus.EMPTY


# ---------------------------------------------------------------- UDP / TCP

def udp_query(host: str, server: str, qtype: int = QTYPE_A,
              timeout: float = 4.0) -> tuple[list[str], list[str], int, bool, float]:
    """返回 (ips, ipv6, rcode, truncated, ms)。失败时 rcode=-1。"""
    packet = build_query(host, qtype)
    t0 = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server, 53))
        data, _ = sock.recvfrom(4096)
        parsed = parse_response(data)
        ms = (time.perf_counter() - t0) * 1000
        return (parsed["ips"], parsed["ipv6"], parsed["rcode"],
                parsed["truncated"], ms)
    except TimeoutError:
        return [], [], -1, False, (time.perf_counter() - t0) * 1000
    except OSError:
        return [], [], -1, False, (time.perf_counter() - t0) * 1000
    except ValueError:
        return [], [], -2, False, (time.perf_counter() - t0) * 1000
    finally:
        sock.close()


def tcp_query(host: str, server: str, qtype: int = QTYPE_A,
              timeout: float = 4.0) -> tuple[list[str], list[str], int]:
    """TCP 回退：UDP 被截断（TC 位）时用。DNS over TCP 有 2 字节长度前缀。"""
    packet = build_query(host, qtype)
    try:
        with socket.create_connection((server, 53), timeout=timeout) as sock:
            sock.sendall(struct.pack(">H", len(packet)) + packet)
            head = _recv_exact(sock, 2)
            if not head:
                return [], [], -1
            length = struct.unpack(">H", head)[0]
            data = _recv_exact(sock, length)
            if not data:
                return [], [], -1
            parsed = parse_response(data)
            return parsed["ips"], parsed["ipv6"], parsed["rcode"]
    except (OSError, ValueError):
        return [], [], -1


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def query_server(server: str, name: str, host: str,
                 timeout: float = 4.0) -> DnsResult:
    """向单个 DNS 服务器查 A（必要时查 AAAA），返回结构化结果。"""
    ips, ipv6, rcode, truncated, ms = udp_query(host, server, QTYPE_A, timeout)

    if truncated:                                  # UDP 装不下，走 TCP
        t_ips, t_ipv6, t_rcode = tcp_query(host, server, QTYPE_A, timeout)
        if t_ips or t_ipv6:
            ips, ipv6, rcode = t_ips, t_ipv6, t_rcode

    # A 拿到了才查 AAAA：A 都不通说明这台服务器整体不可用，再查是浪费时间
    if rcode == 0:
        a6, v6, rc6, _tc6, ms6 = udp_query(host, server, QTYPE_AAAA, timeout)
        if rc6 == 0:
            ipv6 = sorted(set(ipv6 + v6))
            ms = max(ms, ms6)

    if rcode == -1:
        status = DnsStatus.TIMEOUT
    elif rcode < 0:
        status = DnsStatus.ERROR
    else:
        status = _status_from(rcode, ips, ipv6)

    return DnsResult(server=server, name=name, status=status, ips=ips,
                     ipv6=ipv6, ms=ms, rcode=rcode, transport="udp")


# ---------------------------------------------------------------- DoH

def _no_proxy_opener() -> urllib.request.OpenerDirector:
    """强制不走代理的 opener。

    v1.0 直接 urlopen，会读 HTTPS_PROXY 环境变量 —— 于是 DoH 走代理、
    UDP DNS 走裸网，两者网络路径不同，却被拿来互相校验"是否污染"。
    """
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


_DOH_OPENER = _no_proxy_opener()


def doh_query(endpoint: str, name: str, host: str,
              qtype: int = QTYPE_A, timeout: float = 8.0) -> tuple[list[str], list[str], int, float, str]:
    """RFC 8484 DoH（GET + base64url，无填充）。返回 (ips, ipv6, rcode, ms, error)。"""
    query = build_query(host, qtype)
    encoded = base64.urlsafe_b64encode(query).decode().rstrip("=")
    url = endpoint + "?dns=" + encoded
    req = urllib.request.Request(url, headers={
        "accept": "application/dns-message",
        "user-agent": "sitecheck/2.0",
    })
    t0 = time.perf_counter()
    try:
        with _DOH_OPENER.open(req, timeout=timeout) as resp:
            data = resp.read()
        parsed = parse_response(data)
        ms = (time.perf_counter() - t0) * 1000
        return parsed["ips"], parsed["ipv6"], parsed["rcode"], ms, ""
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return [], [], -1, (time.perf_counter() - t0) * 1000, str(exc)[:80]


def query_doh(endpoint: str, name: str, host: str,
              timeout: float = 8.0) -> DnsResult:
    ips, ipv6, rcode, ms, err = doh_query(endpoint, name, host, QTYPE_A, timeout)
    if rcode == 0:
        a6, v6, rc6, ms6, _err6 = doh_query(endpoint, name, host, QTYPE_AAAA, timeout)
        if rc6 == 0:
            ipv6 = sorted(set(ipv6 + v6))
            ms = max(ms, ms6)

    if rcode == -1:
        status = DnsStatus.TIMEOUT if "timed out" in err.lower() else DnsStatus.ERROR
    elif rcode < 0:
        status = DnsStatus.ERROR
    else:
        status = _status_from(rcode, ips, ipv6)

    return DnsResult(server=endpoint, name=name, status=status, ips=ips,
                     ipv6=ipv6, ms=ms, rcode=rcode, transport="doh", error=err)


# ---------------------------------------------------------------- 系统解析

def system_resolve(host: str) -> list[str]:
    """走本机解析栈（会读 hosts）。

    仅用于给报告提供"系统实际返回什么"的参照 —— 判定真身不依赖它。
    """
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, OSError):
        return []
    out: list[str] = []
    for info in infos:
        addr = info[4][0]
        if addr not in out:
            out.append(addr)
    return out
