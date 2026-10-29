# -*- coding: utf-8 -*-
"""网络探测层：TCP / TLS / HTTP。

相对 v1.0 的关键改动：
    1. TCP 区分 refused / timeout / reset / unreachable（v1.0 只有 bool）
    2. TLS 区分"握手被切断"和"握手报错" —— SNI 层封锁的典型特征是
       ClientHello 发出后被 RST 或 EOF，必须与普通 TLS 错误分开
    3. 证书链不可信时降级重试，只取证书内容判 SAN（自签站点也能判真身）
    4. SAN 匹配按 RFC 6125 实现，通配符不跨域（v1.0 有可跨域命中的 bug）
    5. HTTP 只读到 header 结束，明确区分 NO_RESPONSE / MALFORMED / REJECT
       （v1.0 把"一个字节都没收到"当成"服务端拒绝"，误报成反爬）
    6. HTTP 支持经代理 CONNECT 隧道，用于双路径对照
"""
from __future__ import annotations

import re
import socket
import ssl
import time
from collections.abc import Iterable
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Optional

from . import proxy as proxymod
from .models import HttpResult, HttpStatus, ProxyInfo, TcpStatus, TlsResult, TlsStatus

DEFAULT_TIMEOUT = 8.0
# 分层超时：TCP 握手正常在 200ms 内完成，给 8 秒纯属浪费；
# HTTP 等待首字节可以稍长，但也不该和 TLS 共用同一个宽松上限。
# TLS 单独设上限：握手超过 6 秒基本可判定链路不通（或正被中途切断），
# 再等下去只会让"整站打不开"这类最坏场景越拖越久。
TCP_TIMEOUT_CAP = 4.0
TLS_TIMEOUT_CAP = 6.0
HTTP_TIMEOUT_CAP = 6.0
# 代理对照只是"旁证"：能用的代理 1~2 秒就回包了，等满 6 秒毫无意义，
# 却会让"整站打不开"的最坏耗时再多一截。
PROXY_TIMEOUT_CAP = 4.0
HEADER_LIMIT = 64 * 1024          # 防御超大响应头
BODY_SAMPLE = 16 * 1024           # 只读这么多 body 用于提取 title
BODY_TIMEOUT = 1.5                # body 是"锦上添花"，不许多等

_BLOCK_HINTS = ("eof", "reset", "broken pipe", "connection aborted")


# ---------------------------------------------------------------- 证书匹配

def cert_matches(host: str, san: Iterable[str]) -> bool:
    """RFC 6125 主机名匹配。

    通配符 `*.example.com` 只匹配**最左一级**标签，且必须有分隔点：
        www.example.com   -> 匹配
        example.com       -> 不匹配（通配至少需要一个标签）
        evilexample.com   -> 不匹配（v1.0 的 endswith("example.com") 会误判为匹配）
        a.b.example.com   -> 不匹配（跨了多级）
    """
    host = host.lower().rstrip(".")
    if not host:
        return False
    for raw in san:
        name = str(raw).lower().rstrip(".")
        if not name:
            continue
        if name.startswith("*."):
            suffix = name[2:]
            if "." not in host:
                continue
            label, _, rest = host.partition(".")
            if label and rest == suffix:
                return True
        elif host == name:
            return True
    return False


# ---------------------------------------------------------------- SSL 上下文

def _make_context(verify: bool = True,
                  alpn: Optional[list[str]] = None) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if verify:
        ctx.check_hostname = False      # 自己按 SAN 判，才能拿到不匹配时的证书内容
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if alpn:
        try:
            ctx.set_alpn_protocols(alpn)
        except NotImplementedError:
            pass
    return ctx


def _connect(ip: str, port: int, timeout: float,
             proxy_info: Optional[ProxyInfo] = None) -> socket.socket:
    """建立到 ip:port 的连接。指定代理时走 CONNECT 隧道。

    隧道目标是 **IP** 而不是域名：这样"经代理"与"直连"测的是同一个 IP，
    两者才是严格对照。域名只用于 TLS 的 SNI（server_hostname）。
    """
    if proxy_info and proxy_info.present and proxymod.can_tunnel(proxy_info):
        return proxymod.open_tunnel(proxy_info, ip, port, timeout)
    return socket.create_connection((ip, port), timeout=timeout)


def _days_left(not_after: str) -> Optional[int]:
    if not not_after:
        return None
    try:
        dt = parsedate_to_datetime(not_after)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (dt - datetime.now(timezone.utc)).days
    except (TypeError, ValueError):
        return None


def _extract_cert(cert: dict, host: str) -> dict:
    cn = ""
    for rdn in cert.get("subject", ()):
        for key, val in rdn:
            if key == "commonName":
                cn = val
    san = [val for _kind, val in cert.get("subjectAltName", ())]
    not_after = cert.get("notAfter", "")
    return {
        "cn": cn,
        "san": san,
        "cert_match": cert_matches(host, san) if san else None,
        "not_after": not_after,
        "days_left": _days_left(not_after),
    }


def _handshake(ip: str, host: str, port: int, timeout: float,
               verify: bool, proxy_info: Optional[ProxyInfo]) -> TlsResult:
    """执行一次 TLS 握手。异常在调用方统一归类。"""
    ctx = _make_context(verify=verify, alpn=["h2", "http/1.1"])
    t0 = time.perf_counter()
    sock = _connect(ip, port, timeout, proxy_info)
    try:
        with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
            cert = tls_sock.getpeercert() or {}
            info = _extract_cert(cert, host)
            cipher = tls_sock.cipher() or ("", "", 0)
            try:
                alpn = tls_sock.selected_alpn_protocol() or ""
            except (AttributeError, ValueError):
                alpn = ""
            return TlsResult(
                status=TlsStatus.OK,
                cn=info["cn"],
                san=info["san"],
                cert_match=info["cert_match"],
                version=tls_sock.version() or "",
                alpn=alpn,
                cipher=cipher[0] or "",
                not_after=info["not_after"],
                days_left=info["days_left"],
                chain_trusted=verify,
                ms=(time.perf_counter() - t0) * 1000,
            )
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _classify_tls_error(exc: BaseException, ms: float) -> TlsResult:
    """把异常归类成 TlsStatus。这一步决定了"SNI 被切断"能否被识别出来。"""
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return TlsResult(status=TlsStatus.BLOCKED, ms=ms,
                         detail="TLS 握手超时（TCP 已连通，无响应）")
    if isinstance(exc, ConnectionResetError):
        return TlsResult(status=TlsStatus.BLOCKED, ms=ms,
                         detail="握手过程中连接被重置（RST）")
    if isinstance(exc, (ssl.SSLEOFError, ssl.SSLZeroReturnError)):
        return TlsResult(status=TlsStatus.BLOCKED, ms=ms,
                         detail="握手过程中连接被对端关闭（EOF）")
    if isinstance(exc, ssl.SSLError):
        text = str(exc).lower()
        if any(hint in text for hint in _BLOCK_HINTS):
            return TlsResult(status=TlsStatus.BLOCKED, ms=ms,
                             detail="握手被中断：%s" % str(exc)[:60])
        return TlsResult(status=TlsStatus.ERROR, ms=ms,
                         detail="TLS 错误：%s" % str(exc)[:60])
    if isinstance(exc, ConnectionRefusedError):
        return TlsResult(status=TlsStatus.ERROR, ms=ms, detail="连接被拒绝")
    return TlsResult(status=TlsStatus.ERROR, ms=ms,
                     detail="不可达：%s" % str(exc)[:60])


def tls_probe(ip: str, host: str, port: int = 443,
              timeout: float = DEFAULT_TIMEOUT,
              proxy_info: Optional[ProxyInfo] = None) -> TlsResult:
    """探测 TLS，并判定该 IP 是否真的属于目标站。

    两轮策略：
        第一轮严格校验 —— 拿到 SAN + 确认证书链可信
        链不可信时第二轮用 CERT_NONE 重试 —— 只取证书内容判 SAN
    v1.0 在第一轮失败就直接放弃，导致自签 / 私有 CA 站点无法判定真身。
    """
    t0 = time.perf_counter()
    try:
        result = _handshake(ip, host, port, timeout, verify=True, proxy_info=proxy_info)
        result.status = TlsStatus.OK
        return result
    except ssl.SSLCertVerificationError as exc:
        # 链校验失败：降级重试，只为拿到证书内容
        try:
            fallback = _handshake(ip, host, port, timeout, verify=False,
                                  proxy_info=proxy_info)
        except Exception as exc2:                  # noqa: BLE001 - 降级也失败，按原错误归类
            return _classify_tls_error(exc2, (time.perf_counter() - t0) * 1000)
        fallback.chain_trusted = False
        fallback.chain_error = str(exc)[:100]
        fallback.status = (TlsStatus.OK if fallback.cert_match
                           else TlsStatus.CERT_MISMATCH)
        return fallback
    except Exception as exc:                       # noqa: BLE001 - 统一归类
        return _classify_tls_error(exc, (time.perf_counter() - t0) * 1000)


# ---------------------------------------------------------------- TCP

def tcp_probe(ip: str, port: int = 443, timeout: float = DEFAULT_TIMEOUT,
              proxy_info: Optional[ProxyInfo] = None) -> tuple[TcpStatus, float]:
    t0 = time.perf_counter()
    try:
        sock = _connect(ip, port, timeout, proxy_info)
        sock.close()
        return TcpStatus.OK, (time.perf_counter() - t0) * 1000
    except ConnectionRefusedError:
        return TcpStatus.REFUSED, (time.perf_counter() - t0) * 1000
    except ConnectionResetError:
        return TcpStatus.RESET, (time.perf_counter() - t0) * 1000
    except TimeoutError:
        return TcpStatus.TIMEOUT, (time.perf_counter() - t0) * 1000
    except OSError:
        return TcpStatus.UNREACHABLE, (time.perf_counter() - t0) * 1000


# ---------------------------------------------------------------- HTTP

_STATUS_RE = re.compile(rb"HTTP/(\d\.\d)\s+(\d{3})(?:\s+([^\r\n]*))?")
_LOCATION_RE = re.compile(rb"(?im)^location:\s*(\S+)")
_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)


def _read_until_header_end(sock: socket.socket, limit: int = HEADER_LIMIT) -> tuple[bytes, bool]:
    """读到 header 结束。返回 (数据, 是否读到 header 结束)。"""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(8192)
        if not chunk:
            return buf, False
        buf += chunk
        if len(buf) >= limit:
            return buf, False
    return buf, True


def _read_body_sample(sock: socket.socket, already: bytes,
                      limit: int = BODY_SAMPLE) -> bytes:
    """读少量 body 用于提取 title。超时就放弃 —— 不影响结论。"""
    buf = already
    try:
        sock.settimeout(BODY_TIMEOUT)
        while len(buf) < limit:
            chunk = sock.recv(8192)
            if not chunk:
                break
            buf += chunk
            if _TITLE_RE.search(buf):
                break
    except (TimeoutError, OSError):
        pass
    return buf[:limit]


def http_probe(ip: str, host: str, path: str = "/", port: int = 443,
               timeout: float = DEFAULT_TIMEOUT,
               proxy_info: Optional[ProxyInfo] = None,
               use_proxy: bool = False) -> HttpResult:
    """发一个最小 HTTP/1.1 请求，判定 HTTP 层到底通不通。

    四种结果严格区分：
        OK          拿到 2xx/3xx
        REJECT      拿到合法状态行，但 4xx/5xx —— 服务端拒绝，链路是通的
        NO_RESPONSE 一个字节都没收到 —— 链路层不通，绝不是"反爬"
        MALFORMED   收到数据但不是合法 HTTP 响应
    """
    via = "proxy" if use_proxy else "direct"
    active_proxy = proxy_info if use_proxy else None
    t0 = time.perf_counter()

    try:
        sock = _connect(ip, port, timeout, active_proxy)
    except (TimeoutError, OSError) as exc:
        return HttpResult(status=HttpStatus.NO_RESPONSE, via=via,
                          total_ms=(time.perf_counter() - t0) * 1000,
                          detail="连接失败：%s" % str(exc)[:60])

    try:
        ctx = _make_context(verify=False, alpn=["http/1.1"])
        try:
            tls_sock = ctx.wrap_socket(sock, server_hostname=host)
        except (ssl.SSLError, OSError) as exc:
            return HttpResult(status=HttpStatus.NO_RESPONSE, via=via,
                              total_ms=(time.perf_counter() - t0) * 1000,
                              detail="TLS 建立失败：%s" % str(exc)[:60])

        with tls_sock:
            request = ("GET %s HTTP/1.1\r\n"
                       "Host: %s\r\n"
                       "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36\r\n"
                       "Accept: text/html,application/xhtml+xml,*/*;q=0.8\r\n"
                       "Accept-Language: zh-CN,zh;q=0.9,en;q=0.8\r\n"
                       "Accept-Encoding: identity\r\n"
                       "Connection: close\r\n\r\n" % (path, host))
            try:
                tls_sock.settimeout(timeout)
                tls_sock.sendall(request.encode("latin-1"))
            except (TimeoutError, OSError) as exc:
                return HttpResult(status=HttpStatus.NO_RESPONSE, via=via,
                                  total_ms=(time.perf_counter() - t0) * 1000,
                                  detail="请求发送失败：%s" % str(exc)[:60])

            try:
                raw, header_done = _read_until_header_end(tls_sock)
            except (TimeoutError, OSError) as exc:
                return HttpResult(status=HttpStatus.NO_RESPONSE, via=via,
                                  total_ms=(time.perf_counter() - t0) * 1000,
                                  detail="等待响应超时：%s" % str(exc)[:60])

            ttfb = (time.perf_counter() - t0) * 1000

            if not raw:
                return HttpResult(status=HttpStatus.NO_RESPONSE, via=via,
                                  ttfb_ms=ttfb, total_ms=ttfb,
                                  detail="连接建立后未收到任何字节")

            match = _STATUS_RE.match(raw)
            if not match:
                return HttpResult(status=HttpStatus.MALFORMED, via=via,
                                  ttfb_ms=ttfb, total_ms=ttfb,
                                  bytes_read=len(raw),
                                  detail="响应首行不是合法 HTTP 状态行：%r"
                                         % raw[:60])

            code = int(match.group(2))
            head, _, rest = raw.partition(b"\r\n\r\n")

            location = ""
            loc_match = _LOCATION_RE.search(head)
            if loc_match:
                location = loc_match.group(1).decode("latin-1", "replace")

            title = ""
            body = _read_body_sample(tls_sock, rest)
            title_match = _TITLE_RE.search(body)
            if title_match:
                title = title_match.group(1).decode("utf-8", "replace").strip()
                title = re.sub(r"\s+", " ", title)[:80]

            status = HttpStatus.OK if 200 <= code < 400 else HttpStatus.REJECT
            detail = ""
            if not header_done:
                detail = "响应头未完整结束（连接提前关闭）"

            return HttpResult(
                status=status, code=code, location=location, title=title,
                bytes_read=len(raw) + len(rest),
                ttfb_ms=ttfb, total_ms=(time.perf_counter() - t0) * 1000,
                via=via, detail=detail,
            )
    except Exception as exc:                       # noqa: BLE001 - 兜底，绝不抛给调用方
        return HttpResult(status=HttpStatus.MALFORMED, via=via,
                          total_ms=(time.perf_counter() - t0) * 1000,
                          detail="未预期错误：%s" % str(exc)[:60])


# ---------------------------------------------------------------- 组合

def probe_ip(ip: str, host: str, timeout: float = DEFAULT_TIMEOUT,
             proxy_info: Optional[ProxyInfo] = None,
             skip_tcp: bool = False) -> dict:
    """对单个 IP 做 TCP → TLS → HTTP 流水探测。

    skip_tcp=True 表示调用方已经确认过 TCP 可达（两阶段探测里的阶段 B），
    不要再测一遍 —— 重复探测既浪费一次超时窗口，又可能因为网络抖动
    得到与阶段 A 相反的结论，导致 TLS 阶段被无谓跳过。

    代理对照不在这里做：那属于整体判定需要的一次额外验证，
    由 orchestrator 在拿到全部结果后对单个 IP 执行一次即可。
    """
    family = 6 if ":" in ip else 4
    if skip_tcp:
        tcp_status, tcp_ms = TcpStatus.OK, 0.0
    else:
        tcp_status, tcp_ms = tcp_probe(ip, 443, min(timeout, TCP_TIMEOUT_CAP))

    result = {
        "ip": ip,
        "family": family,
        "tcp": tcp_status,
        "tcp_ms": tcp_ms,
        "tls": None,
        "http": None,
        "http_proxy": None,
    }
    if tcp_status is not TcpStatus.OK:
        return result

    tls = tls_probe(ip, host, 443, min(timeout, TLS_TIMEOUT_CAP), proxy_info=None)
    result["tls"] = tls

    if tls.handshake_ok and tls.cert_match:
        result["http"] = http_probe(ip, host, timeout=min(timeout, HTTP_TIMEOUT_CAP),
                                    use_proxy=False)
    return result
