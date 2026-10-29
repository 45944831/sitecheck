# -*- coding: utf-8 -*-
"""系统代理探测。

为什么需要这一层：
    v1.0 全程用裸 socket 直连，而用户的浏览器走系统代理 / PAC。
    在必须经代理出网的环境里，工具必然报"不通"，而浏览器一切正常 ——
    结论与用户实际体验完全相反。README 里"结论和用户实际体验冲突时，
    先怀疑工具"这句告诫，必须由代码兑现。

探测顺序（按"浏览器实际会用什么"排序）：
    1. WinINET 注册表（IE / Edge / Chrome 在 Windows 上都读这里）
    2. PAC 自动配置脚本
    3. 环境变量（命令行工具、curl、pip 用）
"""
from __future__ import annotations

import os
import re
import socket

from .models import ProxyInfo, ProxyKind

_REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

_ENV_KEYS = ("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY")


def _parse_proxy_server(raw: str) -> str:
    """ProxyServer 可能是 "127.0.0.1:8080"，也可能是
    "http=1.2.3.4:8080;https=1.2.3.4:8080"。取 https（HTTPS 探测用）。"""
    raw = (raw or "").strip()
    if not raw:
        return ""
    if "=" not in raw:
        return raw
    mapping: dict[str, str] = {}
    for part in raw.split(";"):
        if "=" in part:
            scheme, _, addr = part.partition("=")
            mapping[scheme.strip().lower()] = addr.strip()
    return mapping.get("https") or mapping.get("http") or next(iter(mapping.values()), "")


def _read_wininet() -> ProxyInfo | None:
    if os.name != "nt":
        return None
    try:
        import winreg
    except ImportError:
        return None

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _REG_PATH) as key:
            try:
                enabled = winreg.QueryValueEx(key, "ProxyEnable")[0]
            except OSError:
                enabled = 0
            try:
                pac = winreg.QueryValueEx(key, "AutoConfigURL")[0]
            except OSError:
                pac = ""
            try:
                override = winreg.QueryValueEx(key, "ProxyOverride")[0]
            except OSError:
                override = ""
            try:
                raw = winreg.QueryValueEx(key, "ProxyServer")[0]
            except OSError:
                raw = ""
    except OSError:
        return None

    if enabled and raw:
        addr = _parse_proxy_server(str(raw))
        if addr:
            if "://" not in addr:
                addr = "http://" + addr
            return ProxyInfo(kind=ProxyKind.WININET, url=addr,
                             source="WinINET 系统代理", no_proxy=str(override))
    if pac:
        return ProxyInfo(kind=ProxyKind.PAC, url=str(pac),
                         source="PAC 自动配置", no_proxy=str(override))
    return None


def _read_env() -> ProxyInfo | None:
    for key in _ENV_KEYS:
        val = os.environ.get(key)
        if val and val.strip():
            val = val.strip()
            if "://" not in val:
                val = "http://" + val
            no_proxy = (os.environ.get("no_proxy")
                        or os.environ.get("NO_PROXY") or "")
            return ProxyInfo(kind=ProxyKind.ENV, url=val,
                             source="环境变量 %s" % key, no_proxy=no_proxy)
    return None


def detect() -> ProxyInfo:
    """返回本机最可能生效的代理配置；没有则返回 kind=NONE。"""
    for probe in (_read_wininet, _read_env):
        try:
            info = probe()
        except Exception:
            info = None
        if info and info.present:
            return info
    return ProxyInfo(kind=ProxyKind.NONE)


def detect_all() -> list[ProxyInfo]:
    """返回所有检测到的代理来源（用于报告里完整展示）。"""
    found: list[ProxyInfo] = []
    for probe in (_read_wininet, _read_env):
        try:
            info = probe()
        except Exception:
            info = None
        if info and info.present:
            found.append(info)
    return found


def _match_pattern(host: str, pattern: str) -> bool:
    pattern = pattern.strip().lower()
    if not pattern:
        return False
    if pattern == "<local>":
        return "." not in host
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return host == suffix or host.endswith("." + suffix)
    if pattern.startswith("."):
        suffix = pattern[1:]
        return host == suffix or host.endswith("." + suffix)
    return host == pattern or host.endswith("." + pattern)


def is_bypassed(proxy: ProxyInfo, host: str) -> bool:
    """该主机是否在代理的 bypass 列表里。"""
    if not proxy.no_proxy:
        return False
    host = host.lower()
    for pattern in re.split(r"[;,]", proxy.no_proxy):
        if _match_pattern(host, pattern):
            return True
    return False


def can_tunnel(proxy: ProxyInfo) -> bool:
    """只有 HTTP 代理支持 CONNECT 隧道（PAC 只给了脚本地址，无法直接连）。"""
    return proxy.present and proxy.kind in (ProxyKind.ENV, ProxyKind.WININET)


def open_tunnel(proxy: ProxyInfo, target_host: str, target_port: int = 443,
                timeout: float = 8.0) -> socket.socket:
    """经 HTTP 代理建立 CONNECT 隧道，返回已连通的裸 socket。

    调用方负责在这条隧道上再包 TLS。
    """
    hp = proxy.host_port
    if not hp:
        raise OSError("代理地址无法解析：%r" % proxy.url)
    phost, pport = hp
    sock = socket.create_connection((phost, pport), timeout=timeout)
    try:
        req = ("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n"
               "User-Agent: sitecheck/2.0\r\nProxy-Connection: keep-alive\r\n\r\n"
               % (target_host, target_port, target_host, target_port))
        sock.sendall(req.encode("latin-1"))

        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                raise OSError("代理在 CONNECT 阶段关闭了连接")
            buf += chunk
            if len(buf) > 32 * 1024:
                raise OSError("代理响应头过大")

        status_line = buf.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        match = re.match(r"HTTP/[\d.]+\s+(\d{3})", status_line)
        if not match:
            raise OSError("代理返回非 HTTP 响应：%s" % status_line[:60])
        code = int(match.group(1))
        if code != 200:
            raise OSError("代理拒绝 CONNECT（HTTP %d）" % code)
        return sock
    except Exception:
        sock.close()
        raise
