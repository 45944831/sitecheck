# -*- coding: utf-8 -*-
"""hosts 文件读写。

相对 v1.0 的改动：
    1. 编码检测：v1.0 用 utf-8-sig 读、utf-8 写，原文件里的 GBK 注释会被
       替换成乱码再写回，属于不可逆损坏。现在按原编码写回。
    2. 原子替换：先写临时文件再 os.replace，中途失败不会留下半截 hosts。
    3. 备份移出 etc 目录，改到 %LOCALAPPDATA%\\sitecheck\\backups，并支持还原。
    4. 保留原换行风格（v1.0 一律改成 CRLF，git 管理时整文件 diff）。
    5. IP 参数强校验，拒绝把任意字符串写进 hosts。
"""
from __future__ import annotations

import ipaddress
import os
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

DEFAULT_HOSTS = Path(r"C:\Windows\System32\drivers\etc\hosts")

# 允许测试与特殊部署覆盖路径
HOSTS_PATH = Path(os.environ.get("SITECHECK_HOSTS") or DEFAULT_HOSTS)

_IP_LINE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)\s+(.*)$")
_ENCODINGS = ("utf-8-sig", "utf-8", "gbk", "latin-1")
MAX_BACKUPS = 10


class HostsError(Exception):
    """hosts 操作失败。message 为 NEED_ADMIN 时表示需要提权。"""


# ---------------------------------------------------------------- 路径

def backup_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
    root = Path(base) if base else Path.home() / ".sitecheck"
    return root / "sitecheck" / "backups"


# ---------------------------------------------------------------- 编码

def detect_encoding(raw: bytes) -> str:
    """识别原文件编码，保证写回时不变形。

    必须先单独判 BOM：utf-8-sig 解码器对"无 BOM 的 UTF-8"也能成功，
    如果直接按 _ENCODINGS 顺序试，普通 UTF-8 文件会被误判成 utf-8-sig，
    写回时平白多出一个 BOM。
    """
    if raw.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    for enc in ("utf-8", "gbk", "latin-1"):
        try:
            raw.decode(enc)
            return enc
        except UnicodeDecodeError:
            continue
    return "latin-1"


def read_text(path: Path = HOSTS_PATH) -> tuple[str, str]:
    """返回 (文本, 编码)。"""
    raw = path.read_bytes()
    enc = detect_encoding(raw)
    return raw.decode(enc), enc


def detect_newline(text: str) -> str:
    return "\r\n" if "\r\n" in text else "\n"


# ---------------------------------------------------------------- 解析

def parse_entries(path: Path = HOSTS_PATH) -> list[dict]:
    """解析全部映射条目。忽略注释与非法行。"""
    try:
        text, _enc = read_text(path)
    except OSError:
        return []

    entries: list[dict] = []
    for line_no, raw_line in enumerate(text.splitlines(), 1):
        code = raw_line.split("#", 1)[0].strip()
        if not code:
            continue
        match = _IP_LINE.match(code)
        if not match:
            continue
        ip, names = match.group(1), match.group(2)
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        for name in names.split():
            entries.append({"line": line_no, "ip": ip, "host": name.lower()})
    return entries


def find_entries(domain: str, path: Path = HOSTS_PATH) -> list[tuple[int, str]]:
    """该域名在 hosts 里的条目 [(行号, IP)]。"""
    target = domain.lower()
    return [(e["line"], e["ip"]) for e in parse_entries(path)
            if e["host"] == target]


def _is_mapping_for(line: str, domain: str) -> bool:
    code = line.split("#", 1)[0].strip()
    if not code:
        return False
    parts = code.split()
    if len(parts) < 2:
        return False
    return any(name.lower() == domain.lower() for name in parts[1:])


# ---------------------------------------------------------------- 校验

def validate_ips(ips: list[str]) -> list[str]:
    """强校验：只接受合法 IP，拒绝任何可注入 hosts 的字符串。"""
    out: list[str] = []
    for raw in ips:
        value = str(raw).strip()
        if not value:
            continue
        try:
            out.append(str(ipaddress.ip_address(value)))
        except ValueError:
            raise HostsError("非法 IP 地址：%r（已中止，hosts 未改动）" % value) from None
    if not out:
        raise HostsError("没有可写入的 IP（已中止，hosts 未改动）")
    return out


# ---------------------------------------------------------------- 备份

def backup(path: Path = HOSTS_PATH) -> Path:
    """备份到独立目录，并清理过旧的备份。"""
    target_dir = backup_dir()
    target_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")[:-3]
    dst = target_dir / ("hosts-%s.bak" % stamp)
    shutil.copy2(path, dst)
    _prune_backups(target_dir)
    return dst


def _prune_backups(target_dir: Path) -> None:
    try:
        files = sorted(target_dir.glob("hosts-*.bak"),
                       key=lambda p: p.stat().st_mtime, reverse=True)
        for old in files[MAX_BACKUPS:]:
            old.unlink(missing_ok=True)
    except OSError:
        pass


def list_backups() -> list[Path]:
    target_dir = backup_dir()
    if not target_dir.exists():
        return []
    return sorted(target_dir.glob("hosts-*.bak"),
                  key=lambda p: p.stat().st_mtime, reverse=True)


def restore(backup_path: Path, path: Path = HOSTS_PATH) -> str:
    """从备份还原。还原前会先把当前状态再备份一次，防止还原错了没退路。"""
    if not backup_path.exists():
        raise HostsError("备份文件不存在：%s" % backup_path)
    try:
        safety = backup(path)
    except OSError as exc:
        raise HostsError("还原前备份失败，已中止：%s" % exc) from exc
    try:
        shutil.copy2(backup_path, path)
    except PermissionError:
        raise HostsError("NEED_ADMIN") from None
    except OSError as exc:
        raise HostsError("还原失败：%s" % exc) from exc
    return "已从 %s 还原（还原前的状态备份在 %s）" % (backup_path.name, safety.name)


# ---------------------------------------------------------------- 预演与写入

def plan(domain: str, ips: list[str], path: Path = HOSTS_PATH) -> tuple[list[tuple[int, str]], list[str]]:
    """预演改动：返回 (将被替换的旧行 [(行号, 原文)], 将新增的行)。"""
    try:
        text, _enc = read_text(path)
    except OSError:
        text = ""
    removed = [(no, line.strip())
               for no, line in enumerate(text.splitlines(), 1)
               if _is_mapping_for(line, domain)]
    added = ["%s    %s" % (ip, domain) for ip in ips]
    return removed, added


def apply(domain: str, ips: list[str], path: Path = HOSTS_PATH) -> tuple[str, Optional[Path]]:
    """写入 hosts。返回 (消息, 备份路径)。

    流程：校验 IP -> 读原文件 -> 备份 -> 原子替换 -> 返回
    """
    ips = validate_ips(ips)

    try:
        text, encoding = read_text(path)
    except OSError as exc:
        raise HostsError("读取 hosts 失败：%s" % exc) from exc

    newline = detect_newline(text)
    lines = text.splitlines()

    try:
        bak = backup(path)
    except OSError as exc:
        raise HostsError("备份失败，已中止（hosts 未改动）：%s" % exc) from exc

    kept = [line for line in lines if not _is_mapping_for(line, domain)]
    added = ["%s    %s" % (ip, domain) for ip in ips]
    while kept and not kept[-1].strip():          # 去掉末尾空行，避免越积越多
        kept.pop()
    out = newline.join(kept + added) + newline

    tmp = path.with_name(path.name + ".sitecheck.tmp")
    try:
        tmp.write_text(out, encoding=encoding, newline="")
        os.replace(tmp, path)
    except PermissionError:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise HostsError("NEED_ADMIN") from None
    except OSError as exc:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise HostsError("写入失败：%s（备份在 %s）" % (exc, bak)) from exc

    return "已写入 %d 条映射（编码 %s）" % (len(added), encoding), bak


def flush_dns() -> tuple[bool, str]:
    """刷新 DNS 缓存。

    说明：hosts 的改动本身会立即生效，不受 DNS 缓存影响。
    这里刷新是为了让浏览器 / 系统里可能缓存的旧解析结果尽快失效。

    ipconfig 的输出是 GBK 编码，不能依赖 locale 推断（在 UTF-8 终端下会乱码），
    所以按字节取回再逐个编码尝试。
    """
    if os.name != "nt":
        return True, "非 Windows，跳过"
    try:
        proc = subprocess.run(["ipconfig", "/flushdns"], capture_output=True,
                              timeout=25)
        ok = proc.returncode == 0
        raw = (proc.stdout or b"") + (proc.stderr or b"")
        detail = ""
        for encoding in ("gbk", "utf-8", "latin-1"):
            try:
                detail = raw.decode(encoding).strip()
                break
            except UnicodeDecodeError:
                continue
        return ok, detail[:200] or ("成功" if ok else "无输出")
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)[:120]


# ---------------------------------------------------------------- 提权

def is_admin() -> bool:
    if os.name != "nt":
        return os.geteuid() == 0
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin(args: list[str]) -> bool:
    """以管理员身份重启自身。参数用 list2cmdline 拼接，避免引号注入。"""
    if os.name != "nt":
        return False
    try:
        import ctypes
        import sys
        params = subprocess.list2cmdline(args)
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, None, 1)
        return rc > 32
    except Exception:
        return False
