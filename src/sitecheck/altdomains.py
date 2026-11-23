"""证书备用域名：从已抓取的 TLS SAN 里筛出同站域名，逐个探测可用性。

为什么必须过滤（实测证据，不要删掉这层）：
  github.com 的证书只有 github.com / www.github.com 两条 SAN，很干净；
  但 www.baidu.com 的证书有 53 条 SAN，混着 baifubao.com、apollo.auto、
  dwz.cn、mct.y.nuomi.com 等完全无关的品牌域名。把 SAN 原样当"备用地址"
  推荐给用户是误导。这里只保留与目标存在共同注册域的域名。

只在握手成功（能拿到证书）时才有数据；SNI 被切断的站点证书都拿不到，
这个模块自然返回空列表 —— 不猜、不编造备用地址。
"""
from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor, wait

from . import dns as dnsmod
from . import probe as probemod
from .models import AltDomain

# 这些后缀本身不是注册域：foo.github.io 和 bar.github.io 是不同站点。
# 命中时直接用完整域名当基域，避免把别人的 Pages 当备用地址。
_HOSTING_SUFFIXES = frozenset({
    "github.io", "gitlab.io", "gitee.io", "pages.dev", "netlify.app",
    "vercel.app", "workers.dev", "appspot.com", "herokuapp.com",
    "azurewebsites.net", "cloudfront.net", "s3.amazonaws.com",
})

MAX_ALT_DOMAINS = 4
ALT_TIMEOUT = 3.0


def _normalize(domain: str) -> str:
    return domain.strip().lower().rstrip(".")


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _base_domain(domain: str) -> str:
    """粗略注册域：去掉最左一段；托管平台后缀除外。

    不用完整 public suffix list —— 这里的目的只是筛掉跨品牌域名，
    宁可漏掉少数同站域名，也不能把无关域名当备用地址推荐。
    """
    parts = domain.split(".")
    if len(parts) <= 2:
        return domain
    base = ".".join(parts[1:])
    if base in _HOSTING_SUFFIXES:
        return domain
    return base


def extract_alt_domains(target: str, san: Iterable[str],
                        limit: int = MAX_ALT_DOMAINS) -> list[str]:
    """从 SAN 里提取同站备用域名。

    过滤掉：目标自身、通配符（是模式不是地址）、IP 字面量、
    注册域不同的域名（共享证书上的陌生品牌）。
    """
    target = _normalize(target)
    if not target:
        return []
    base = _base_domain(target)
    found: set[str] = set()
    for raw in san:
        cand = _normalize(raw or "")
        if not cand or cand == target or "*" in cand or _is_ip(cand):
            continue
        if _base_domain(cand) != base:
            continue
        found.add(cand)
    # 父域优先，其次标签少的；避免把深层子服务排在 baidu.com 前面。
    return sorted(found, key=lambda d: (d != base, d.count("."), d))[:limit]


def probe_alt_domain(domain: str, timeout: float = ALT_TIMEOUT) -> AltDomain:
    """对一个备用域名做轻量探测，判定本机能否访问。

    用该域名自己的解析结果（不是目标站的 IP）—— 用户实际访问时走的就是它。
    """
    try:
        ips = [ip for ip in dnsmod.system_resolve(domain) if ip]
    except Exception as exc:                          # noqa: BLE001
        return AltDomain(domain, None, detail="解析失败：%s" % str(exc)[:60])
    if not ips:
        return AltDomain(domain, None, detail="系统解析未返回地址")
    ip = next((a for a in ips if ":" not in a), ips[0])

    tls = probemod.tls_probe(ip, domain, timeout=timeout)
    if not tls.handshake_ok:
        return AltDomain(domain, False, ip,
                         "TLS 握手失败：%s（单次采样，可能是暂时抖动）"
                         % (tls.detail or tls.status.value))
    if tls.cert_match is False:
        return AltDomain(domain, False, ip, "证书不匹配该域名（单次采样）")

    http = probemod.http_probe(ip, domain, timeout=timeout)
    if http.usable:
        return AltDomain(domain, True, ip, "HTTPS 正常，HTTP %s" % http.code_str)
    return AltDomain(domain, False, ip,
                     "HTTP 无响应：%s（单次采样，可能是暂时抖动）"
                     % (http.detail or http.status.value))


def probe_alt_domains(target: str, san: Iterable[str], budget: float = 6.0,
                      progress=None) -> list[AltDomain]:
    """并发探测同站备用域名，总耗时受 budget 约束。

    超时的域名不脑补结论，直接丢弃 —— 报告里只列有证据的条目。
    """
    domains = extract_alt_domains(target, san)
    if not domains:
        return []
    if progress:
        progress("备用域名", "证书还覆盖 %d 个同站域名，逐个探测" % len(domains), 0, 0)

    found: dict[str, AltDomain] = {}
    workers = min(4, len(domains))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(probe_alt_domain, d): d for d in domains}
        done, pending = wait(futures, timeout=max(budget, 0.1))
        for future in done:
            try:
                result = future.result()
            except Exception:                         # noqa: BLE001
                result = None
            if result:
                found[result.domain] = result
        # 超时的也保留为「无法判定」：让用户知道证书覆盖了它，只是没测出来。
        # 直接丢掉会让报告看起来只有一两个备用域名，掩盖了真实覆盖情况。
        for future in pending:
            future.cancel()
            domain = futures[future]
            found[domain] = AltDomain(domain, None, detail="探测超时，未得出结论")
    # 按提取顺序输出，保证报告稳定
    return [found[d] for d in domains if d in found]
