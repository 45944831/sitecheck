# -*- coding: utf-8 -*-
"""
sitecheck.py —— 网站直连检测工具

用法：
    python sitecheck.py <域名>              # 例：python sitecheck.py example.com
    python sitecheck.py <域名> --report out.md

做什么：
    1. 多 DNS + 加密 DNS 解析，判断 DNS 是否被污染
    2. 逐 IP 做 TCP / TLS / HTTP 探测，用证书主体判定 IP 真身
    3. 判定能否直连，失败则定位到具体层（DNS / TCP / TLS / HTTP）
    4. 只在 hosts 真能解决问题时才给出 hosts 建议
    5. 能直连时给出优化建议

只读：不修改 hosts、不改 DNS、不改任何系统配置。
"""
import sys, os, re, ssl, socket, struct, random, base64, urllib.request
import time, argparse, shutil, subprocess, tempfile
from datetime import datetime, timezone

TIMEOUT = 8.0
UDP_RESOLVERS = [("223.5.5.5", "阿里"), ("119.29.29.29", "腾讯"), ("114.114.114.114", "114"),
                 ("180.76.76.76", "百度"), ("1.1.1.1", "Cloudflare"), ("8.8.8.8", "Google")]
DOH_ENDPOINTS = ["https://dns.alidns.com/dns-query", "https://doh.pub/dns-query"]
# 控制组：验证本环境出网是否可信。这些站点正常网络下必通。
CONTROLS = [("github.com", "20.205.243.166"), ("www.cloudflare.com", None)]


# ---------- DNS ----------
def dns_wire(host, qtype=1):
    p = struct.pack(">HHHHHH", random.randint(0, 65535), 0x0100, 1, 0, 0, 0)
    for lbl in host.encode().split(b"."):
        p += bytes([len(lbl)]) + lbl
    return p + b"\x00" + struct.pack(">HH", qtype, 1)


def parse_answers(data):
    try:
        rcode = data[3] & 0x0F
        ancount = struct.unpack(">H", data[6:8])[0]
        off = 12
        while off < len(data) and data[off] != 0:
            off += data[off] + 1
        off += 5
        ips = []
        for _ in range(ancount):
            if off >= len(data):
                break
            if data[off] & 0xC0 == 0xC0:
                off += 2
            else:
                while off < len(data) and data[off] != 0:
                    off += data[off] + 1
                off += 1
            if off + 10 > len(data):
                break
            rt, rc = struct.unpack(">HH", data[off:off + 4])
            rl = struct.unpack(">H", data[off + 8:off + 10])[0]
            rd = data[off + 10:off + 10 + rl]
            off += 10 + rl
            if rt == 1 and rl == 4 and rc == 1:
                ips.append(".".join(str(b) for b in rd))
        return sorted(set(ips)), rcode
    except Exception:
        return [], -1


def udp_query(host, server, timeout=4.0):
    t0 = time.perf_counter()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(dns_wire(host), (server, 53))
        data, _ = s.recvfrom(2048)
        ips, rcode = parse_answers(data)
        return ips, rcode, (time.perf_counter() - t0) * 1000
    except Exception:
        return [], -1, (time.perf_counter() - t0) * 1000
    finally:
        s.close()


def doh_query(endpoint, host, timeout=12.0):
    b = base64.urlsafe_b64encode(dns_wire(host)).decode().rstrip("=")
    req = urllib.request.Request(endpoint + "?dns=" + b,
                                headers={"accept": "application/dns-message", "User-Agent": "Mozilla/5.0"})
    t0 = time.perf_counter()
    try:
        data = urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()).read()
        ips, _ = parse_answers(data)
        return ips, (time.perf_counter() - t0) * 1000
    except Exception:
        return [], (time.perf_counter() - t0) * 1000


# ---------- 连接探测 ----------
def tcp_ping(ip, port=443, timeout=TIMEOUT):
    t0 = time.perf_counter()
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.close()
        return True, (time.perf_counter() - t0) * 1000
    except Exception:
        return False, (time.perf_counter() - t0) * 1000


def tls_handshake(ip, host, port=443, timeout=TIMEOUT):
    """返回 dict：ok / 阶段 / 证书CN / SAN / 是否匹配 / TLS版本 / ALPN / 加密套件 / 证书过期"""
    out = {"ok": False, "stage": "", "cn": "", "san": [], "match": None,
           "tls": "", "alpn": "", "cipher": "", "notafter": ""}
    ctx = ssl.create_default_context()
    ctx.check_hostname = False          # 关主机名校验但不关证书链校验，才能拿到证书内容
    ctx.verify_mode = ssl.CERT_REQUIRED
    try:
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    except Exception:
        pass
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                cert = ss.getpeercert() or {}
                for rdn in cert.get("subject", ()):
                    for k, v in rdn:
                        if k == "commonName":
                            out["cn"] = v
                san = [v for _, v in cert.get("subjectAltName", ())]
                out["san"] = san
                out["match"] = any(host == x or (x.startswith("*.") and host.endswith(x[2:])) for x in san)
                out["tls"] = ss.version()
                try:
                    out["alpn"] = ss.selected_alpn_protocol() or ""
                except Exception:
                    pass
                try:
                    out["cipher"] = (ss.cipher() or ("", "", ""))[0]
                except Exception:
                    pass
                out["notafter"] = cert.get("notAfter", "")
                out["ok"] = True
                out["stage"] = "OK"
                return out
    except ssl.SSLCertVerificationError as e:
        out["stage"] = "证书链校验失败: %s" % str(e)[:45]
    except ssl.SSLError as e:
        out["stage"] = "TLS 错误: %s" % str(e)[:45]
    except socket.timeout:
        out["stage"] = "TLS 握手超时（TCP 已连通，无响应）"
    except ConnectionRefusedError:
        out["stage"] = "连接被拒绝"
    except ConnectionResetError:
        out["stage"] = "连接被重置 (RST)"
    except OSError as e:
        out["stage"] = "不可达: %s" % str(e)[:45]
    return out


def http_get(ip, host, path="/", timeout=TIMEOUT):
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((ip, 443), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                ss.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n"
                            "Accept: text/html\r\nConnection: close\r\n\r\n" % (path, host)).encode())
                buf = b""
                try:
                    while len(buf) < 300000:
                        c = ss.recv(65536)
                        if not c:
                            break
                        buf += c
                except Exception:
                    pass
        txt = buf.decode("utf-8", "replace")
        st = re.match(r"HTTP/[\d.]+ (\d+)", txt)
        loc = re.search(r"(?i)^location:\s*(\S+)", txt, re.M)
        ttl = re.search(r"<title[^>]*>(.*?)</title>", txt, re.S | re.I)
        return {"status": st.group(1) if st else "?", "location": loc.group(1) if loc else None,
                "title": (ttl.group(1).strip()[:60] if ttl else ""), "bytes": len(buf)}
    except Exception as e:
        return {"status": "", "location": None, "title": "", "bytes": 0, "err": str(e)[:45]}


# ---------- hosts ----------
HOSTS_PATH = r"C:\Windows\System32\drivers\etc\hosts"


def read_hosts(domain):
    try:
        with open(HOSTS_PATH, "r", encoding="utf-8-sig", errors="replace") as f:
            hits = []
            for ln, raw in enumerate(f, 1):
                line = raw.split("#", 1)[0].strip()
                if not line:
                    continue
                p = line.split()
                if len(p) < 2 or not re.match(r"^\d+\.\d+\.\d+\.\d+$", p[0]):
                    continue
                for h in p[1:]:
                    if h.lower() == domain.lower():
                        hits.append((ln, p[0]))
            return hits
    except Exception:
        return []


# ---------- 主流程 ----------
def control_check():
    """控制组：验证本环境出网是否可信"""
    ok = []
    for host, ip in CONTROLS:
        ips, _, _ = udp_query(host, "223.5.5.5")
        target = ip or (ips[0] if ips else None)
        if not target:
            continue
        r = tls_handshake(target, host, timeout=6.0)
        ok.append((host, target, r["ok"]))
    return ok


def analyze(domain, extra_ips=None, progress=None):
    extra_ips = extra_ips or []
    say = progress or (lambda m: None)
    R = {"domain": domain, "time": datetime.now().strftime("%Y-%m-%d %H:%M"),
         "dns": [], "doh": [], "hosts": read_hosts(domain), "control": [], "probes": [],
         "real_ip": None, "verdict": "", "layer": "", "hosts_advice": "", "tips": [],
         "extra_ips": extra_ips}

    say("正在向 %d 个 DNS 服务器查询解析 ..." % len(UDP_RESOLVERS))
    for srv, name in UDP_RESOLVERS:
        ips, rcode, ms = udp_query(domain, srv)
        R["dns"].append({"srv": srv, "name": name, "ips": ips, "rcode": rcode, "ms": ms})
    say("正在通过加密 DNS（DoH）交叉验证 ...")
    for ep in DOH_ENDPOINTS:
        ips, ms = doh_query(ep, domain)
        R["doh"].append({"ep": ep, "ips": ips, "ms": ms})

    say("正在验证本机出网通道（控制组）...")
    R["control"] = control_check()

    # 系统 DNS 当前结果（优先取国内解析器）
    sys_ips = []
    for d in R["dns"]:
        if d["name"] in ("阿里", "腾讯") and d["ips"]:
            sys_ips = d["ips"]
            break
    if not sys_ips:
        for d in R["dns"]:
            if d["ips"]:
                sys_ips = d["ips"]
                break
    R["sys_ips"] = sys_ips

    # 候选 IP：所有解析结果去重
    cands = []
    for d in R["dns"]:
        for ip in d["ips"]:
            if ip not in cands:
                cands.append(ip)
    for d in R["doh"]:
        for ip in d["ips"]:
            if ip not in cands:
                cands.append(ip)

    manual = []
    for ip in extra_ips:
        if ip not in cands:
            cands.append(ip)
        manual.append(ip)

    # hosts 里已有的 IP 必须纳入探测：用户实际问的往往就是"我现在这条还能不能用"
    hosts_ips = [ip for _, ip in R["hosts"]]
    for ip in hosts_ips:
        if ip not in cands:
            cands.append(ip)
    R["hosts_ips"] = hosts_ips

    total = len(cands)
    for i, ip in enumerate(cands, 1):
        say("探测 %d/%d：%s ..." % (i, total, ip))
        tcp_ok, tcp_ms = tcp_ping(ip)
        info = {"ip": ip, "tcp": tcp_ok, "tcp_ms": tcp_ms, "tls": None, "http": None,
                "src": ("手动" if ip in manual else
                        "hosts" if ip in hosts_ips else
                        ("解析" if ip in sys_ips else "候选"))}
        if tcp_ok:
            info["tls"] = tls_handshake(ip, domain)
            if info["tls"]["ok"] and info["tls"]["match"]:
                info["http"] = http_get(ip, domain)
        R["probes"].append(info)

    # 判定真实 IP：证书 SAN 匹配域名
    genuine = [p for p in R["probes"] if p["tls"] and p["tls"]["ok"] and p["tls"]["match"]]
    R["real_ips"] = [p["ip"] for p in genuine]
    if genuine:
        R["real_ip"] = genuine[0]["ip"]

    R["sys_ips"] = sys_ips

    udp_set = [tuple(d["ips"]) for d in R["dns"] if d["ips"]]
    R["all_agree"] = len(set(udp_set)) <= 1 and bool(udp_set)
    R["doh_diff"] = bool(R["doh"][0]["ips"]) and R["doh"][0]["ips"] != sys_ips

    return R


def verdict(R):
    d = R["domain"]
    genuine = [p for p in R["probes"] if p["tls"] and p["tls"]["ok"] and p["tls"]["match"]]
    # 拿到任何 HTTP 响应都说明链路是通的，403/5xx 是服务端拒绝，不是网络问题
    responded = [p for p in genuine if p["http"] and p["http"]["status"]]
    works = [p for p in responded if p["http"]["status"].startswith(("2", "3"))]
    rejected = [p for p in responded if not p["http"]["status"].startswith(("2", "3"))]
    reached = works or rejected

    if reached:
        # DNS 解析出来的 IP 能通 → 不需要 hosts；只有 DNS 的都不行、别的 IP 能通，才推荐 hosts
        dns_ok = [p for p in reached if p["ip"] in R["sys_ips"]]
        p = dns_ok[0] if dns_ok else reached[0]
        st = p["http"]["status"]
        if works:
            R["layer"] = "SUCCESS"
            R["verdict"] = "可以直连（HTTP %s%s）" % (
                st, "" if dns_ok else "，经由非 DNS 解析的 IP")
        else:
            R["layer"] = "HTTP_REJECT"
            R["verdict"] = ("链路可连通（HTTP %s）—— 网络层没问题%s。"
                            "本工具发的是极简请求头，4xx/5xx 多半是服务端的反爬 / 地域 / WAF 策略，"
                            "浏览器带完整请求头访问往往是正常的，与 DNS 和 hosts 无关"
                            % (st, "" if dns_ok else "，且当前经由非 DNS 解析的 IP"))
        hosts_ips = R.get("hosts_ips", [])
        if dns_ok:
            tip = ""
            if hosts_ips:
                tip = "（hosts 里已有的 %s 属于冗余，删掉也不影响访问）" % "、".join(hosts_ips)
            R["hosts_advice"] = "DNS 解析正常且可连通，无需添加 hosts。" + tip
            R["hosts_write_needed"] = False
        elif p["ip"] in hosts_ips:
            R["hosts_advice"] = ("该站需要靠 hosts 才能访问，而你 hosts 里已经有这条并且可用 —— "
                                 "保持现状即可，无需改动：\n\n```\n%s    %s\n```" % (p["ip"], d))
            R["hosts_write_needed"] = False
        else:
            R["hosts_advice"] = ("DNS 当前返回的 IP 不可用，但以下 IP 能完成 TLS 握手、"
                                 "证书匹配且有 HTTP 响应，添加 hosts 可解决：\n\n```\n%s    %s\n```"
                                 % (p["ip"], d))
            R["hosts_write_needed"] = True
            R["hosts_entry_ips"] = R.get("real_ips") or [p["ip"]]
        R["tips"] = build_tips(R, p)
        return

    # 失败定位
    if not any(d["ips"] for d in R["dns"]) and not any(d["ips"] for d in R["doh"]):
        R["layer"] = "DNS"
        R["verdict"] = "解析失败：所有 DNS 均无 A 记录"
        R["hosts_advice"] = "不适用：域名本身解析不出，请先确认域名是否正确或已过期。"
        return

    poison_hint = ("　DNS 疑似被污染，工具无法从解析结果里找到真 IP。"
                   "请从 urlscan.io 等渠道确认该站真实 IP，再用 --ip 参数验证一次，"
                   "只有证书能匹配上域名的 IP 才值得写进 hosts。")
    blocked = [p for p in R["probes"] if p["tcp"] and p["tls"]
               and p["tls"]["stage"].startswith(("TLS 握手超时", "连接被重置"))]
    if blocked:
        R["layer"] = "TLS/SNI"
        R["verdict"] = "TCP 能连通，但 TLS 握手被切断（RST 或无响应）"
        R["hosts_advice"] = ("添加 hosts 无效。封锁发生在 SNI 层：客户端发出域名明文后才被切断，"
                             "改 hosts 只影响 DNS 解析，够不到这一层。")
        return

    dead = [p for p in R["probes"] if not p["tcp"]]
    if dead and not any(p["tcp"] for p in R["probes"]):
        R["layer"] = "TCP"
        R["verdict"] = "所有候选 IP 的 443 端口均不可达"
        R["hosts_advice"] = ("不适用：连 TCP 都连不上，换 IP 也没用。"
                             "可能是服务器下线、端口被封，或本机出网受限。" + poison_hint)
        return

    mismatch = [p for p in R["probes"] if p["tls"] and p["tls"]["ok"] and not p["tls"]["match"]]
    if mismatch:
        R["layer"] = "DNS 污染"
        R["verdict"] = "解析到的 IP 上不是目标站点（证书主体不匹配）"
        R["hosts_advice"] = ("确认是 DNS 污染，但本次未找到能匹配证书的真实 IP。" + poison_hint)
        return

    R["layer"] = "未知"
    R["verdict"] = "未能完成直连，原因需结合本机网络进一步确认"
    R["hosts_advice"] = "暂无法判定。" + poison_hint


def build_tips(R, p):
    tips = []
    lat = sorted([(d["ms"], d["name"], d["srv"]) for d in R["dns"] if d["ips"]])
    if lat:
        tips.append("DNS 延迟最快：%s（%s）%.0f ms；最慢：%s %.0f ms" %
                    (lat[0][1], lat[0][2], lat[0][0], lat[-1][1], lat[-1][0]))
    if R["all_agree"] and R["doh_diff"]:
        tips.append("[!] 所有 UDP DNS 返回一致但与加密 DNS 不同，存在污染迹象，建议启用 DoH")
    tls = p["tls"]
    if tls.get("alpn") == "h2":
        tips.append("已启用 HTTP/2，协议层无需优化")
    elif tls.get("alpn"):
        tips.append("当前协商协议 %s，可考虑启用 HTTP/2 提升并发加载" % tls["alpn"])
    if tls.get("tls") in ("TLSv1.3",):
        tips.append("TLS 1.3 已启用，握手开销最低")
    elif tls.get("tls"):
        tips.append("TLS 版本 %s，建议升级到 1.3" % tls["tls"])
    if p["http"] and p["http"]["status"]:
        st = p["http"]["status"]
        if st.startswith(("2", "3")):
            if st.startswith("3") and p["http"]["location"]:
                tips.append("首页返回 %s 跳转到 %s，可把书签直接指向最终地址省一次往返"
                            % (st, p["http"]["location"]))
        else:
            tips.append("[!] 服务端返回 HTTP %s。链路是通的——本工具发的是极简请求头，"
                        "这类响应多半是反爬 / 地域 / WAF 策略，不代表浏览器打不开。"
                        "若浏览器也打不开，那才是内容层拒绝，换 hosts 和 DNS 都无效" % st)
    if R["hosts"]:
        tips.append("hosts 中已有该域名条目（行 %s），若与当前可用 IP 不一致建议更新"
                    % "、".join(str(x[0]) for x in R["hosts"]))
    if p.get("tcp_ms"):
        tips.append("TCP 建连 %.0f ms，若明显偏高说明链路质量一般，可换就近 DNS 或 CDN 节点" % p["tcp_ms"])
    return tips


# ---------- 写入 hosts（需要管理员权限） ----------
VERSION = "1.0"


def _version_path():
    """版本文件位置：优先放程序旁边，写不了再退回 %LOCALAPPDATA%"""
    if getattr(sys, "frozen", False):
        base = os.path.dirname(sys.executable)
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    p = os.path.join(base, "sitecheck.version")
    try:
        with open(p, "a", encoding="utf-8"):
            pass
        return p
    except Exception:
        fb = os.path.join(os.environ.get("LOCALAPPDATA", tempfile.gettempdir()), "sitecheck")
        try:
            os.makedirs(fb, exist_ok=True)
        except Exception:
            pass
        return os.path.join(fb, "sitecheck.version")


def next_version():
    """
    读取并递增版本号：每次启动 +0.1，逢 10 进 1（1.9 -> 2.0）。
    用整数存 major/minor，不走浮点，避免 0.1 累加出 1.9000000000000001 这种东西。
    """
    global VERSION
    p = _version_path()
    major, minor, found = 1, 0, False
    try:
        with open(p, "r", encoding="utf-8") as f:
            txt = f.read().strip()
        if txt:
            parts = txt.split(".")
            major = int(parts[0])
            minor = int(parts[1]) if len(parts) > 1 else 0
            found = True
    except Exception:
        pass

    if found:                       # 首次运行保持 1.0，之后每次启动才 +0.1
        minor += 1
        if minor >= 10:             # 逢 10 进 1
            major += 1
            minor = 0

    v = "%d.%d" % (major, minor)
    try:
        with open(p, "w", encoding="utf-8") as f:
            f.write(v)
    except Exception:
        pass
    VERSION = v
    return v


def _mapping_matches(line, domain):
    """该行是否为指向 domain 的映射（忽略注释）"""
    code = line.split("#", 1)[0].strip()
    if not code:
        return False
    p = code.split()
    if len(p) < 2:
        return False
    return any(h.lower() == domain.lower() for h in p[1:])


def hosts_backup():
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    dst = HOSTS_PATH + ".sitecheck-bak-" + ts
    shutil.copy2(HOSTS_PATH, dst)
    return dst


def hosts_plan(domain, ips):
    """预演改动，返回 (将被替换的旧行 [(行号, 原文)], 将新增的行 [str])"""
    try:
        with open(HOSTS_PATH, "r", encoding="utf-8-sig", errors="replace") as f:
            lines = f.read().splitlines()
    except Exception:
        lines = []
    removed = [(i + 1, l.strip()) for i, l in enumerate(lines) if _mapping_matches(l, domain)]
    added = ["%s    %s" % (ip, domain) for ip in ips]
    return removed, added


def apply_hosts(domain, ips):
    """
    写入 hosts：先备份，再替换该域名的旧条目，最后追加新条目。
    返回 (ok, 消息, 备份路径)；ok=False 且消息为 NEED_ADMIN 表示需要提权。
    """
    try:
        with open(HOSTS_PATH, "r", encoding="utf-8-sig", errors="replace") as f:
            lines = f.read().splitlines()
    except Exception as e:
        return False, "读取 hosts 失败：%s" % e, None
    try:
        bak = hosts_backup()
    except Exception as e:
        return False, "备份失败，已中止（hosts 未改动）：%s" % e, None
    kept = [l for l in lines if not _mapping_matches(l, domain)]
    added = ["%s    %s" % (ip, domain) for ip in ips]
    out = "\r\n".join(kept + added) + "\r\n"
    try:
        with open(HOSTS_PATH, "w", encoding="utf-8", newline="") as f:
            f.write(out)
    except PermissionError:
        return False, "NEED_ADMIN", bak
    except Exception as e:
        return False, "写入失败：%s（备份在 %s）" % (e, bak), bak
    return True, "已写入 %d 条映射" % len(added), bak


def flush_dns():
    try:
        r = subprocess.run(["ipconfig", "/flushdns"], capture_output=True,
                           text=True, errors="replace", timeout=25)
        ok = r.returncode == 0
        detail = ((r.stdout or "") + (r.stderr or "")).strip()[:200]
        return ok, detail or ("成功" if ok else "无输出")
    except Exception as e:
        return False, str(e)


def relaunch_as_admin(args):
    """用 runas 提权重启自身，返回是否成功发起（不代表用户同意了 UAC）"""
    try:
        import ctypes
        params = " ".join('"%s"' % a for a in args)
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
        return rc > 32
    except Exception:
        return False


def render(R, md=False):
    L = []
    A = L.append
    A("# 网站直连检测：%s" % R["domain"])
    A("")
    real = R.get("real_ips") or []
    if real:
        A("**真实 IP：%s**　（已通过 TLS 证书校验，确认归属该站）" % "、".join(real))
    else:
        A("**真实 IP：未能确认**　（所有候选 IP 均未通过证书校验或不可达，"
          "解析结果大概率是伪造的）")
    A("")
    A("检测时间：%s　|　工具版本 v%s" % (R["time"], VERSION))
    A("")
    A("## 结论")
    A("")
    A("- **判定**：%s" % R["verdict"])
    A("- **阻断点**：%s" % R["layer"])
    A("- **hosts 建议**：%s" % R["hosts_advice"])
    A("")
    if R["tips"]:
        A("## 优化建议")
        A("")
        for t in R["tips"]:
            A("- %s" % t)
        A("")
    A("## 控制组（探测可信度）")
    A("")
    for host, ip, ok in R["control"]:
        A("- %s（%s）：%s" % (host, ip, "通" if ok else "不通"))
    if not any(x[2] for x in R["control"]):
        A("")
        A("> [!] 控制组全部不通，说明本机/本环境出网受限，下方“TCP 不通”类结论不可靠，请在网络正常的环境重跑。")
    A("")
    A("## DNS 解析")
    A("")
    A("| 服务器 | 结果 | 耗时 |")
    A("|---|---|---|")
    for d in R["dns"]:
        A("| %s %s | %s | %.0f ms |" % (d["name"], d["srv"],
                                        ", ".join(d["ips"]) if d["ips"] else "无记录", d["ms"]))
    for d in R["doh"]:
        A("| DoH %s | %s | %.0f ms |" % (d["ep"].replace("https://", ""),
                                         ", ".join(d["ips"]) if d["ips"] else "无记录", d["ms"]))
    A("")
    if R["all_agree"]:
        A("所有 UDP DNS 返回结果一致%s。" % ("（但与加密 DNS 不同，疑似污染）" if R["doh_diff"] else ""))
    A("")
    A("## 逐 IP 探测")
    A("")
    A("| IP | 来源 | TCP | TLS 握手 | 证书主体 | 匹配 | HTTP |")
    A("|---|---|---|---|---|---|---|")
    for p in R["probes"]:
        t = p["tls"]
        A("| %s | %s | %s | %s | %s | %s | %s |" % (
            p["ip"], p.get("src", "-"), "通" if p["tcp"] else "断",
            (t["stage"][:26] if t else "-"),
            (t["cn"][:24] if t and t["cn"] else "-"),
            ("是" if t and t["match"] else ("否" if t and t["match"] is not None else "-")),
            (p["http"]["status"] if p["http"] and p["http"]["status"] else "-")))
    A("")
    A("## 本机 hosts 现状")
    A("")
    if R["hosts"]:
        for ln, ip in R["hosts"]:
            A("- 第 %d 行：`%s %s`" % (ln, ip, R["domain"]))
    else:
        A("- 无该域名的 hosts 条目")
    return "\n".join(L)


def _esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def _inline(s):
    s = _esc(s)
    s = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", s)
    s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    s = s.replace("[!]", '<span style="color:#b26a00;">[!]</span>')
    return s


def _table(rows):
    """rows: [[单元格...], ...]，首行当表头"""
    h = ["<table border='1' cellspacing='0' cellpadding='4' "
         "style='border-color:#d0d0d0;margin:2px 0;'>",
         "<tr bgcolor='#f0f2f5'>" + "".join(
             "<th align='left' style='padding:4px 8px;'>%s</th>" % _inline(c) for c in rows[0]) + "</tr>"]
    for r in rows[1:]:
        h.append("<tr>" + "".join("<td style='padding:4px 8px;'>%s</td>" % _inline(c)
                                  for c in r) + "</tr>")
    h.append("</table>")
    return "".join(h)


def render_html(R):
    """
    生成 HTML 供 GUI 结果区显示。
    表格用真正的 <table>，列对齐由布局引擎保证，不依赖等宽字体——
    混排中英文时 Consolas 会回退到中文字体，字宽凑不齐，纯文本补空格对不准。
    """
    md = render(R)
    out, buf, tbl, pre = [], [], [], False
    lines = md.split("\n") + [""]

    def flush_tbl():
        if tbl:
            out.append(_table(tbl))
            tbl.clear()

    for raw in lines:
        s = raw.rstrip()
        if s.startswith("```"):
            flush_tbl()
            pre = not pre
            if pre:
                out.append("<pre style='background:#f4f4f4;padding:6px;"
                           "font-family:Consolas,monospace;'>")
            else:
                out.append("</pre>")
            continue
        if pre:
            out.append(_esc(raw))
            continue
        if s.startswith("|"):
            cells = [c.strip() for c in s.strip().strip("|").split("|")]
            if cells and all(set(c) <= set("-: ") for c in cells):
                continue          # 分隔行
            tbl.append(cells)
            continue
        flush_tbl()
        if not s:
            continue
        if s.startswith("# "):
            out.append("<h2 style='margin:10px 0 4px;'>%s</h2>" % _inline(s[2:]))
        elif s.startswith("## "):
            out.append("<h3 style='margin:10px 0 4px;color:#333;'>%s</h3>" % _inline(s[3:]))
        elif s.startswith("- ") or s.startswith("  - "):
            out.append("<div style='margin-left:14px;'>• %s</div>" % _inline(s.strip()[2:]))
        elif s.startswith("> "):
            out.append("<div style='color:#b26a00;margin-left:8px;'>%s</div>" % _inline(s[2:]))
        else:
            out.append("<div style='margin:3px 0;'>%s</div>" % _inline(s))
    flush_tbl()
    return "".join(out)


def main():
    # 控制台编码兜底：避免中文/符号在 GBK 终端下抛 UnicodeEncodeError
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except Exception:
            pass

    ver = next_version()   # 每次启动递增一次

    ap = argparse.ArgumentParser(description="网站直连检测工具")
    ap.add_argument("domain", nargs="?", help="域名，如 example.com；留空则进入交互模式")
    ap.add_argument("--report", help="输出 markdown 报告路径")
    ap.add_argument("--ip", action="append", default=[],
                    help="手动指定候选 IP，可重复。DNS 被污染时必须用它来验证真实 IP")
    ap.add_argument("--apply-hosts", action="store_true",
                    help="把确认可用的真实 IP 写入 hosts 并刷新 DNS 缓存（需要管理员权限）")
    args = ap.parse_args()

    interactive = not args.domain
    if interactive:
        print("=" * 60)
        print(" 网站直连检测工具 sitecheck  v%s" % VERSION)
        print("=" * 60)
        print("用法：直接回车检测单个域名，或用命令行参数：")
        print("  sitecheck.exe <域名> [--ip IP] [--report 文件名.md]")
        print()
        try:
            args.domain = input("请输入要检测的域名：").strip()
        except EOFError:
            return
        if not args.domain:
            print("未输入域名。")
            return

    domain = re.sub(r"^https?://", "", args.domain).strip().strip("/").split("/")[0].split("?")[0]

    if args.apply_hosts:
        ips = [x.strip() for x in args.ip if x.strip()]
        if not ips:
            print("未指定 --ip，先自动检测以确认真实 IP ...\n")
            _R = analyze(domain, [], progress=lambda m: print("  " + m))
            verdict(_R)
            ips = _R.get("real_ips") or []
        if not ips:
            print("\n没有可用于写入的真实 IP（候选均未通过证书校验）。已中止，hosts 未改动。")
            raise SystemExit(1)
        removed, added = hosts_plan(domain, ips)
        print("\n将对 %s 做如下改动：" % HOSTS_PATH)
        for ln, txt in removed:
            print("  替换第 %-4d 行  %s" % (ln, txt))
        for l in added:
            print("  新增            %s" % l)
        ok, msg, bak = apply_hosts(domain, ips)
        print()
        if ok:
            fok, fmsg = flush_dns()
            print("写入成功：%s" % msg)
            print("DNS 缓存刷新：%s" % ("成功" if fok else "失败 -> %s" % fmsg))
        else:
            print("写入失败：%s" % msg)
        if bak:
            print("备份文件：%s" % bak)
        raise SystemExit(0 if ok else 1)

    print("\n检测 %s ...\n" % domain)
    R = analyze(domain, args.ip)
    verdict(R)
    text = render(R)
    print(text)
    if args.report:
        path = args.report
    elif interactive:
        path = "检测结果-%s.md" % domain
    else:
        path = None
    if path:
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
            print("\n报告已写入 %s" % os.path.abspath(path))
        except Exception as e:
            print("\n报告写入失败：%s" % e)

    if interactive:
        try:
            input("\n按回车键退出...")
        except EOFError:
            pass


if __name__ == "__main__":
    main()
