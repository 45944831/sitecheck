# -*- coding: utf-8 -*-
"""本机 hosts 文件体检 v2：绕过 hosts 直接向 114.114.114.114 发 UDP DNS 查询。只读取、只探测，不改任何文件。"""
import socket, ssl, re, json, struct, random
from concurrent.futures import ThreadPoolExecutor

HOSTS = r"C:\Windows\System32\drivers\etc\hosts"
DNSSERVER = "114.114.114.114"
TIMEOUT = 6.0

# ---------- 极简 DNS A 查询（绕过 hosts 文件） ----------
def dns_a(host, server=DNSSERVER, timeout=5.0):
    tid = random.randint(0, 65535)
    q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    for lbl in host.encode().split(b"."):
        q += bytes([len(lbl)]) + lbl
    q += b"\x00" + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(q, (server, 53))
        data, _ = s.recvfrom(2048)
    except Exception:
        return []
    finally:
        s.close()
    try:
        if len(data) < 12:
            return []
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
            rtype, rclass = struct.unpack(">HH", data[off:off + 4])
            rdlen = struct.unpack(">H", data[off + 8:off + 10])[0]
            rdata = data[off + 10:off + 10 + rdlen]
            off += 10 + rdlen
            if rtype == 1 and rdlen == 4 and rclass == 1:
                ips.append(".".join(str(b) for b in rdata))
        return sorted(set(ips))
    except Exception:
        return []

def tcp_test(ip, port=443):
    try:
        s = socket.create_connection((ip, port), timeout=TIMEOUT)
        s.close()
        return True
    except Exception:
        return False

def tls_test(ip, host, port=443):
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((ip, port), timeout=TIMEOUT) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                ss.getpeercert()
                return ("ok", "TLS 握手成功，证书校验通过")
    except ssl.SSLCertVerificationError as e:
        return ("mismatch", "有响应但证书不匹配: %s" % str(e)[:50])
    except ssl.SSLError as e:
        return ("mismatch", "TLS 错误: %s" % str(e)[:50])
    except socket.timeout:
        return ("noresponse", "TCP 通但 TLS 无响应（SNI 过滤特征）")
    except ConnectionRefusedError:
        return ("refused", "连接被拒绝")
    except OSError as e:
        return ("noresponse", "不可达: %s" % str(e)[:50])

def http_status(ip, host, port=443):
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((ip, port), timeout=TIMEOUT) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                ss.sendall(("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n" % host).encode())
                resp = ss.recv(400).decode("utf-8", "replace")
                m = re.match(r"HTTP/[\d.]+ (\d+)", resp)
                return m.group(1) if m else "?"
    except Exception:
        return "?"

def parse_hosts(path):
    entries = []
    with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
        for ln, raw in enumerate(f, 1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 2 or not re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[0]):
                continue
            for host in parts[1:]:
                entries.append({"line": ln, "ip": parts[0], "host": host.lower()})
    return entries

def main():
    entries = parse_hosts(HOSTS)
    by_host = {}
    for e in entries:
        by_host.setdefault(e["host"], []).append(e["ip"])
    print("hosts 共 %d 条映射 / %d 个域名 / %d 个唯一 IP\n" % (
        len(entries), len(by_host), len({e["ip"] for e in entries})))

    print("=== 控制组：本环境直连通道 ===")
    for ip in ["1.1.1.1", "8.8.8.8", "114.114.114.114"]:
        print("  %-16s TCP443=%s" % (ip, "通" if tcp_test(ip) else "不通"))

    print("\n=== 真实 DNS 解析（绕过 hosts）===")
    dns_map = {}
    with ThreadPoolExecutor(max_workers=10) as ex:
        futs = {ex.submit(dns_a, h): h for h in by_host}
        for fu in futs:
            dns_map[futs[fu]] = fu.result()
    for h in sorted(by_host):
        print("  %-28s %s" % (h, ", ".join(dns_map.get(h) or ["解析失败"])))

    all_ips = sorted({e["ip"] for e in entries})
    ip_alive = {}
    with ThreadPoolExecutor(max_workers=16) as ex:
        futs = {ex.submit(tcp_test, ip): ip for ip in all_ips}
        for fu in futs:
            ip_alive[futs[fu]] = fu.result()

    print("\n=== 逐条探测 ===")
    results = []
    for host in sorted(by_host):
        ips = by_host[host]
        dnsips = dns_map.get(host, [])
        seen = set()
        for idx, ip in enumerate(ips, 1):
            dup = ip in seen
            seen.add(ip)
            alive = ip_alive.get(ip, False)
            st, msg = tls_test(ip, host) if alive else ("dead", "TCP 不通")
            http = http_status(ip, host) if st == "ok" else ""
            in_dns = ip in dnsips
            results.append(dict(host=host, ip=ip, order=idx, alive=alive, in_dns=in_dns,
                                dup=dup, status=st, msg=msg, http=http, dns=dnsips))
            print("  %-26s %-16s #%-2s TCP=%-3s TLS=%-11s HTTP=%-4s 在DNS中=%s%s" % (
                host, ip, idx, "通" if alive else "断", st, http or "-",
                "是" if in_dns else "否", "  <重复>" if dup else ""))

    with open(r"E:\2026-10-01-22-18-18\hosts-audit.json", "w", encoding="utf-8") as f:
        json.dump({"results": results}, f, ensure_ascii=False, indent=1)
    print("\n已写入 hosts-audit.json")

if __name__ == "__main__":
    main()
