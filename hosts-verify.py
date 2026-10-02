# -*- coding: utf-8 -*-
"""
hosts 本地复核脚本（只读、不改任何文件）

用途：在你本机正常网络出口下，逐条探测 hosts 里的 IP 是否真的活着。
用法：python hosts-verify.py
输出：控制台结果 + hosts-verify-result.txt
"""
import os, re, ssl, socket
from concurrent.futures import ThreadPoolExecutor

HOSTS = r"C:\Windows\System32\drivers\etc\hosts"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hosts-verify-result.txt")
TIMEOUT = 5.0

def parse_hosts(path):
    entries, seen = [], set()
    with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
        for ln, raw in enumerate(f, 1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            p = line.split()
            if len(p) < 2 or not re.match(r"^\d+\.\d+\.\d+\.\d+$", p[0]):
                continue
            for host in p[1:]:
                entries.append({"line": ln, "ip": p[0], "host": host.lower()})
    return entries

def is_bogus(ip):
    a = list(map(int, ip.split(".")))
    if a[0] == 10:
        return "私有地址 RFC1918"
    if a[0] == 172 and 16 <= a[1] <= 31:
        return "私有地址 RFC1918"
    if a[0] == 192 and a[1] == 168:
        return "私有地址 RFC1918"
    if a[0] == 127:
        return "回环地址"
    if a[0] == 198 and 18 <= a[1] <= 19:
        return "RFC2544 测速保留段"
    return ""

def probe(ip, host):
    bogus = is_bogus(ip)
    if bogus:
        return ("BOGUS", bogus, "")
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((ip, 443), timeout=TIMEOUT) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                ss.getpeercert()
                ss.sendall(("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n" % host).encode())
                resp = ss.recv(300).decode("utf-8", "replace")
                m = re.match(r"HTTP/[\d.]+ (\d+)", resp)
                return ("ALIVE", "TLS 握手成功，证书校验通过", m.group(1) if m else "?")
    except ssl.SSLCertVerificationError as e:
        return ("MISMATCH", "有响应但证书不匹配: %s" % str(e)[:45], "")
    except ssl.SSLError as e:
        return ("MISMATCH", "TLS 错误: %s" % str(e)[:45], "")
    except socket.timeout:
        return ("BLOCKED", "TCP 通但 TLS 无响应（疑似 SNI 过滤）", "")
    except ConnectionRefusedError:
        return ("DEAD", "连接被拒绝", "")
    except OSError as e:
        return ("DEAD", "不可达: %s" % str(e)[:45], "")

def main():
    entries = parse_hosts(HOSTS)
    print("hosts 共 %d 条映射，开始探测（超时 %ss）\n" % (len(entries), TIMEOUT))
    print("控制组：")
    for ip in ["1.1.1.1", "8.8.8.8"]:
        try:
            s = socket.create_connection((ip, 443), timeout=TIMEOUT); s.close()
            print("  %s:443  通   <- 说明本机出口正常，结果可信" % ip); break
        except Exception:
            print("  %s:443  不通" % ip)

    jobs = [(e["ip"], e["host"]) for e in entries]
    with ThreadPoolExecutor(max_workers=16) as ex:
        res = list(ex.map(lambda j: probe(*j), jobs))

    lines = []
    print("\n%-26s %-16s %-10s %-5s %s" % ("域名", "IP", "状态", "HTTP", "说明"))
    print("-" * 100)
    for e, (st, msg, http) in zip(entries, res):
        row = "%-26s %-16s %-10s %-5s %s" % (e["host"], e["ip"], st, http or "-", msg)
        print(row)
        lines.append("行%-4d %s" % (e["line"], row))

    alive = sum(1 for r in res if r[0] == "ALIVE")
    dead = sum(1 for r in res if r[0] in ("DEAD", "BOGUS"))
    blocked = sum(1 for r in res if r[0] == "BLOCKED")
    summary = "\n汇总：存活 %d / 失效 %d / 被拦 %d / 证书不匹配 %d / 共 %d" % (
        alive, dead, blocked, sum(1 for r in res if r[0] == "MISMATCH"), len(res))
    print(summary)

    with open(OUT, "w", encoding="utf-8") as f:
        f.write(summary + "\n\n" + "\n".join(lines))
    print("\n结果已写入 " + OUT)

if __name__ == "__main__":
    main()
