# -*- coding: utf-8 -*-
"""探测 greasyfork.org 候选 IP 的真身：TLS 证书主体 + 页面内容。只读。"""
import socket, ssl, re

TIMEOUT = 8.0

def cert_probe(ip, host, port=443):
    """返回 (握手结果, 证书CN, SAN列表, 是否匹配host, HTTP状态, 页面标题)"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False          # 关闭主机名校验，但不关证书链校验
    ctx.verify_mode = ssl.CERT_REQUIRED # 这样 getpeercert() 才有内容
    try:
        with socket.create_connection((ip, port), timeout=TIMEOUT) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                cert = ss.getpeercert()
                cn = ""
                san = []
                if cert:
                    for rdn in cert.get("subject", ()):
                        for k, v in rdn:
                            if k == "commonName":
                                cn = v
                    for t, v in cert.get("subjectAltName", ()):
                        san.append(v)
                match = any(host == x or (x.startswith("*.") and host.endswith(x[2:])) for x in san)
                ss.sendall(("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\nConnection: close\r\n\r\n" % host).encode())
                buf = b""
                try:
                    while len(buf) < 200000:
                        c = ss.recv(65536)
                        if not c:
                            break
                        buf += c
                except Exception:
                    pass
                txt = buf.decode("utf-8", "replace")
                m = re.search(r"<title[^>]*>(.*?)</title>", txt, re.S | re.I)
                title = (m.group(1).strip()[:60] if m else "")
                st = re.match(r"HTTP/[\d.]+ (\d+)", txt)
                return ("OK", cn, san, match, st.group(1) if st else "?", title)
    except ssl.SSLCertVerificationError as e:
        return ("证书校验失败: %s" % str(e)[:50], "", [], None, "", "")
    except ssl.SSLError as e:
        return ("TLS 错误: %s" % str(e)[:50], "", [], None, "", "")
    except socket.timeout:
        return ("超时（TCP通但TLS无响应）", "", [], None, "", "")
    except ConnectionRefusedError:
        return ("连接被拒绝", "", [], None, "", "")
    except OSError as e:
        return ("不可达: %s" % str(e)[:50], "", [], None, "", "")

TARGETS = [
    ("104.244.46.244", "greasyfork.org", "114/阿里/腾讯/百度/1.1.1.1/8.8.8.8 全部返回"),
    ("192.133.77.59", "www.greasyfork.org", "各 DNS 对 www 的返回"),
    ("69.30.25.21", "greasyfork.org", "第一轮体检时 114 的返回"),
    ("104.21.33.155", "greasyfork.org", "实测候选 A"),
    ("172.67.164.117", "greasyfork.org", "实测候选 B"),
    ("162.125.32.10", "greasyfork.org", "实测候选 C"),
    ("31.13.95.169", "greasyfork.org", "实测候选 D"),
]

print("探测目标：greasyfork.org 能否通过指定 IP 直连\n")
print("%-16s %-20s %-34s %s" % ("IP", "握手/SNI", "证书 CN", "匹配 / HTTP / 标题"))
print("-" * 118)
for ip, host, note in TARGETS:
    st, cn, san, match, http, title = cert_probe(ip, host)
    flag = "是" if match else ("否" if match is not None else "-")
    print("%-16s %-20s %-34s %s / %s / %s" % (ip, host, cn or st[:34], flag, http or "-", title or "-"))
    print("%-16s ^ %s" % ("", note))
