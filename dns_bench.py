# -*- coding: utf-8 -*-
"""DNS 基准测试：延迟 / 可用性 / 防污染 / 解析一致性。只读，不改任何系统配置。"""
import socket, struct, random, time, statistics, json
from concurrent.futures import ThreadPoolExecutor

SERVERS = [
    ("114.114.114.114", "114 DNS"),
    ("114.114.115.115", "114 DNS 备"),
    ("223.5.5.5", "阿里 AliDNS"),
    ("223.6.6.6", "阿里 AliDNS 备"),
    ("119.29.29.29", "腾讯 DNSPod"),
    ("119.28.28.28", "腾讯 DNSPod 备"),
    ("180.76.76.76", "百度 DNS"),
    ("101.226.4.6", "DNS 派 电信"),
    ("123.125.81.6", "DNS 派 联通"),
    ("218.30.118.6", "DNS 派 电信备"),
    ("117.50.10.10", "OneDNS"),
    ("52.80.52.52", "AWS 中国"),
    ("8.8.8.8", "Google"),
    ("8.8.4.4", "Google 备"),
    ("1.1.1.1", "Cloudflare"),
    ("1.0.0.1", "Cloudflare 备"),
    ("9.9.9.9", "Quad9"),
    ("208.67.222.222", "OpenDNS"),
]

COMMON = ["www.baidu.com", "www.taobao.com", "www.qq.com", "www.jd.com",
          "www.zhihu.com", "www.bilibili.com", "github.com", "www.microsoft.com"]

def query(host, server, timeout=3.0):
    """返回 (ips, rcode, 耗时ms, 错误信息)"""
    tid = random.randint(0, 65535)
    q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    try:
        for lbl in host.encode().split(b"."):
            q += bytes([len(lbl)]) + lbl
    except Exception:
        return ([], -1, 0, "编码失败")
    q += b"\x00" + struct.pack(">HH", 1, 1)
    t0 = time.perf_counter()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(q, (server, 53))
        data, _ = s.recvfrom(2048)
    except socket.timeout:
        return ([], -1, (time.perf_counter() - t0) * 1000, "超时")
    except OSError as e:
        return ([], -1, (time.perf_counter() - t0) * 1000, "不可达 %s" % e)
    finally:
        s.close()
    ms = (time.perf_counter() - t0) * 1000
    try:
        rcode = struct.unpack(">H", data[2:4])[0] & 0x000F
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
            if rtype == 1 and rdlen == 4:
                ips.append(".".join(str(b) for b in rdata))
        return (sorted(set(ips)), rcode, ms, "")
    except Exception as e:
        return ([], -1, ms, "解析异常 %s" % e)

def bench(server):
    ip, name = server
    lat = []
    ok = 0
    for d in COMMON:
        ips, rcode, ms, err = query(d, ip)
        if ips:
            ok += 1
            lat.append(ms)
    # 防污染：随机不存在的域名，干净 DNS 应返回 NXDOMAIN(rcode=3)
    poison = []
    for _ in range(3):
        fake = "xq%d%dzk.com" % (random.randint(100000, 999999), random.randint(10, 99))
        ips, rcode, ms, err = query(fake, ip)
        poison.append((fake, rcode, ips[:2], err))
    return {"ip": ip, "name": name, "ok": ok, "total": len(COMMON),
            "lat": lat, "poison": poison}

def main():
    print("测试 %d 个 DNS，每个查 %d 个常用域名 + 3 次随机域名防污染检测\n" % (len(SERVERS), len(COMMON)))
    with ThreadPoolExecutor(max_workers=12) as ex:
        results = list(ex.map(bench, SERVERS))

    print("%-16s %-14s %-8s %-10s %-10s %s" % ("IP", "名称", "成功", "平均延迟", "最小延迟", "防污染"))
    print("-" * 92)
    rows = []
    for r in results:
        if r["lat"]:
            avg = statistics.mean(r["lat"])
            mn = min(r["lat"])
            status = "%d/%d" % (r["ok"], r["total"])
        else:
            avg = mn = float("nan")
            status = "0/%d  不可用" % r["total"]
        nx = sum(1 for p in r["poison"] if p[1] == 3)
        timeout_n = sum(1 for p in r["poison"] if p[1] == -1)
        fake_ip = sum(1 for p in r["poison"] if p[2])
        if not r["lat"]:
            pv = "不可达"
        elif nx == 3:
            pv = "干净 (3/3 NXDOMAIN)"
        elif fake_ip:
            pv = "!! 污染 (不存在域名返回了伪造 IP)"
        elif timeout_n:
            pv = "有丢包 (%d/3 超时，非污染)" % timeout_n
        else:
            pv = "存疑 (NX %d/3)" % nx
        print("%-16s %-14s %-8s %-10s %-10s %s" % (
            r["ip"], r["name"], status,
            ("%.1f ms" % avg) if r["lat"] else "-",
            ("%.1f ms" % mn) if r["lat"] else "-", pv))
        rows.append(dict(r, avg=avg, mn=mn, nx=nx, fake_ip=fake_ip, verdict=pv))

    print("\n=== 防污染细节 ===")
    for r in rows:
        if not r["lat"]:
            continue
        det = "; ".join("%s→rcode=%s%s" % (p[0][:14], p[1], (" %s" % p[2] if p[2] else "")) for p in r["poison"])
        print("  %-16s %-14s %s" % (r["ip"], r["name"], det))

    with open(r"E:\2026-10-01-22-18-18\dns-bench.json", "w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=1)
    print("\n已写入 dns-bench.json")

if __name__ == "__main__":
    main()
