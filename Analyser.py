"""Network Traffic Analyzer: protocols, packet stats, traffic trends, threat detection, HTML dashboard.

Usage:
  python analyzer.py sample sample.pcap          # synthetic lab traffic (includes simulated attacks)
  python analyzer.py analyze sample.pcap --open  # console report + dashboard.html + CSV (+ PNG)

Pure Python, passive analysis only. Use it on your own or authorized .pcap files.
"""
import argparse, csv, datetime, os, random, socket, struct, webbrowser
from collections import Counter, defaultdict
from Detectors import run_detectors, ORDER, CLEAR
from Dashboard import build_dashboard

PORTS = {20: "FTP", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
         67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP",
         143: "IMAP", 443: "HTTPS", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-alt"}


# ---------- PCAP reader ----------
def read_pcap(path):
    with open(path, "rb") as f:
        gh = f.read(24)
        magic = gh[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            end, nano = "<", magic == b"\x4d\x3c\xb2\xa1"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            end, nano = ">", magic == b"\xa1\xb2\x3c\x4d"
        else:
            raise ValueError("Only classic .pcap is supported (not pcapng). "
                             "In Wireshark use File > Save As > pcap.")
        link = struct.unpack(end + "I", gh[20:24])[0]
        div = 1e9 if nano else 1e6
        while True:
            h = f.read(16)
            if len(h) < 16:
                break
            s, frac, incl, orig = struct.unpack(end + "IIII", h)
            yield s + frac / div, orig, f.read(incl), link


# ---------- Packet parser ----------
def mac(b):
    return ":".join(f"{x:02x}" for x in b)


def dns_query(buf, i):
    """Return the queried name if buf[i:] is a plain DNS query, else None."""
    if len(buf) < i + 13 or buf[i + 2] & 0x80 or struct.unpack("!H", buf[i + 4:i + 6])[0] != 1:
        return None
    pos, labels = i + 12, []
    while pos < len(buf) and buf[pos]:
        n = buf[pos]
        lab = buf[pos + 1:pos + 1 + n]
        if n > 63 or len(lab) < n or not all(48 <= c <= 57 or 65 <= c <= 90 or 97 <= c <= 122 or c in (45, 95) for c in lab):
            return None
        labels.append(lab.decode()); pos += n + 1
    return ".".join(labels) if labels else None


def parse(data, link):
    p = dict(proto="Other", app="Other", src=None, dst=None, sport=None, dport=None,
             flags=0, arp=None, dns=None, icmp=None)
    if link == 1:
        if len(data) < 14: return p
        et, off = struct.unpack("!H", data[12:14])[0], 14
        if et == 0x8100 and len(data) >= 18:
            et, off = struct.unpack("!H", data[16:18])[0], 18
    elif link == 101 and data:
        off, et = 0, (0x0800 if data[0] >> 4 == 4 else 0x86DD)
    else:
        return p
    if et == 0x0806:
        p["proto"] = p["app"] = "ARP"
        if len(data) >= off + 28:   # (opcode, sender MAC, sender IP, target IP)
            p["arp"] = (struct.unpack("!H", data[off + 6:off + 8])[0], mac(data[off + 8:off + 14]),
                        socket.inet_ntoa(data[off + 14:off + 18]), socket.inet_ntoa(data[off + 24:off + 28]))
        return p
    if et == 0x0800 and len(data) >= off + 20:
        ihl, ipp = (data[off] & 15) * 4, data[off + 9]
        p["src"] = socket.inet_ntoa(data[off + 12:off + 16])
        p["dst"] = socket.inet_ntoa(data[off + 16:off + 20])
        l4 = off + ihl
    elif et == 0x86DD and len(data) >= off + 40:
        ipp, l4 = data[off + 6], off + 40
        p["src"] = socket.inet_ntop(socket.AF_INET6, data[off + 8:off + 24])
        p["dst"] = socket.inet_ntop(socket.AF_INET6, data[off + 24:off + 40])
    else:
        return p
    if ipp == 6 and len(data) >= l4 + 14:
        p["proto"] = "TCP"; p["flags"] = data[l4 + 13]
        p["sport"], p["dport"] = struct.unpack("!HH", data[l4:l4 + 4])
    elif ipp == 17 and len(data) >= l4 + 4:
        p["proto"] = "UDP"
        p["sport"], p["dport"] = struct.unpack("!HH", data[l4:l4 + 4])
        if p["dport"] == 53:
            p["dns"] = dns_query(data, l4 + 8)
    elif ipp in (1, 58):
        p["proto"] = "ICMP"
        if ipp == 1 and len(data) > l4: p["icmp"] = data[l4]
    else:
        p["proto"] = f"IP-{ipp}"
    known = [PORTS[x] for x in (p["sport"], p["dport"]) if x in PORTS]
    p["app"] = known[0] if known else p["proto"]
    return p


# ---------- Analysis ----------
def analyze(path, outdir, png=True, show=False):
    os.makedirs(outdir, exist_ok=True)
    proto, app, app_bytes, src_bytes, convs = Counter(), Counter(), Counter(), Counter(), Counter()
    sizes, timeline = [], defaultdict(lambda: [0, 0])
    ev = dict(syn=[], conn=[], arp=[], dns=[], icmp=[], clear=Counter())
    t0 = None
    for ts, size, data, link in read_pcap(path):
        t0 = ts if t0 is None else t0
        t, p = ts - t0, parse(data, link)
        sec = int(t)
        proto[p["proto"]] += 1; app[p["app"]] += 1; app_bytes[p["app"]] += size
        sizes.append(size); timeline[sec][0] += 1; timeline[sec][1] += size
        if p["src"]:
            src_bytes[p["src"]] += size
            convs[(p["src"], p["dst"], p["proto"])] += size
        f = p["flags"]
        if p["proto"] == "TCP" and f & 0x02 and not f & 0x10:      # SYN without ACK
            ev["syn"].append((t, p["src"], p["dst"], p["dport"]))
            ev["conn"].append((t, p["src"], p["dst"], p["dport"]))
        elif p["proto"] == "UDP" and p["dport"] not in (53, 67, 68, 123):
            ev["conn"].append((t, p["src"], p["dst"], p["dport"]))
        if p["arp"]: ev["arp"].append((t, *p["arp"]))
        if p["dns"]: ev["dns"].append((t, p["src"], p["dns"]))
        if p["icmp"] == 8: ev["icmp"].append((t, p["src"], p["dst"]))
        if p["app"] in CLEAR and p["proto"] == "TCP" and f & 0x10:   # established sessions only, not bare SYN probes
            ev["clear"][(p["app"], p["src"], p["dst"])] += 1

    n = len(sizes)
    if not n:
        print("No packets found."); return
    dur, tot, avg = max(timeline) + 1, sum(sizes), sum(sizes) / len(sizes)
    alerts, risk = run_detectors(ev)

    lo, hi = min(sizes), max(sizes)
    step = (hi - lo) / 12 or 1
    hist = Counter(min(11, int((s - lo) / step)) for s in sizes)
    stats = dict(file=os.path.basename(path), generated=datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
                 packets=n, bytes=tot, duration=dur, pps=n / dur, kbps=tot * 8 / dur / 1000,
                 apps=dict(app.most_common(10)), talkers=src_bytes.most_common(8),
                 convs=[[s, d, pr, b] for (s, d, pr), b in convs.most_common(8)],
                 timeline=[timeline.get(s, [0, 0]) for s in range(dur)],
                 hist=[[int(lo + i * step), hist.get(i, 0)] for i in range(12)],
                 alerts=alerts, risk=risk)

    print(f"\n=== Summary: {path} ===")
    print(f"Packets: {n} | Bytes: {tot} | Duration: {dur}s | Risk: {risk['score']}/100 ({risk['label']})")
    print(f"Packet size min/avg/max: {lo}/{avg:.1f}/{hi} B | Avg rate: {stats['pps']:.1f} pkt/s, {stats['kbps']:.1f} kbps")
    print("Transport protocols:", dict(proto.most_common()))
    print("Top apps:", dict(app.most_common(8)))
    print("\nTop talkers (bytes sent):")
    for ip, b in src_bytes.most_common(5): print(f"  {ip:<18}{b}")
    print(f"\nSecurity findings: {len(alerts)}")
    for a in alerts:
        print(f"  [{a['sev'].upper():<8}] {a['type']} ({a['mitre']}) - {a['detail']}")

    with open(os.path.join(outdir, "timeline.csv"), "w", newline="") as f:
        w = csv.writer(f); w.writerow(["second", "packets", "bytes"])
        for s, row in enumerate(stats["timeline"]): w.writerow([s, *row])
    with open(os.path.join(outdir, "protocols.csv"), "w", newline="") as f:
        w = csv.writer(f); w.writerow(["app", "packets", "bytes"])
        for a, c in app.most_common(): w.writerow([a, c, app_bytes[a]])
    with open(os.path.join(outdir, "findings.csv"), "w", newline="") as f:
        w = csv.writer(f); w.writerow(["severity", "type", "mitre", "source", "time_s", "detail", "fix"])
        for a in alerts: w.writerow([a["sev"], a["type"], a["mitre"], a["src"], a["t"], a["detail"], a["fix"]])

    dash = os.path.join(outdir, "dashboard.html")
    build_dashboard(stats, dash)
    print(f"\nSaved in '{outdir}/': dashboard.html, findings.csv, timeline.csv, protocols.csv")

    if png:
        try:
            import matplotlib; matplotlib.use("Agg")
            import matplotlib.pyplot as plt
            fig, ax = plt.subplots(2, 2, figsize=(12, 8)); x = range(dur)
            ax[0][0].plot(x, [r[0] for r in stats["timeline"]]); ax[0][0].set_title("Packets per second")
            ax[0][1].plot(x, [r[1] for r in stats["timeline"]], color="tab:orange"); ax[0][1].set_title("Bytes per second")
            ax[1][0].pie(list(app.values()), labels=list(app.keys()), autopct="%1.0f%%"); ax[1][0].set_title("Protocol share")
            ax[1][1].hist(sizes, bins=30, color="tab:green"); ax[1][1].set_title("Packet size distribution")
            plt.tight_layout(); plt.savefig(os.path.join(outdir, "report.png"), dpi=110)
            print("Saved in output: report.png")
        except ImportError:
            print("(matplotlib not installed: skipped report.png. The dashboard does not need it.)")
    if show:
        webbrowser.open("file://" + os.path.abspath(dash))


# ---------- Lab traffic generator (writes a .pcap file only; sends nothing) ----------
def _mb(m): return bytes.fromhex(m.replace(":", ""))


def mk_packet(src, dst, proto, sport, dport, payload=b"", flags=0x18):
    eth = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x08\x00"
    if proto == "TCP":
        l4 = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 8192, 0, 0); n = 6
    elif proto == "UDP":
        l4 = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0); n = 17
    else:
        l4 = struct.pack("!BBHI", 8, 0, 0, 0); n = 1
    body = l4 + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(body), 0, 0, 64, n, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    return eth + ip + body


def mk_dns(name):
    q = b"".join(bytes([len(x)]) + x.encode() for x in name.split(".")) + b"\0"
    return struct.pack("!HHHHHH", random.randint(0, 65535), 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", 1, 1)


def mk_arp(op, smac, sip, tmac, tip):
    return (_mb(tmac) + _mb(smac) + b"\x08\x06" +
            struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, op, _mb(smac), socket.inet_aton(sip), _mb(tmac), socket.inet_aton(tip)))


def make_sample(path, seconds=60):
    random.seed(7)
    hosts = [f"192.168.1.{i}" for i in range(10, 16)]
    svcs = [("TCP", 443, 0.45), ("TCP", 80, 0.15), ("UDP", 53, 0.2),
            ("TCP", 22, 0.05), ("UDP", 123, 0.05), ("ICMP", 0, 0.1)]
    domains = ["www.example.com", "mail.example.org", "cdn.example.net", "api.example.com"]
    pkts = []
    for s in range(seconds):                      # normal background traffic with a burst
        rate = 20 + (80 if 25 <= s <= 35 else 0) + random.randint(0, 15)
        for _ in range(rate):
            pr, port, _w = random.choices(svcs, [x[2] for x in svcs])[0]
            payload = mk_dns(random.choice(domains)) if port == 53 else os.urandom(random.choice([0, 40, 200, 600, 1200]))
            pkts.append((s + random.random(), mk_packet(random.choice(hosts), random.choice(["8.8.8.8", "1.1.1.1", "93.184.216.34"]),
                                                        pr, random.randint(1024, 65000), port, payload)))
    # --- simulated lab scenarios (detection test data) ---
    for i in range(60):                           # 1. vertical port scan
        pkts.append((40 + i * 0.05, mk_packet("192.168.1.99", "192.168.1.10", "TCP", 44444, 20 + i, b"", 0x02)))
    for i in range(30):                           # 2. ICMP ping sweep
        pkts.append((15 + i * 0.1, mk_packet("192.168.1.77", f"192.168.1.{100 + i}", "ICMP", 0, 0)))
    for i in range(400):                          # 3. SYN flood from spoofed sources
        pkts.append((50 + i * 0.005, mk_packet(f"10.{random.randint(0, 250)}.{random.randint(0, 250)}.{random.randint(1, 250)}",
                                               "192.168.1.10", "TCP", random.randint(1024, 65000), 80, b"", 0x02)))
    gw = "192.168.1.1"                            # 4. ARP spoofing: a second MAC claims the gateway IP
    for t in (1, 20):
        pkts.append((t, mk_arp(2, "02:00:00:00:00:01", gw, "02:00:00:00:00:0a", "192.168.1.10")))
    for t in (30, 35, 45):
        pkts.append((t, mk_arp(2, "02:00:00:00:00:66", gw, "02:00:00:00:00:0a", "192.168.1.10")))
    for i in range(40):                           # 5. DNS tunneling-style queries
        sub = "".join(random.choice("abcdefghijklmnopqrstuvwxyz234567") for _ in range(32))
        pkts.append((10 + i, mk_packet("192.168.1.13", "8.8.8.8", "UDP", random.randint(1024, 65000), 53, mk_dns(f"{sub}.t.evil-c2.example"))))
    for i in range(11):                           # 6. periodic beaconing
        pkts.append((3 + i * 5 + random.uniform(-0.15, 0.15), mk_packet("192.168.1.12", "203.0.113.50", "TCP", 50000 + i, 8443, b"", 0x02)))
    pkts.sort(key=lambda x: x[0])
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        base = 1_700_000_000
        for t, d in pkts:
            f.write(struct.pack("<IIII", base + int(t), int((t % 1) * 1e6), len(d), len(d)) + d)
    print(f"{len(pkts)} sample packets -> {path}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sample"); s.add_argument("out")
    a = sub.add_parser("analyze"); a.add_argument("pcap"); a.add_argument("--out", default="output")
    a.add_argument("--no-png", action="store_true", help="skip matplotlib report.png")
    a.add_argument("--open", action="store_true", help="open the dashboard in your browser")
    args = ap.parse_args()
    make_sample(args.out) if args.cmd == "sample" else analyze(args.pcap, args.out, not args.no_png, args.open)

