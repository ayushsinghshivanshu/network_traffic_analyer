"""Network Traffic Analyzer - protocols, packet stats, traffic trends.
 
Usage:
  python analyzer.py sample sample.pcap          # synthetic traffic banao
  python analyzer.py analyze sample.pcap         # report + charts + CSV
 
Sirf apni ya authorized .pcap files par use karo.
"""
import argparse, csv, os, random, socket, struct
from collections import Counter, defaultdict
 
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
            raise ValueError("Sirf classic .pcap supported hai (pcapng nahi). "
                             "Wireshark me 'Save As > pcap' karo.")
        link = struct.unpack(end + "I", gh[20:24])[0]
        div = 1e9 if nano else 1e6
        while True:
            h = f.read(16)
            if len(h) < 16:
                break
            s, frac, incl, orig = struct.unpack(end + "IIII", h)
            yield s + frac / div, orig, f.read(incl), link
 
# ---------- Packet parser ----------
def parse(data, link):
    p = dict(proto="Other", app="Other", src=None, dst=None, sport=None, dport=None, flags=0)
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
        p["proto"] = p["app"] = "ARP"; return p
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
    elif ipp in (1, 58):
        p["proto"] = "ICMP"
    else:
        p["proto"] = f"IP-{ipp}"
    known = [PORTS[x] for x in (p["sport"], p["dport"]) if x in PORTS]
    p["app"] = known[0] if known else p["proto"]
    return p
 
# ---------- Analysis ----------
def analyze(path, outdir):
    os.makedirs(outdir, exist_ok=True)
    proto, app = Counter(), Counter()
    app_bytes, src_bytes = Counter(), Counter()
    convs = Counter()
    sizes, timeline = [], defaultdict(lambda: [0, 0])
    syn_targets = defaultdict(set)
    t0 = None
    for ts, size, data, link in read_pcap(path):
        t0 = ts if t0 is None else t0
        p = parse(data, link)
        sec = int(ts - t0)
        proto[p["proto"]] += 1; app[p["app"]] += 1; app_bytes[p["app"]] += size
        sizes.append(size); timeline[sec][0] += 1; timeline[sec][1] += size
        if p["src"]:
            src_bytes[p["src"]] += size
            convs[(p["src"], p["dst"], p["proto"])] += size
            # SYN set, ACK not set -> possible scan indicator
            if p["proto"] == "TCP" and p["flags"] & 0x02 and not p["flags"] & 0x10:
                syn_targets[p["src"]].add((p["dst"], p["dport"]))
    n = len(sizes)
    if not n:
        print("Koi packet nahi mila."); return
    dur = max(timeline) + 1
    avg = sum(sizes) / n
    print(f"\n=== Summary: {path} ===")
    print(f"Packets: {n} | Bytes: {sum(sizes)} | Duration: {dur}s")
    print(f"Packet size min/avg/max: {min(sizes)}/{avg:.1f}/{max(sizes)} B")
    print(f"Avg rate: {n/dur:.1f} pkt/s, {sum(sizes)*8/dur/1000:.1f} kbps")
    print("\nTransport protocols:", dict(proto.most_common()))
    print("Top apps:", dict(app.most_common(8)))
    print("\nTop talkers (bytes sent):")
    for ip, b in src_bytes.most_common(5): print(f"  {ip:<18}{b}")
    print("\nTop conversations:")
    for (s, d, pr), b in convs.most_common(5): print(f"  {s} -> {d} [{pr}] {b} B")
    sus = [(s, len(t)) for s, t in syn_targets.items() if len(t) >= 20]
    if sus:
        print("\n[!] Possible port-scan pattern (>=20 unique SYN targets):")
        for s, c in sus: print(f"  {s}: {c} unique dst/port")
 
    # CSV exports
    with open(os.path.join(outdir, "timeline.csv"), "w", newline="") as f:
        w = csv.writer(f); w.writerow(["second", "packets", "bytes"])
        for s in range(dur): w.writerow([s, *timeline.get(s, [0, 0])])
    with open(os.path.join(outdir, "protocols.csv"), "w", newline="") as f:
        w = csv.writer(f); w.writerow(["app", "packets", "bytes"])
        for a, c in app.most_common(): w.writerow([a, c, app_bytes[a]])
 
    # Charts
    import matplotlib; matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(2, 2, figsize=(12, 8))
    x = range(dur)
    ax[0][0].plot(x, [timeline.get(s, [0, 0])[0] for s in x]); ax[0][0].set_title("Packets per second")
    ax[0][1].plot(x, [timeline.get(s, [0, 0])[1] for s in x], color="tab:orange"); ax[0][1].set_title("Bytes per second")
    ax[1][0].pie(list(app.values()), labels=list(app.keys()), autopct="%1.0f%%"); ax[1][0].set_title("Protocol share")
    ax[1][1].hist(sizes, bins=30, color="tab:green"); ax[1][1].set_title("Packet size distribution")
    for a in (ax[0][0], ax[0][1]): a.set_xlabel("seconds")
    plt.tight_layout()
    out = os.path.join(outdir, "report.png"); plt.savefig(out, dpi=110)
    print(f"\nSaved: {out}, timeline.csv, protocols.csv in '{outdir}/'")
 
# ---------- Sample traffic generator ----------
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
 
def make_sample(path, seconds=60):
    random.seed(7)
    hosts = [f"192.168.1.{i}" for i in range(10, 16)]
    svcs = [("TCP", 443, 0.45), ("TCP", 80, 0.15), ("UDP", 53, 0.2),
            ("TCP", 22, 0.05), ("UDP", 123, 0.05), ("ICMP", 0, 0.1)]
    pkts = []
    for s in range(seconds):
        rate = 20 + (80 if 25 <= s <= 35 else 0) + random.randint(0, 15)  # burst
        for _ in range(rate):
            pr, port, _w = random.choices(svcs, [x[2] for x in svcs])[0]
            payload = os.urandom(random.choice([0, 40, 200, 600, 1200]))
            pkts.append((s + random.random(), mk_packet(
                random.choice(hosts), random.choice(["8.8.8.8", "1.1.1.1", "93.184.216.34"]),
                pr, random.randint(1024, 65000), port, payload)))
    for i in range(60):  # simulated scan (lab demo)
        pkts.append((40 + i * 0.05, mk_packet("192.168.1.99", "192.168.1.10", "TCP",
                                              44444, 20 + i, b"", 0x02)))
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
    args = ap.parse_args()
    make_sample(args.out) if args.cmd == "sample" else analyze(args.pcap, args.out)
 

