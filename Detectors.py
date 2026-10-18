"""Passive, defensive detections for PCAP analysis (blue-team / IDS style).

Everything here only READS parsed packet events. Nothing is sent on the network.
Each finding carries a severity, a MITRE ATT&CK technique ID and a suggested fix.
"""
import math, statistics
from collections import Counter, defaultdict

CFG = dict(scan_targets=20, scan_window=10.0,   # unique ports/hosts inside the window
           syn_rate=100,                        # SYNs per second to one host
           sweep_hosts=20,                      # unique ICMP echo targets inside the window
           beacon_min=8, beacon_cv=0.15, beacon_gap=2.0,
           dns_min=15, dns_len=20, dns_entropy=3.2, dns_unique=0.8)
ORDER = ["critical", "high", "medium", "low"]
WEIGHT = dict(critical=40, high=25, medium=12, low=4)
CLEAR = {"Telnet": "medium", "FTP": "medium", "HTTP": "low", "POP3": "low", "IMAP": "low", "SMTP": "low"}


def _alert(sev, kind, mitre, src, detail, t=None, fix=""):
    return dict(sev=sev, type=kind, mitre=mitre, src=src, detail=detail,
                t=None if t is None else round(t, 1), fix=fix)


def _best_window(events, window):
    """events: [(t, key)] in time order -> (max unique keys inside any window, window start)."""
    best, start, live, j = 0, 0.0, Counter(), 0
    for t, k in events:
        live[k] += 1
        while t - events[j][0] > window:
            old = events[j][1]
            live[old] -= 1
            if not live[old]:
                del live[old]
            j += 1
        if len(live) > best:
            best, start = len(live), events[j][0]
    return best, start


def scans(syn, c):
    """TCP SYN (no ACK) probing: many ports on one host, or one port on many hosts."""
    out, by = [], defaultdict(list)
    for t, s, d, dp in syn:
        by[s].append((t, d, dp))
    for s, evs in by.items():
        vert, hor = defaultdict(list), defaultdict(list)
        for t, d, dp in evs:
            vert[d].append((t, dp)); hor[dp].append((t, d))
        for groups, kind, what in ((vert, "Port scan (vertical)", "ports on {k}"),
                                   (hor, "Host sweep (horizontal)", "hosts on port {k}")):
            best = max(((*_best_window(e, c["scan_window"]), k) for k, e in groups.items()),
                       key=lambda x: x[0], default=(0, 0, None))
            if best[0] >= c["scan_targets"]:
                out.append(_alert("high", kind, "T1046", s,
                    f"{s} probed {best[0]} " + what.format(k=best[2]) + f" within {c['scan_window']:.0f}s",
                    best[1], "Rate-limit or block the source; confirm it is not an authorized scanner."))
    return out


def syn_flood(syn, c):
    per = defaultdict(lambda: defaultdict(lambda: [0, set()]))
    for t, s, d, dp in syn:
        cell = per[d][int(t)]
        cell[0] += 1; cell[1].add(s)
    out = []
    for d, secs in per.items():
        sec, (n, srcs) = max(secs.items(), key=lambda kv: kv[1][0])
        if n >= c["syn_rate"]:
            out.append(_alert("critical" if len(srcs) >= 10 else "high", "SYN flood", "T1498", d,
                f"{d} received {n} SYN packets in one second from {len(srcs)} source(s)", sec,
                "Enable SYN cookies, rate-limit new connections, filter spoofed sources upstream."))
    return out


def arp_spoof(arp):
    seen, flagged, out = {}, set(), []
    for t, op, sha, spa, tpa in arp:
        if spa == "0.0.0.0":
            continue
        if spa in seen and sha not in seen[spa] and (spa, sha) not in flagged:
            flagged.add((spa, sha))
            out.append(_alert("high", "ARP spoofing (IP-MAC conflict)", "T1557.002", spa,
                f"{spa} was claimed by {', '.join(sorted(seen[spa]))} and later by {sha}", t,
                "Use static ARP entries or Dynamic ARP Inspection; check for a rogue device or DHCP change."))
        seen.setdefault(spa, set()).add(sha)
    return out


def _entropy(s):
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in Counter(s).values()) if n else 0.0


def dns_tunnel(dns, c):
    g, out = defaultdict(list), []
    for t, s, q in dns:
        parts = q.lower().split(".")
        if len(parts) >= 3:   # last two labels approximate the registered domain
            g[(s, ".".join(parts[-2:]))].append((t, ".".join(parts[:-2])))
    for (s, base), qs in g.items():
        subs, n = [x[1] for x in qs], len(qs)
        if n < c["dns_min"]:
            continue
        uniq = len(set(subs)) / n
        ln = sum(map(len, subs)) / n
        ent = sum(_entropy(x.replace(".", "")) for x in subs) / n
        if uniq >= c["dns_unique"] and ln >= c["dns_len"] and ent >= c["dns_entropy"]:
            out.append(_alert("high", "DNS tunneling suspected", "T1071.004", s,
                f"{s} sent {n} queries to *.{base}: avg subdomain {ln:.0f} chars, "
                f"{ent:.1f} bits entropy, {uniq:.0%} unique", qs[0][0],
                "Inspect the domain, restrict DNS to approved resolvers, alert on long random labels."))
    return out


def beacons(conn, c):
    g, out = defaultdict(list), []
    for t, s, d, dp in conn:
        g[(s, d, dp)].append(t)
    for (s, d, dp), ts in g.items():
        if len(ts) < c["beacon_min"]:
            continue
        gaps = [b - a for a, b in zip(ts, ts[1:])]
        m = statistics.mean(gaps)
        if m >= c["beacon_gap"] and statistics.pstdev(gaps) / m <= c["beacon_cv"]:
            out.append(_alert("medium", "Periodic beaconing", "T1071", s,
                f"{s} contacted {d}:{dp} {len(ts)} times, every {m:.1f}s "
                f"(jitter {statistics.pstdev(gaps) / m:.0%})", ts[0],
                "Check what process on the host opens this connection; review the destination's reputation."))
    return out


def icmp_sweep(icmp, c):
    by, out = defaultdict(list), []
    for t, s, d in icmp:
        by[s].append((t, d))
    for s, e in by.items():
        n, start = _best_window(e, c["scan_window"])
        if n >= c["sweep_hosts"]:
            out.append(_alert("medium", "ICMP ping sweep", "T1018", s,
                f"{s} sent echo requests to {n} hosts within {c['scan_window']:.0f}s", start,
                "Filter ICMP echo from untrusted segments; confirm the source is an approved monitor."))
    return out


def cleartext(clear):
    per = defaultdict(lambda: [0, set()])
    for (app, s, d), n in clear.items():
        per[app][0] += n; per[app][1].add(s)
    return [_alert(CLEAR[a], f"Cleartext protocol: {a}", "T1040", f"{len(h)} host(s)",
                   f"{n} packet(s) of unencrypted {a}; data and credentials can be sniffed on the path.", None,
                   "Switch to an encrypted equivalent (SSH, SFTP, HTTPS, IMAPS/POP3S, SMTP+TLS).")
            for a, (n, h) in per.items()]


def run_detectors(ev, cfg=None):
    c = {**CFG, **(cfg or {})}
    alerts = (scans(ev["syn"], c) + syn_flood(ev["syn"], c) + arp_spoof(ev["arp"]) +
              dns_tunnel(ev["dns"], c) + beacons(ev["conn"], c) + icmp_sweep(ev["icmp"], c) +
              cleartext(ev["clear"]))
    alerts.sort(key=lambda a: (ORDER.index(a["sev"]), a["t"] if a["t"] is not None else 1e9))
    score = min(100, sum(WEIGHT[a["sev"]] for a in alerts))
    return alerts, dict(score=score, label="Critical" if score >= 70 else "Elevated" if score >= 30 else "Low")
