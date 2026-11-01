#!/usr/bin/env python3
"""Logs latency every 2 minutes, to locate where ping rises at rush hour.

Usage: rush_monitor.py [--once] [--hours N] [--csv PATH] [--isp-hop IP] [--isp-hop2 IP] [--relay IP]

--isp-hop     your ISP's first router (from `tracepath`); shows whether the rise is local
--isp-hop2    a later router on the route, such as the first international hop
--relay       your relay's public IP; with a STUN service on UDP 3478, per-flow UDP is timed too
Uses little bandwidth: about 10 small pings per target per cycle.
"""
import argparse, concurrent.futures as cf, csv, os, re, socket, statistics as st, struct, subprocess, time

TARGETS = {
    "valve_madrid": "155.133.246.34",
    "valve_paris": "185.25.182.18",
    "valve_frankfurt": "155.133.226.68",
    "vultr_madrid": "mad-es-ping.vultr.com",
    "vultr_paris": "par-fr-ping.vultr.com",
    "oracle_madrid": "objectstorage.eu-madrid-1.oraclecloud.com",
    "oracle_marseille": "objectstorage.eu-marseille-1.oraclecloud.com",
}
COLS = ["time", "isp_first_hop", "cogent_spain_hop", *TARGETS, "oracle_paris_relay", "relay_udp_best", "relay_udp_median", "relay_udp_worst"]


def ping(ip):
    o = subprocess.run(["ping", "-n", "-q", "-c", "10", "-i", "0.2", "-W", "2", ip], capture_output=True, text=True).stdout
    m = re.search(r"= [\d.]+/([\d.]+)/", o)
    return float(m[1]) if m else ""


def stun_port(host):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.5)
    s.connect((host, 3478))
    v = []
    for _ in range(4):
        t = time.time()
        s.send(struct.pack("!HHI", 1, 0, 0x2112A442) + os.urandom(12))
        try:
            s.recv(1500)
            v.append((time.time() - t) * 1000)
        except OSError:
            pass
        time.sleep(0.05)
    s.close()
    return st.median(v) if v else None


def sample(args):
    targets = dict(TARGETS)
    for name, ip in (("isp_first_hop", args.isp_hop), ("cogent_spain_hop", args.isp_hop2), ("oracle_paris_relay", args.relay)):
        if ip:
            targets[name] = ip
    with cf.ThreadPoolExecutor(len(targets)) as e:
        vals = dict(zip(targets, e.map(ping, targets.values())))
    ports = [x for x in (stun_port(args.relay) for _ in range(10)) if x is not None] if args.relay else []
    best, med, worst = (round(min(ports), 1), round(st.median(ports), 1), round(max(ports), 1)) if ports else ("", "", "")
    return {"time": time.strftime("%Y-%m-%d %H:%M"), **vals, "relay_udp_best": best, "relay_udp_median": med, "relay_udp_worst": worst}


def main():
    a = argparse.ArgumentParser()
    a.add_argument("--once", action="store_true")
    a.add_argument("--hours", type=float, default=72)
    a.add_argument("--isp-hop")
    a.add_argument("--isp-hop2")
    a.add_argument("--relay")
    a.add_argument("--csv", default=os.path.expanduser("~/.local/share/lagrelay/rush.csv"))
    args = a.parse_args()
    end = time.time() + args.hours * 3600
    new = not os.path.exists(args.csv)
    with open(args.csv, "a", newline="") as f:
        w = csv.DictWriter(f, COLS)
        if new:
            w.writeheader()
        while True:
            start = time.time()
            r = sample(args)
            w.writerow(r)
            f.flush()
            if args.once:
                print(r)
                return
            if time.time() > end:
                return
            time.sleep(max(1, 120 - (time.time() - start)))


if __name__ == "__main__":
    main()
