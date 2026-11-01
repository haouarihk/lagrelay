#!/usr/bin/env python3
"""Summarises rush_monitor.py's log and says where the rush-hour rise happens.

Usage: rush_report.py [CSV] [--threshold MS]
"""
import argparse, csv, os, statistics as st

KEYS = ["isp_first_hop", "cogent_spain_hop", "valve_madrid", "valve_paris", "valve_frankfurt", "vultr_madrid", "vultr_paris", "oracle_madrid", "oracle_marseille", "oracle_paris_relay", "relay_udp_best", "relay_udp_median"]


def num(r, k):
    try:
        return float(r[k])
    except (KeyError, TypeError, ValueError):
        return None


def med(rows, k):
    v = [x for x in (num(r, k) for r in rows) if x is not None]
    return st.median(v) if v else None


def diagnose(quiet, rush):
    """Plain-language verdict from {target: median} for quiet and rush periods."""
    rise = lambda k: (rush[k] - quiet[k]) if rush.get(k) is not None and quiet.get(k) is not None else None
    madrid = rise("valve_madrid")
    if madrid is None:
        return "Not enough data."
    first = rise("isp_first_hop")
    if first is not None and first >= madrid * 0.6:
        return "Most of the rise is at your ISP's first hop, before any relay. A relay won't fix this."
    others = [k for k in ("vultr_paris", "oracle_marseille", "oracle_paris_relay", "relay_udp_best") if rise(k) is not None]
    if not others:
        return "No relay measurements to compare."
    calm = [k for k in others if rise(k) < madrid * 0.4]
    if calm:
        return "The rise is mostly on the Madrid path; these stayed much calmer: " + ", ".join(calm) + ". A relay on one of them may help."
    return "Every path rises together, which points to your ISP's shared international capacity. A relay probably won't help much."


def main():
    a = argparse.ArgumentParser()
    a.add_argument("csv", nargs="?", default=os.path.expanduser("~/.local/share/lagrelay/rush.csv"))
    a.add_argument("--threshold", type=float, default=35, help="Valve Madrid ping (ms) that counts as rush hour")
    args = a.parse_args()
    rows = list(csv.DictReader(open(args.csv)))
    hours = {}
    for r in rows:
        hours.setdefault(r["time"][11:13], []).append(r)
    show = ["isp_first_hop", "valve_madrid", "valve_paris", "vultr_paris", "oracle_marseille", "relay_udp_best", "relay_udp_median"]
    print(f"{len(rows)} samples\nhour  n  " + " ".join(f"{k[:12]:>12}" for k in show))
    for h in sorted(hours):
        cells = [med(hours[h], k) for k in show]
        print(f"{h}h {len(hours[h]):>3}  " + " ".join(f"{'-' if c is None else format(c, '.0f'):>12}" for c in cells))
    rush = [r for r in rows if (num(r, "valve_madrid") or 0) >= args.threshold]
    quiet = [r for r in rows if num(r, "valve_madrid") is not None and num(r, "valve_madrid") < args.threshold]
    print(f"\nrush samples (Valve Madrid >= {args.threshold:.0f} ms): {len(rush)}, quiet: {len(quiet)}")
    if not rush or not quiet:
        print("No rush hour captured yet.")
        return
    q, r = {k: med(quiet, k) for k in KEYS}, {k: med(rush, k) for k in KEYS}
    print(f"{'target':20}{'quiet':>7}{'rush':>7}{'rise':>7}")
    for k in KEYS:
        if q[k] is not None and r[k] is not None:
            print(f"{k:20}{q[k]:7.0f}{r[k]:7.0f}{r[k] - q[k]:+7.0f}")
    print("\n" + diagnose(q, r))


if __name__ == "__main__":
    main()
