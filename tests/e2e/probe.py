#!/usr/bin/env python3
"""Client-side checks. Usage: probe.py echo | stream SECONDS PPS | download | big"""
import hashlib, json, socket, sys, time

GAME = "172.30.3.30"

def echo():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)
    for _ in range(5):
        # No route at all ("network unreachable") also counts as no reply.
        try:
            s.sendto(b"ping", (GAME, 9000))
            print(s.recv(2048).decode().split("|")[0])
            return 0
        except OSError:
            pass
    print("no-reply")
    return 1

def once():
    # One packet with no retry: proves a packet held during route measurement isn't lost.
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(4)
    s.sendto(b"once", (GAME, 9000))
    try:
        print(s.recv(2048).decode().split("|")[0])
    except OSError:
        print("lost")

def sticky(secs):
    # One socket for the whole run: prints the addresses the server saw, in order.
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.4)
    seen, end = [], time.time() + secs
    while time.time() < end:
        try:
            s.sendto(b"sticky", (GAME, 9000))
            ip = s.recv(2048).decode().split("|")[0]
            if not seen or seen[-1] != ip:
                seen.append(ip)
        except OSError:
            pass
        time.sleep(0.25)
    print(" ".join(seen))

def stream(secs, pps):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(False)
    sent, got, rtts, seen = 0, 0, [], set()
    end = time.time() + secs
    nxt = time.time()
    while time.time() < end:
        if time.time() >= nxt:
            s.sendto(json.dumps({"i": sent, "t": time.time()}).encode().ljust(200), (GAME, 9000))
            sent += 1
            nxt += 1 / pps
        try:
            while True:
                d = json.loads(s.recv(2048).split(b"|", 1)[1])
                if d["i"] not in seen:
                    seen.add(d["i"])
                    got += 1
                    rtts.append(time.time() - d["t"])
        except BlockingIOError:
            time.sleep(0.001)
    time.sleep(0.5)
    try:
        while True:
            d = json.loads(s.recv(2048).split(b"|", 1)[1])
            if d["i"] not in seen:
                seen.add(d["i"])
                got += 1
    except BlockingIOError:
        pass
    # Longest run of consecutive lost packets = the worst outage in the game.
    worst = run = 0
    for i in range(sent):
        run = 0 if i in seen else run + 1
        worst = max(worst, run)
    rtts.sort()
    print(json.dumps({"sent": sent, "got": got, "loss_pct": round(100 * (sent - got) / max(sent, 1), 2),
                      "worst_gap_ms": round(worst * 1000 / pps), "p50_ms": round(rtts[len(rtts)//2]*1000, 1) if rtts else None}))

def download():
    s = socket.create_connection((GAME, 9001), timeout=20)
    h, n, t = hashlib.sha256(), 0, time.time()
    while True:
        b = s.recv(1 << 16)
        if not b:
            break
        h.update(b)
        n += len(b)
        if n >= 20 << 20:
            break
    want = hashlib.sha256(bytes((i * 31) & 0xFF for i in range(1 << 16)) * 320).hexdigest()
    print("identical" if h.hexdigest() == want else "corrupt", n, round(n * 8 / 1e6 / (time.time() - t), 1))

def big():
    # A datagram over the tunnel MTU must be fragmented and still arrive whole.
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    p = b"x" * 3000
    s.sendto(p, (GAME, 9000))
    print("ok" if s.recv(65535).split(b"|", 1)[1] == p else "corrupt")

c = sys.argv[1]
if c == "echo":
    sys.exit(echo())
elif c == "sticky":
    sticky(float(sys.argv[2]))
elif c == "once":
    once()
elif c == "stream":
    stream(float(sys.argv[2]), float(sys.argv[3]))
elif c == "download":
    download()
elif c == "big":
    big()
