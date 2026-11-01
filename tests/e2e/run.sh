#!/usr/bin/env bash
# End-to-end test on isolated Docker networks. The client has no route to the
# game server or the exit: traffic can only get there through the bridges.
#
#   client --(net-a)-- bridge1/bridge2 --(net-b)-- exit --(net-c)-- game
#
# Usage: tests/e2e/run.sh [path to static binaries]
set -u
# Runs share container names, so a second one would destroy the first one's containers.
exec 9>"${TMPDIR:-/tmp}/lagrelay-e2e.lock"
flock -n 9 || { echo "another end-to-end run is in progress" >&2; exit 2; }
# Runs share container names and subnets, so a second run would break the first.
exec 9>"${TMPDIR:-/tmp}/lagrelay-e2e.lock"
flock -n 9 || { echo "another e2e run is in progress" >&2; exit 3; }
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
BIN=${1:-$ROOT/target/x86_64-unknown-linux-musl/release}
P=lagrelay-e2e
IMG=$P:latest
PASS=0; FAIL=0
ok()  { echo "PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL  $1"; [ -n "${2:-}" ] && echo "      $2"; FAIL=$((FAIL+1)); }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected '$3', got '$2'"; fi; }
x() { docker exec "$P-$1" "${@:2}"; }

cleanup() {
  for c in client client2 bridge1 bridge2 exit game; do docker rm -f $P-$c >/dev/null 2>&1; done
  for n in a b c; do docker network rm $P-$n >/dev/null 2>&1; done
}
trap cleanup EXIT
cleanup
# Hosts that can't load Docker's AppArmor profile need E2E_DOCKER_OPTS, for
# example E2E_DOCKER_OPTS="--security-opt apparmor=unconfined". `docker build`
# can't take that option, so the image is created from a container instead.
OPTS=${E2E_DOCKER_OPTS:-}
if ! docker image inspect $IMG >/dev/null 2>&1; then
  docker rm -f $P-img >/dev/null 2>&1
  docker run --name $P-img $OPTS debian:bookworm-slim sh -c \
    'apt-get update -qq && apt-get install -y -qq --no-install-recommends iproute2 iptables iputils-ping python3 procps >/dev/null' || exit 2
  docker commit $P-img $IMG >/dev/null && docker rm $P-img >/dev/null || exit 2
fi
docker network create --internal --subnet 172.30.1.0/24 $P-a >/dev/null
docker network create --internal --subnet 172.30.2.0/24 $P-b >/dev/null
docker network create --internal --subnet 172.30.3.0/24 $P-c >/dev/null

run() { # name net ip
  docker run -d --name $P-$1 --hostname $1 $OPTS --cap-add NET_ADMIN --cap-add NET_RAW --device /dev/net/tun --sysctl net.ipv4.ip_forward=1 --network $P-$2 --ip $3 \
    -v "$BIN/lagrelay:/usr/local/bin/lagrelay:ro" -v "$BIN/lagrelayd:/usr/local/bin/lagrelayd:ro" \
    -v "$ROOT/tests/e2e:/e2e:ro" $IMG sleep infinity >/dev/null
}
run client  a 172.30.1.10
run client2 a 172.30.1.13
run bridge1 a 172.30.1.11; docker network connect --ip 172.30.2.11 $P-b $P-bridge1
run bridge2 a 172.30.1.12; docker network connect --ip 172.30.2.12 $P-b $P-bridge2
run exit    b 172.30.2.20; docker network connect --ip 172.30.3.20 $P-c $P-exit
run game    c 172.30.3.30
docker exec -d $P-game python3 /e2e/game_server.py

WAN=$(x exit sh -c "ip -o -4 addr show | awk '/172.30.3.20/{print \$2}'")
x exit lagrelayd init --name exit1 --public-addr 172.30.2.20 --exit >/dev/null
x exit sed -i "s/^\[exit\]/[exit]\nwan_interface = \"$WAN\"/" /etc/lagrelay/relayd.toml
x bridge1 lagrelayd init --name b1 --public-addr 172.30.1.11 >/dev/null
x bridge2 lagrelayd init --name b2 --public-addr 172.30.1.12 >/dev/null
# This test network only has private addresses, so it has to allow them.
for r in exit bridge1 bridge2; do x $r sed -i 's/^allow_private_destinations.*/allow_private_destinations = true/' /etc/lagrelay/relayd.toml; done
KEY=$(x client lagrelay key 2>/dev/null)
for r in exit bridge1 bridge2; do x $r lagrelayd add-client me "$KEY" >/dev/null; done
start_relay() { docker exec -d $P-$1 sh -c "lagrelayd run >/tmp/relay.log 2>&1"; }
for r in exit bridge1 bridge2; do start_relay $r; done
sleep 1
for r in bridge1 bridge2 exit; do x client lagrelay relay add "$(x $r lagrelayd link)" >/dev/null; done
x client lagrelay game add testgame --cidr 172.30.3.0/24 --exit exit1 >/dev/null

check "before connecting, game server is unreachable" "$(x client python3 /e2e/probe.py echo)" "no-reply"

connect() { docker exec -d $P-client sh -c "lagrelay connect testgame --plain $* >/tmp/client.log 2>&1"; }
wait_up() { for _ in $(seq 1 40); do x client python3 /e2e/probe.py echo 2>/dev/null | grep -q 172.30.3.20 && return 0; sleep 0.5; done; return 1; }
stop_client() { x client pkill -INT -x lagrelay; for _ in $(seq 1 20); do x client pgrep -x lagrelay >/dev/null || return 0; sleep 0.25; done; return 1; }
jq_() { python3 -c "import json,sys;print(json.load(sys.stdin)['$1'])"; }

# Traffic starts at once, before the tunnel is up, as when the game is already running.
connect --routes 2
if wait_up; then ok "tunnel comes up through bridges only"; else bad "tunnel comes up through bridges only" "$(x client cat /tmp/client.log | tail -5)"; fi
check "game server sees the exit's IP, not the client's" "$(x client python3 /e2e/probe.py echo)" "172.30.3.20"
ROUTES=$(x client sh -c "tail -1 /tmp/client.log")
case "$ROUTES" in *"b1 > exit1"*"b2 > exit1"*|*"b2 > exit1"*"b1 > exit1"*) ok "two routes carry traffic (multipath)";; *) bad "two routes carry traffic (multipath)" "$ROUTES";; esac

DL=$(x client python3 /e2e/probe.py download)
check "20 MiB TCP download is byte-identical (MSS, NAT, ordering)" "$(echo "$DL" | cut -d' ' -f1)" "identical"
echo "      throughput: $(echo "$DL" | cut -d' ' -f3) Mbit/s"
check "3000-byte UDP datagram survives fragmentation" "$(x client python3 /e2e/probe.py big)" "ok"

S=$(x client python3 /e2e/probe.py stream 4 100)
echo "      clean stream: $S"
check "no loss on a clean network" "$(echo "$S" | jq_ loss_pct)" "0.0"

# Heavy loss on one bridge's client link: multipath should hide it completely.
x bridge1 tc qdisc add dev eth0 root netem loss 40% 2>/dev/null; TC=$?
if [ $TC -eq 0 ]; then
  S=$(x client python3 /e2e/probe.py stream 5 100); echo "      40% loss on one route: $S"
  L=$(echo "$S" | jq_ loss_pct)
  if python3 -c "import sys;sys.exit(0 if $L < 1 else 1)"; then ok "multipath hides 40% loss on one route"; else bad "multipath hides 40% loss on one route" "$S"; fi
  x bridge1 tc qdisc del dev eth0 root
else
  echo "SKIP  loss test: kernel module sch_netem is not available"
fi

# Kill one bridge mid-stream: game traffic must not notice.
docker exec -d $P-client sh -c "python3 /e2e/probe.py stream 8 100 >/tmp/kill.json"
sleep 2; x bridge1 pkill -x lagrelayd; sleep 7
S=$(x client cat /tmp/kill.json); echo "      one bridge killed: $S"
G=$(echo "$S" | jq_ worst_gap_ms)
if [ "$G" -le 100 ]; then ok "bridge failure causes under 100 ms of disruption"; else bad "bridge failure causes under 100 ms of disruption" "$S"; fi
start_relay bridge1

# Restart the exit: the client must reconnect by itself.
x exit pkill -x lagrelayd; sleep 1; start_relay exit; sleep 1
if wait_up; then ok "client reconnects after exit restart"; else bad "client reconnects after exit restart" "$(x client tail -3 /tmp/client.log)"; fi
sleep 12
check "tunnel still works after reconnect" "$(x client python3 /e2e/probe.py echo)" "172.30.3.20"

if stop_client; then ok "client shuts down on Ctrl+C"; else bad "client shuts down on Ctrl+C"; fi
check "shutdown removes the TUN device" "$(x client sh -c 'ip link show lagrelay-c0 >/dev/null 2>&1 && echo present || echo gone')" "gone"
check "traffic stops being tunnelled after shutdown" "$(x client python3 /e2e/probe.py echo)" "no-reply"
x client lagrelay history | grep -q testgame && ok "session saved to history" || bad "session saved to history"

# Quality routing: slow one route; with a single active route it must avoid it.
if [ $TC -eq 0 ]; then
  x bridge1 tc qdisc add dev eth0 root netem delay 80ms
  connect --routes 1; wait_up >/dev/null; sleep 3
  L=$(x client sh -c "tail -1 /tmp/client.log")
  case "$L" in *"routes=[b2 > exit1"*) ok "route selection picks the faster bridge";; *) bad "route selection picks the faster bridge" "$L";; esac
  stop_client; x bridge1 tc qdisc del dev eth0 root
fi

# Simulates an ISP that routes each flow differently: one set of source ports gets
# 40 ms of extra delay. The client must find the fast ports, and must move to the
# others by itself when the slow set flips mid-session.
ports_slow() { # 0 = even source ports slow, 1 = odd
  x client tc qdisc replace dev eth0 root handle 1: prio
  x client tc qdisc replace dev eth0 parent 1:3 handle 30: netem delay 40ms
  x client tc filter del dev eth0 parent 1: 2>/dev/null
  x client tc filter add dev eth0 parent 1: protocol ip prio 1 u32 match udp src $1 0x1 at 20 flowid 1:3 2>/dev/null ||
    x client tc filter add dev eth0 parent 1: protocol ip prio 1 u32 match u16 $1 0x1 at 20 flowid 1:3
}
active_ports() { x client sh -c "tail -1 /tmp/client.log" | sed -E 's/.*routes=\[([^]]*)\].*/\1/' | grep -oE ':[0-9]+ ' | tr -d ': '; }
all_have_parity() { # parity
  P_=$(active_ports); [ -n "$P_" ] || return 1
  for q in $P_; do [ $((q % 2)) -eq "$1" ] || return 1; done
}
if [ $TC -eq 0 ]; then
  ports_slow 0
  connect --routes 2; wait_up >/dev/null; sleep 3
  if all_have_parity 1; then ok "finds the fast source ports at startup"; else bad "finds the fast source ports at startup" "$(x client tail -1 /tmp/client.log)"; fi
  L=$(x client python3 /e2e/probe.py stream 3 50); echo "      with slow ports avoided: $L"
  P50=$(echo "$L" | jq_ p50_ms)
  if python3 -c "import sys;sys.exit(0 if $P50 < 25 else 1)"; then ok "game traffic avoids the slow path"; else bad "game traffic avoids the slow path" "$L"; fi
  ports_slow 1
  MOVED=no; for _ in $(seq 1 60); do sleep 1; all_have_parity 0 && { MOVED=yes; break; }; done
  if [ "$MOVED" = yes ]; then ok "moves to fast ports when conditions change"; else bad "moves to fast ports when conditions change" "$(x client tail -1 /tmp/client.log)"; fi
  stop_client; x client tc qdisc del dev eth0 root
fi

# The built-in direct route: give the client its own path to the game server.
docker network connect --ip 172.30.3.10 $P-c $P-client
DIF=$(x client sh -c "ip -o -4 addr show | awk '/172.30.3.10/{print \$2}'")
SELF=172.30.3.10; EXIT=172.30.3.20
seen() { x client python3 /e2e/probe.py echo; }
wait_seen() { end=$((SECONDS + $2)); while [ $SECONDS -lt $end ]; do [ "$(seen)" = "$1" ] && return 0; sleep 1; done; return 1; }

connect --routes 1 --flows 4; sleep 3
check "direct is used when it's the fastest route" "$(x client python3 /e2e/probe.py once)" "$SELF"
check "direct path downloads correctly" "$(x client python3 /e2e/probe.py download | cut -d' ' -f1)" "identical"
sleep 3 # Status lines are written every 2 seconds.
x client sh -c "tail -1 /tmp/client.log" | grep -q "172.30.3.30 direct" && ok "dashboard data shows the server on direct" || bad "dashboard data shows the server on direct" "$(x client tail -1 /tmp/client.log)"
stop_client
check "no rules left after quitting" "$(x client sh -c 'ip rule | grep -cE "^7[567]00:"')" "0"

connect --routes 1 --flows 4 --no-direct; sleep 3
check "--no-direct always uses the relay" "$(x client python3 /e2e/probe.py once)" "$EXIT"
stop_client

if [ $TC -eq 0 ]; then
  x client tc qdisc add dev $DIF root netem delay 60ms
  connect --routes 1 --flows 4; sleep 3
  check "relay is used when direct is slower" "$(x client python3 /e2e/probe.py once)" "$EXIT"
  # Every relay down: live traffic falls back to direct, the backup.
  x exit pkill -x lagrelayd
  if wait_seen $SELF 40; then ok "direct takes over when all relays fail"; else bad "direct takes over when all relays fail" "$(seen)"; fi
  start_relay exit; sleep 1; stop_client

  # Direct stays better for live traffic only with --live-switch.
  connect --routes 1 --flows 4 --live-switch; sleep 3
  check "live switch starts on the relay" "$(seen)" "$EXIT"
  x client tc qdisc del dev $DIF root
  if wait_seen $SELF 60; then ok "--live-switch moves live traffic to direct once it's better"; else bad "--live-switch moves live traffic to direct once it's better" "$(seen)"; fi
  stop_client

  # Without the flag, the same improvement must not touch live traffic.
  x client tc qdisc add dev $DIF root netem delay 60ms
  connect --routes 1 --flows 4; sleep 3; seen >/dev/null
  x client tc qdisc del dev $DIF root
  sleep 25
  check "by default live traffic isn't moved just for speed" "$(seen)" "$EXIT"
  stop_client
fi

# Direct goes down while in use: the relay takes over as the backup.
connect --routes 1 --flows 4; sleep 3; seen >/dev/null
docker exec -d $P-client sh -c "python3 /e2e/probe.py sticky 50 >/tmp/sticky.txt"
sleep 3
x client iptables -I OUTPUT -o $DIF -j DROP
if wait_seen $EXIT 45; then ok "relay takes over when direct fails"; else bad "relay takes over when direct fails" "$(seen)"; fi
sleep 3
x client iptables -D OUTPUT -o $DIF -j DROP
# The probe only writes its result when it finishes.
for _ in $(seq 1 60); do x client pgrep -f "probe.py sticky" >/dev/null || break; sleep 1; done
ST=$(x client cat /tmp/sticky.txt)
case "$ST" in "$SELF $EXIT"*) ok "an open socket keeps working through the move ($ST)";; *) bad "an open socket keeps working through the move" "server saw: $ST";; esac
stop_client
LEFT=$(x client sh -c "iptables-save 2>/dev/null | grep -c lagrelay-c0")
check "no firewall rules left after quitting" "$LEFT" "0"
docker network disconnect $P-c $P-client

# `lagrelay off`: from another terminal, while running, and after a crash.
connect --routes 1 --flows 4 --no-direct; wait_up >/dev/null
OUT=$(x client lagrelay off 2>&1)
case "$OUT" in *"LagRelay stopped"*) ok "off stops a running session";; *) bad "off stops a running session" "$OUT";; esac
check "off leaves no process behind" "$(x client sh -c 'pgrep -x lagrelay | wc -l')" "0"
x client tail -2 /tmp/client.log | grep -q "session: testgame" && ok "off lets the session exit cleanly" || bad "off lets the session exit cleanly" "$(x client tail -2 /tmp/client.log)"
check "traffic isn't tunnelled after off" "$(x client python3 /e2e/probe.py echo)" "no-reply"
OUT=$(x client lagrelay off 2>&1)
case "$OUT" in *"isn't running"*) ok "off is safe when nothing is running";; *) bad "off is safe when nothing is running" "$OUT";; esac

connect --routes 1 --flows 4; wait_up >/dev/null
OUT=$(x client lagrelay connect testgame --plain 2>&1)
case "$OUT" in *"already running"*) ok "a second session is refused";; *) bad "a second session is refused" "$OUT";; esac
x client pkill -KILL -x lagrelay; sleep 1
check "a crash leaves routing behind (test setup)" "$(x client sh -c 'ip rule | grep -cE "^7[567]00:" | grep -qv "^0$" && echo yes || echo no')" "yes"
OUT=$(x client lagrelay off 2>&1)
case "$OUT" in *"left routing behind"*) ok "off clears routing left by a crash";; *) bad "off clears routing left by a crash" "$OUT";; esac
check "no rules left after off" "$(x client sh -c 'ip rule | grep -cE "^7[567]00:"')" "0"
check "no firewall rules left after off" "$(x client sh -c 'iptables-save 2>/dev/null | grep -c lagrelay-c0')" "0"

# Security: a client whose key isn't authorized gets nothing.
x client2 lagrelay relay add "$(x exit lagrelayd link | sed 's/172.30.2.20/172.30.1.11/')" >/dev/null
x client2 lagrelay relay add "$(x bridge1 lagrelayd link)" >/dev/null
OUT=$(x client2 lagrelay scan 2>&1)
case "$OUT" in *b1*"no reply"*) ok "unauthorized client is refused";; *) bad "unauthorized client is refused" "$OUT";; esac
# The right key with the wrong token must also get nothing, and the relay must not
# reveal whether a token was close: it stays completely silent.
x client sh -c "mkdir -p /tmp/wrongtok && sed -E 's/lrt_[A-Za-z0-9_-]+/lrt_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/' ~/.config/lagrelay/config.toml > /tmp/wrongtok/config.toml"
OUT=$(docker exec -e LAGRELAY_HOME=/tmp/wrongtok $P-client lagrelay scan 2>&1)
case "$OUT" in *b1*"no reply"*) ok "authorized key with a wrong token is refused";; *) bad "authorized key with a wrong token is refused" "$OUT";; esac
x exit sh -c "lagrelayd link" | grep -q 'token=lrt_' && ok "client link carries the token" || bad "client link carries the token"
x exit sh -c "grep -q lrt_ /tmp/relay.log" && bad "access token must never reach the relay log" || ok "access token never reaches the relay log"
x bridge1 sh -c "grep -q 'client2' /tmp/relay.log" && bad "relay never logged the unauthorized client" || ok "relay never logged the unauthorized client"

# Diagnostics need an exit on a direct path; give the client one through net-b.
docker network connect --ip 172.30.2.10 $P-b $P-client
OUT=$(x client lagrelay scan 2>&1); echo "$OUT" | sed 's/^/      /'
case "$OUT" in *exit1*" ms"*ok*) ok "lagrelay scan measures relays";; *) bad "lagrelay scan measures relays" "$OUT";; esac
OUT=$(x client lagrelay diag speed --relay exit1 --secs 1 2>&1); echo "$OUT" | tail -1 | sed 's/^/      /'
case "$OUT" in *"download "*Mbit*"upload "*Mbit*) ok "speed test reports both directions";; *) bad "speed test reports both directions" "$OUT";; esac
OUT=$(x client lagrelay diag compare 172.30.3.30:9001 2>&1); echo "$OUT" | sed 's/^/      /'
case "$OUT" in *"via exit1"*ms*) ok "exit-to-game latency probe works";; *) bad "exit-to-game latency probe works" "$OUT";; esac

OUT=$(x client lagrelay diag bufferbloat --relay exit1 2>&1); echo "$OUT" | tail -2 | sed 's/^/      /'
case "$OUT" in *"under upload load"*grade*) ok "bufferbloat test grades latency under load";; *) bad "bufferbloat test grades latency under load" "$OUT";; esac

# With the default setting, private addresses must be unreachable through the exit.
x exit sed -i '/^allow_private_destinations/d' /etc/lagrelay/relayd.toml
x exit pkill -x lagrelayd; sleep 1; start_relay exit; sleep 1
OUT=$(x client lagrelay diag compare 172.30.3.30:9001 2>&1)
case "$OUT" in *"via exit1"*"cannot reach"*) ok "default relay refuses private destinations";; *) bad "default relay refuses private destinations" "$OUT";; esac

# The one-word preset: on Linux it has no CIDR, so it must fall back cleanly.
OUT=$(docker exec $P-client timeout -s INT 6 lagrelay optimize faceit --plain 2>&1)
case "$OUT" in *"Optimizing for CS2 on FACEIT"*"only tweaks are active"*"Restoring PC settings"*) ok "optimize faceit falls back to tweaks and restores";; *) bad "optimize faceit falls back to tweaks and restores" "$OUT";; esac
x client lagrelay game list | grep -q 'faceit .*cs2.exe' && ok "optimize creates the game profile" || bad "optimize creates the game profile"

echo; echo "passed $PASS, failed $FAIL"
[ "$FAIL" -eq 0 ]
