#!/usr/bin/env bash
# Installs or upgrades the LagRelay relay on a Linux server.
#
#   curl -fsSL https://raw.githubusercontent.com/haouarihk/lagrelay/main/install.sh | sudo bash
#
# Options (after `sudo bash -s --` when piping):
#   --name NAME         Relay name shown to clients (default: this machine's hostname)
#   --public-addr ADDR  Address clients connect to (default: detected public IPv4)
#   --port PORT         UDP port (default: 41820)
#   --bridge            Forward traffic only, instead of also being an internet exit
#   --client KEY        Authorize a client's public key (from `lagrelay key`)
#   --client-name NAME  Name for that client (default: my-pc)
#   --version TAG       Install a specific release, such as v0.1.0 (default: latest)
#   --arch ARCH         x64 or arm64 (default: detected)
#   --uninstall         Remove the service and binary; add --purge to delete the config and keys
set -euo pipefail

REPO=haouarihk/lagrelay
RELEASE_URL=${LAGRELAY_RELEASE_URL:-https://github.com/$REPO/releases}
BIN=/usr/local/bin/lagrelayd
CONFIG=/etc/lagrelay/relayd.toml
UNIT=/etc/systemd/system/lagrelayd.service

NAME=$(hostname 2>/dev/null || echo relay)
PUBLIC_ADDR=""; PORT=41820; EXIT=1; CLIENT=""; CLIENT_NAME=my-pc; VERSION=""; ARCH=""; UNINSTALL=0; PURGE=0

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
need_value() { [ $# -ge 2 ] && [ -n "$2" ] || die "$1 needs a value"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --name) need_value "$@"; NAME=$2; shift 2 ;;
    --public-addr) need_value "$@"; PUBLIC_ADDR=$2; shift 2 ;;
    --port) need_value "$@"; PORT=$2; shift 2 ;;
    --bridge) EXIT=0; shift ;;
    --exit) EXIT=1; shift ;;
    --client) need_value "$@"; CLIENT=$2; shift 2 ;;
    --client-name) need_value "$@"; CLIENT_NAME=$2; shift 2 ;;
    --version) need_value "$@"; VERSION=$2; shift 2 ;;
    --arch) need_value "$@"; ARCH=$2; shift 2 ;;
    --uninstall) UNINSTALL=1; shift ;;
    --purge) PURGE=1; shift ;;
    -h|--help) sed -n '2,16p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//' || true; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[ "$(uname -s)" = Linux ] || die "this installer is for Linux servers"
[ "$(id -u)" = 0 ] || die "run this as root, for example with sudo"
HAS_SYSTEMD=0; command -v systemctl >/dev/null 2>&1 && [ -d /etc/systemd/system ] && HAS_SYSTEMD=1

if [ "$UNINSTALL" = 1 ]; then
  if [ "$HAS_SYSTEMD" = 1 ]; then
    systemctl disable --now lagrelayd 2>/dev/null || true
    rm -f "$UNIT"; systemctl daemon-reload
  fi
  rm -f "$BIN"
  [ "$PURGE" = 1 ] && rm -rf /etc/lagrelay
  say "LagRelay relay removed."
  [ "$PURGE" = 1 ] || say "The config and keys are still in /etc/lagrelay. Add --purge to delete them."
  say "Close UDP port $PORT in your firewall if nothing else uses it."
  exit 0
fi

for t in curl tar sha256sum; do command -v "$t" >/dev/null 2>&1 || die "$t is required; install it and run this again"; done
case "$PORT" in ''|*[!0-9]*) die "--port must be a number" ;; esac
[ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || die "--port must be between 1 and 65535"
if [ "$EXIT" = 1 ]; then
  for t in ip iptables; do
    command -v "$t" >/dev/null 2>&1 || die "$t is required for an exit relay; install iproute2 and iptables, or use --bridge"
  done
  [ -e /dev/net/tun ] || die "/dev/net/tun is missing, which an exit relay needs; load the tun module, or use --bridge"
fi

if [ -z "$ARCH" ]; then
  case "$(uname -m)" in
    x86_64|amd64) ARCH=x64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) die "no build for $(uname -m); releases cover x64 and arm64" ;;
  esac
fi
case "$ARCH" in x64|arm64) ;; *) die "--arch must be x64 or arm64" ;; esac

ARCHIVE=lagrelay-linux-$ARCH.tar.gz
if [ -n "$VERSION" ]; then BASE=$RELEASE_URL/download/$VERSION; else BASE=$RELEASE_URL/latest/download; fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
say "Downloading $ARCHIVE..."
curl -fsSL --retry 3 -o "$TMP/$ARCHIVE" "$BASE/$ARCHIVE" || die "could not download $BASE/$ARCHIVE"
curl -fsSL --retry 3 -o "$TMP/SHA256SUMS.txt" "$BASE/SHA256SUMS.txt" || die "could not download the checksums"
grep -F " $ARCHIVE" "$TMP/SHA256SUMS.txt" > "$TMP/expected" || die "$ARCHIVE isn't listed in the checksums"
(cd "$TMP" && sha256sum --quiet -c expected) || die "checksum mismatch; the download is corrupt or was tampered with, so nothing was installed"
tar -xzf "$TMP/$ARCHIVE" -C "$TMP"
SRC=$TMP/lagrelay-linux-$ARCH/lagrelayd
[ -f "$SRC" ] || die "the archive doesn't contain lagrelayd"
"$SRC" --version >/dev/null 2>&1 || die "the $ARCH build won't run on this machine"

UPGRADE=0; [ -e "$BIN" ] && UPGRADE=1
install -m 755 "$SRC" "$BIN"
say "Installed $("$BIN" --version)."

if [ -f "$CONFIG" ]; then
  say "Keeping the existing config and keys in $CONFIG."
else
  if [ -z "$PUBLIC_ADDR" ]; then
    say "Detecting this server's public IP..."
    PUBLIC_ADDR=$(curl -4 -fsS --max-time 10 https://api.ipify.org || true)
    case "$PUBLIC_ADDR" in
      *.*.*.*) ;;
      *) die "could not detect the public IP; pass it with --public-addr" ;;
    esac
  fi
  INIT=(init --name "$NAME" --public-addr "$PUBLIC_ADDR" --port "$PORT")
  [ "$EXIT" = 1 ] && INIT+=(--exit)
  # Its output holds the access token, which shouldn't end up in terminal logs.
  "$BIN" "${INIT[@]}" >/dev/null
  say "Created $CONFIG with a new key and access token."
fi
PORT=$(sed -n 's/^port = \([0-9]*\).*/\1/p' "$CONFIG" | head -1)

if [ -n "$CLIENT" ]; then
  if "$BIN" clients | grep -qF "$CLIENT"; then
    say "That client key is already authorized."
  else
    "$BIN" add-client "$CLIENT_NAME" "$CLIENT" >/dev/null || die "could not authorize that key; check it and the name '$CLIENT_NAME'"
    say "Authorized client '$CLIENT_NAME'."
  fi
fi

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
  ufw allow "$PORT/udp" comment lagrelay >/dev/null && say "Opened UDP $PORT in ufw."
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  firewall-cmd -q --permanent --add-port="$PORT/udp" && firewall-cmd -q --reload && say "Opened UDP $PORT in firewalld."
elif command -v iptables >/dev/null 2>&1 && iptables -S INPUT 2>/dev/null | grep -qE -- '-j (REJECT|DROP)|^-P INPUT DROP'; then
  # For example Oracle's Ubuntu images, which block everything by default.
  iptables -C INPUT -p udp --dport "$PORT" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p udp --dport "$PORT" -j ACCEPT
  say "Opened UDP $PORT in iptables."
  if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save >/dev/null 2>&1 || true
  else
    say "note: that iptables rule won't survive a reboot unless you save it."
  fi
fi

if [ "$HAS_SYSTEMD" = 1 ]; then
  cat > "$UNIT" <<UNIT
[Unit]
Description=LagRelay relay
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$BIN run
Restart=always
RestartSec=2
# Needs root for TUN, routes and NAT when acting as an exit.
NoNewPrivileges=true
ProtectHome=true
PrivateTmp=true
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable lagrelayd >/dev/null 2>&1
  systemctl restart lagrelayd
  systemctl is-active --quiet lagrelayd || die "the relay didn't start; see: journalctl -u lagrelayd -n 30"
  say "Relay service is running."
else
  say "systemd wasn't found, so start the relay yourself: lagrelayd run"
fi

say ""
[ "$UPGRADE" = 1 ] && say "Upgrade finished." || say "Install finished."
say "Open UDP port $PORT in your cloud provider's firewall too, if it has one."
say ""
say "Next steps:"
if [ -z "$CLIENT" ] && [ -z "$("$BIN" clients)" ]; then
  say "  1. On your PC, run: lagrelay key"
  say "  2. Here, authorize it:"
  say "       sudo lagrelayd add-client my-pc 'PASTE_KEY' && sudo systemctl restart lagrelayd"
  say "  3. Here, get the client link. Keep it private, it contains the access token:"
  say "       sudo lagrelayd link"
  say "  4. On your PC, add it:  lagrelay relay add 'PASTE_LINK'"
else
  say "  1. Here, get the client link. Keep it private, it contains the access token:"
  say "       sudo lagrelayd link"
  say "  2. On your PC, add it:  lagrelay relay add 'PASTE_LINK'"
fi
