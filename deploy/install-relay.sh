#!/usr/bin/env bash
# Installs the relay on a Linux VPS. Run as root from the unpacked release folder:
#   ./install-relay.sh --name tokyo --public-addr 203.0.113.5 --exit
# Omit --exit for a bridge-only relay.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
HERE=$(cd "$(dirname "$0")" && pwd)
install -m 755 "$HERE/lagrelayd" /usr/local/bin/lagrelayd
if [ ! -f /etc/lagrelay/relayd.toml ]; then
  lagrelayd init "$@"
else
  echo "keeping the existing /etc/lagrelay/relayd.toml and its key"
fi
install -m 644 "$HERE/lagrelayd.service" /etc/systemd/system/lagrelayd.service
systemctl daemon-reload
systemctl enable --now lagrelayd
if command -v ufw >/dev/null && ufw status | grep -q active; then
  ufw allow 41820/udp
fi
echo
echo "Relay running. Make sure UDP 41820 is open in your provider's firewall too."
echo "Next: on your PC run 'lagrelay key', then here:"
echo "  lagrelayd add-client MY-PC <key> && systemctl restart lagrelayd"
echo "Then get the client link with: sudo lagrelayd link"
echo "Keep it private: it contains this relay's access token."
