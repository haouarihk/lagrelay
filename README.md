# LagRelay

Route your game's traffic through relay servers you host yourself. It's a terminal app for Windows, with Linux support growing. It has no accounts, subscriptions or telemetry: the only servers involved are yours.

This is an independent program, not affiliated with ExitLag. It was designed after studying how ExitLag behaves (see [docs/REVERSE_ENGINEERING.md](docs/REVERSE_ENGINEERING.md)) and shares no code, drivers or server access with it.

## Downloads

Builds for every push are on the [Actions](../../actions) page, and tagged versions are on [Releases](../../releases). Each archive has both the client (`lagrelay`) and the relay (`lagrelayd`).

| Archive | Client | Relay |
|---|---|---|
| `lagrelay-windows-x64.zip` | Full, with per-process capture | Bridge only |
| `lagrelay-linux-x64.tar.gz` | Selects games by network | Bridge and exit |
| `lagrelay-linux-arm64.tar.gz` | Selects games by network | Bridge and exit |

## Quick start

**1. Set up a relay** on a Linux VPS close to the game servers:

```bash
tar xzf lagrelay-linux-x64.tar.gz && cd lagrelay-linux-x64
sudo ./install-relay.sh --name tokyo --public-addr 203.0.113.5 --exit
```

Open UDP port 41820 in your provider's firewall.

**2. On your PC**, unzip `lagrelay-windows-x64.zip`, open a terminal as Administrator in that folder, and run:

```powershell
.\lagrelay.exe key
```

**3. Authorize the PC** on the relay using that key:

```bash
sudo lagrelayd add-client my-pc 'PASTE_KEY' && sudo systemctl restart lagrelayd
sudo lagrelayd link
```

The link contains the relay's access token, so treat it like a password. If it leaks, run `sudo lagrelayd rotate-token`, restart the relay, and add the new link on your PCs.

**4. Add the relay and play:**

```powershell
.\lagrelay.exe relay add "lagrelay://...the link from above..."
.\lagrelay.exe doctor
.\lagrelay.exe optimize cs2
```

## One-command optimizing

```powershell
lagrelay optimize cs2        # CS2 on Valve servers
lagrelay optimize faceit     # CS2 on FACEIT
```

This applies the PC tweaks, connects through your relays, and shows a live dashboard. When you press `q`, it disconnects and restores your settings.

| Option | Effect |
|---|---|
| `--exit tokyo` | Use this exit relay instead of choosing automatically |
| `--tweaks-only` | Only tune the PC; relay nothing |
| `--dns` | Also switch to the fastest DNS server (your previous DNS is restored afterwards) |
| `--keep` | Leave tweaks applied after quitting |
| `--revert` | Undo anything left applied, for example after a crash |

Tweaks in this preset: Ultimate Performance power plan, core parking off, Game Bar capture off, high-priority network marking, high CPU priority for `cs2.exe` (applies the next time CS2 starts), high-performance GPU preference, and 0.5 ms timer resolution.

The presets are careful around anti-cheat by design:

- LagRelay never opens a handle to `cs2.exe` or any anti-cheat process, and never injects into the game or edits its files. It finds which process owns a connection from Windows' system tables.
- On FACEIT, only `cs2.exe`'s traffic is relayed. The FACEIT client and anti-cheat keep your direct connection.

### Before using it on FACEIT

- **FACEIT may refuse WinDivert, the packet capture driver.** FACEIT blocks some drivers, and I couldn't find anything that says whether WinDivert is allowed. If capture fails, or the anti-cheat complains, LagRelay leaves your traffic direct and keeps only the tweaks. Working around the anti-cheat isn't supported.
- **The game server sees your relay's IP.** FACEIT publishes no clear policy on this that I could find. If your account matters to you, ask FACEIT support first.
- FACEIT's [safe tools list](https://support.faceit.com/hc/en-us/articles/360015788779-What-is-deemed-to-be-a-cheat) names Timer Resolution, but it doesn't cover every tweak here. It also isn't exhaustive.

## What a relay can and can't do

A relay helps when your ISP takes a poor route to the game server. It can't beat the speed of light, and on a route that's already good it can add latency. Compare before you commit:

```powershell
lagrelay diag compare 203.0.113.50:27015
```

## All commands

| Command | What it does |
|---|---|
| `optimize cs2` / `faceit` | Everything above, in one command |
| `key` | Print this PC's public key |
| `relay add` / `list` / `rm` | Manage relays |
| `game add NAME --process x.exe` | Add any other game |
| `connect GAME [--routes N] [--flows N] [--no-direct] [--live-switch] [--multi-internet] [--max-bridges N]` | Connect a game without tweaks |
| `scan` | Latency to each relay |
| `diag speed` / `bufferbloat` / `compare` / `ping` / `trace` | Network tests |
| `dns test` / `apply fastest` / `reset` / `flush` | DNS optimizer |
| `boost list` / `apply NAME` / `revert` | Individual reversible tweaks |
| `ram` | Trim idle memory from background apps |
| `shape on` / `off` | Limit bulk traffic to reduce lag |
| `sys` | CPU, RAM, GPU, networks |
| `history` | Past sessions |
| `doctor` | Check that this PC is ready |

## How routing works

```
game --> LagRelay --> bridge (optional) --> exit relay --> game server
              \-----> bridge (optional) ---/
```

- **Multipath:** each packet is sent over several routes (2 by default) and the first copy to arrive wins, so one route's loss or outage doesn't reach the game.
- **Fastest-path search:** some ISPs send each connection down a different path, so the same relay can differ by 20 ms or more depending on the source port. LagRelay tries 16 flows when it connects, keeps the fastest few, and tries 4 new ones every 30 seconds while you play. Set `--flows 1` to turn this off. `lagrelay scan` shows the best, typical and worst flow to each relay.
- **Built-in `direct` route:** the plain internet route is always in the list. Each game server is measured both ways when first contacted, and uses direct unless a relay is at least 3 ms faster. It's also the backup: if every relay fails, traffic moves to direct, and if direct fails, it moves to a relay. Unlike switching between relays, moving a live connection between direct and a relay changes the IP the game server sees, so being faster only affects new connections unless you pass `--live-switch`, which may drop you from a match. Use `--no-direct` to always relay.
- **Route optimizer:** every route is measured continuously. Failed routes are replaced straight away. A healthy route is only replaced by one that's clearly better for several seconds, which prevents flapping.
- **Recovery:** packets lost on all routes are requested again, if they're still fresh enough to be useful.
- **Multi Internet:** `--multi-internet` sends over every network you have, for example Ethernet and a phone hotspot.
- **Encryption:** every hop uses Noise IKpsk0 with ChaCha20-Poly1305. Bridges see only encrypted data.
- **Access control:** a client needs both the relay's access token and a key you've authorized. The token never travels over the network, and a relay gives no reply at all to anyone without both, so scanners can't even tell it's there. Handshake attempts are also rate limited.

More relays give more route choices. Add bridge-only relays by leaving out `--exit` during install.

## Limitations

- Windows capture has not yet been tested on real Windows with the driver loaded. See [docs/STATUS.md](docs/STATUS.md).
- IPv4 only. A matched game's IPv6 traffic is dropped so it falls back to IPv4 (`block_ipv6` in the config).
- TCP connections opened before you connect stay direct until the game reconnects, so start LagRelay before the game.
- On Linux, games are selected by destination network (`--cidr`), not by process, so the `cs2` and `faceit` presets only apply tweaks there.
- The Windows traffic shaper limits upload only.

## Releasing

Push a version tag to build and publish a release:

```bash
git tag v0.1.0 && git push origin v0.1.0
```

## Building

Needs Rust, plus [cargo-zigbuild](https://github.com/rust-cross/cargo-zigbuild) and zig for cross-compiling.

```bash
cargo test --workspace
scripts/package.sh           # creates the archives in dist/
tests/e2e/run.sh             # end-to-end test on Docker networks
```

WinDivert is LGPLv3/GPLv2 and is shipped as separate, unmodified files. Its licence is included in the Windows archive.
