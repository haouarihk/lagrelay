# How ExitLag 5.24.0 works

Findings from static analysis of `SetupExitLag-5.24.0-x64.exe` (SHA-256 `8e1482aa23169ee442e368fad1ad0c5767d20ce596ab8129b7e4cce24d18dc86`). The installer and the app were never run, and ExitLag's servers were never contacted.

LagRelay is an independent design informed by these findings. It contains no ExitLag code, drivers, assets or game data. Extracted files and decompiled output were kept out of this repository.

## Method

| Step | Tool | Result |
|---|---|---|
| Unpack the installer | A small custom parser, because REA and innoextract 1.9 can't read Inno Setup 6.7 | 1,491 files, all matching the installer's SHA-256 hashes |
| Read the install script | Strings from the decoded setup header | Drivers, services, install steps |
| Recover the API surface | PE export table of `libexitlag.dll` | Class and method names |
| Recover wire schemas | Protobuf descriptors embedded in `libexitlag.dll` | Control-plane messages |
| Read features and behaviour | Strings in `ExitLag.exe` and `libexitlag.dll`, including logs and QML paths | Feature list and internal logic |
| Confirm tuning details | [REA](https://github.com/morluto/rea) with Ghidra 12.1.4 (`decompile-all`, 86 `BridgePool` functions) | Timers and thresholds |

Evidence strength varies. Names and log strings show that a feature exists and roughly how it behaves, and exact algorithms were only checked where noted. The bridge-to-final-server wire format was not fully recovered because LagRelay doesn't need to be compatible with it.

## Architecture

```
Game --> driver capture --> libexitlag BridgePool --> Bridge --> Final Server --> game server
                                                  \-> Bridge --/
```

- **`ExitLag.exe`:** Qt 6/QML interface and most feature controllers.
- **`libexitlag.dll`:** the C++ network engine, built on Boost.Asio. Key classes are `API`, `NetworkMap`, `App`, `BridgePool` and `BridgePoolSocket`.
- **Bridges** are entry relays and **Final Servers** are exits. Routes can use one or two bridges ("dual-bridge").
- **Control plane:** HTTPS with protobuf (`ExitLag_WebService_Protocol_L2`) for login, the server and game database, remote pings, reports and remote config.

### Packet capture

The user can choose between two methods, and the app switches away from one if a firewall blocks it:

| Method | Driver | Notes |
|---|---|---|
| WFP | `nfextlag.sys` (NetFilter SDK, using WFP callouts) | Described as the current method. Needed for Multi Internet and Traffic Shaper |
| NDIS | `ndextlag.sys` (WinpkFilter) | "Legacy" option |

Both drivers are commercial SDKs, signed for ExitLag and licensed to it. LagRelay can't reuse them and uses WinDivert instead. ExitLag also warns when another WinDivert program, such as GoodbyeDPI, is running, and `lagrelay doctor` makes a similar check.

### Connection engine

Each proxied connection gets a `BridgePool`, which works like this:

- **Multipath:** data is sent over several bridge sockets, with separate TCP and UDP route counts per app.
- **Reliability:** sequence numbers, confirmations, retransmission requests and out-of-order handling across routes.
- **Route choice:** `NetworkMap` combines client-to-bridge pings with server-side pings (bridge to bridge, bridge to final, final to datacenter).
- **Failover:** a spare route replaces a failed bridge. A pool with no live bridges closes.
- **Optimizer:** a candidate replaces a route only if it beats a percentage threshold. The threshold rises after a switch and decays after 5 stable minutes (`300000000000` ns in `decay_route_optimization_threshold`). RTT and jitter stability use 10-second windows.
- **Background pinging:** a scheduler prioritises "high-potential" bridges and adds round-robin probes.
- **Other:** optional high UDP ports, a socket QoS option, and an `IpGroup` of game server ranges. It also recognises Steam Datagram Relay pings in a connection's first packets.

## Feature comparison

| ExitLag feature | LagRelay | How |
|---|---|---|
| Bridge and exit relays, single or dual bridge | Yes | Your own servers; `--max-bridges` |
| Multipath routes | Yes | `--routes N`, live `+`/`-` in the dashboard |
| Automatic exit selection | Yes | Measured latency, plus exit-to-game when `ping_target` is set |
| Manual exit selection | Yes | `--exit` |
| Region or continent selection | Not needed | Choose by relay name |
| Route optimizer with adaptive threshold | Yes | Same idea, with its own values |
| Spare routes and failover | Yes | All routes stay measured on standby |
| Retransmission | Yes | NACK-based, limited to fresh packets |
| Multi Internet with chosen networks | Yes | `--multi-internet`, `settings.interfaces` |
| Interface priority order | No | Best route per network is chosen automatically |
| Per-process capture | Yes, Windows | WinDivert plus system socket tables |
| Rules by IP range and port | Yes | `--cidr`, `--port` |
| Game database, icons, launcher integration | No | Proprietary, server-side data. Use presets or `game add` |
| Community servers | Partly | Use a profile with `--cidr` |
| IPv6 proxying | No | The game is pushed to IPv4 |
| DNS optimizer, apply, reset, flush | Yes | `dns` commands |
| Game-specific DNS override | No | Not built yet |
| Ping monitor, MTR-style trace | Partly | `diag ping`, `diag trace` use system tools |
| Speed test | Yes | Runs against your own relay |
| Bufferbloat test and grade | Yes | `diag bufferbloat` |
| Connection reports | Yes, local only | `history` |
| Hardware monitor | Partly | `sys`; NVIDIA GPU only, no history |
| Traffic Shaper | Partly | Windows upload per app; Linux CAKE. No download limits on Windows, no dynamic throttle |
| Ultimate power plan, core parking, Game Bar, SysMain | Yes | `boost`, all reversible |
| Timer resolution (Input Lag Reducer) | Yes | While `optimize` is running |
| Process priority | Yes | Set at launch by Windows, never touching the running game |
| Lower background process priority | No | Not built yet |
| GPU high performance | Partly | Windows GPU preference only. ExitLag also locks NVIDIA and AMD clocks |
| Unreal Engine booster | No | Edits game config files, which is a risk with anti-cheat |
| RAM cleaner | Yes, manual | `ram`. No scheduled runs |
| QoS marking, high UDP ports | Yes | `boost apply qos`, `extra_ports` on the relay |
| In-game overlay and FPS counter | No | Doesn't fit a terminal app; the dashboard shows ping |
| Autostart, tray icon | No | Not built yet |
| Accounts, trials, licensing, hardware ID, VM detection, analytics, surveys, remote config | Left out on purpose | Not needed for a personal tool |

## What wasn't copied

The game database, relay network and account system live on ExitLag's servers, so they can't be recovered from the client. Any such access would also need an ExitLag account and is out of scope. LagRelay doesn't talk to ExitLag's servers or bypass its licensing.
