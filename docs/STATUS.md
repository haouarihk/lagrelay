# Test status

## Verified

| Area | How | Result |
|---|---|---|
| Protocol, packet handling, routing logic, parsers | Unit tests on Linux | 107 pass |
| Same core and client tests on a Windows build | Run under Wine (Debian trixie) | 85 pass |
| Relay, multipath and Linux capture | `tests/e2e/run.sh`: real TUN devices, NAT and netem on isolated Docker networks | 54 of 54 checks pass |
| Windows capture filter | Compiled by the real `WinDivert.dll` | Accepted |
| Windows binary | Under Wine: version, key, relay and game commands, doctor, and `optimize --tweaks-only` | Works, and imports only standard Windows DLLs |
| Tweak undo order | Apply and revert under Wine for Game Bar, QoS and priority | Restored |

End-to-end measurements, on a local Docker network so latency is near zero:

- 40% packet loss on one of two routes: 0 of 500 packets lost.
- One bridge killed mid-stream: 0 of 800 packets lost.
- A 20 MiB TCP download arrived byte-identical at 200-340 Mbit/s.
- The client reconnected by itself after the exit relay restarted.

## Live relay (Oracle Paris, ARM64)

Tested against the installed service over a real ISP connection:

- Traffic through the relay reached a public website, which saw the relay's IP.
- Throughput was 76 Mbit/s down and 71 Mbit/s up.
- A wrong access token, an unauthorized key and random packets all got no reply.
- A private destination was refused.

Flow search, 5 connections each on that route, during a moderate slowdown on the ISP's side: a single flow gave 48-54 ms (median 53), and searching 16 flows gave 47-49 ms (median 49). In the end-to-end suite, where one set of source ports was delayed by 40 ms, it chose only fast ports and moved when the slow set flipped mid-session.

## Direct route

In the end-to-end suite, on Linux capture:

- Direct was used when fastest, and the relay when direct was slower.
- Traffic moved to direct when every relay failed, and to the relay when direct failed.
- One open socket kept working through a move from direct to the relay.
- `--live-switch` moved live traffic, and without it live traffic stayed put.

The Windows version of this logic compiles but has never run, because it needs the capture driver. Whether a real game survives a move between routes is untested. It changes the IP the game server sees, so expect a disconnect.

## ISP routing can vary per connection

The same server measured 46-65 ms depending only on the UDP source port, and each port stayed consistent during the test. This looks like ISP load balancing across paths. A single ping result is therefore one draw from a range, and comparisons between providers need many flows.

## Not verified

- **Windows capture on real Windows.** Wine can't load kernel drivers, so opening the driver, per-process matching, rewriting and injecting packets have never run. This code has only been read closely, by me and an independent reviewer, whose findings were fixed.
- **CS2 and FACEIT.** No real game has been played through this. Any latency benefit is unmeasured.
- **FACEIT Anti-Cheat with WinDivert.** Unknown. It may refuse to run alongside the driver.
- **Real Windows tool behaviour.** Under Wine, `powercfg` is missing and PowerShell is a stub, so these are unproven: the power plan, core parking, SysMain, NetQos policies, DNS changes, the traffic shaper and the RAM cleaner.
- **Real internet paths.** Flow search picked faster flows on your live route, but switching routes during real congestion has only been tested with artificial delay and loss.
- **`install.sh` on a real VPS.** It has been tested in containers, with `systemctl` simulated, but not on a real server with systemd.
- **Linux tweaks and shaping** (`tc cake`, `resolvectl`, CPU governor).

## First run on Windows

Do these in order, as Administrator. Start without FACEIT running.

1. `lagrelay doctor`: every line should say `ok`.
2. `lagrelay scan`: your relays should answer.
3. `lagrelay boost apply power gamebar`, check `lagrelay boost list`, then `lagrelay boost revert`. Confirm your power plan came back.
4. Run `lagrelay game add test --process curl.exe --process powershell.exe`, then `lagrelay connect test`. In a second terminal, run `curl.exe https://api.ipify.org`. It should print your relay's IP.
5. Press `q`, then run the same `curl` again. It should print your own IP, and your internet should work normally.
6. `lagrelay optimize cs2`, then play a Valve match or community server.
7. Only after that, try `lagrelay optimize faceit`. If FACEIT complains, quit LagRelay. Don't try to work around it.

If internet access breaks at any point, closing LagRelay releases the driver. Rebooting always clears it.
