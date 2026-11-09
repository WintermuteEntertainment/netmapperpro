# NetMapperPro architecture

Reference written 2026-11-08 for Tim and for future sessions. The "Before the refactor" section describes the single-file script at commit `a3a5f58`. The "After the refactor" section describes the package layout that replaced it.

## Two programs

1. **The scanner**: does all the real work. It started as one file, `NET_MAPPER_PRO.py`.
2. **The web app** (Flask, port 7890): a browser front end with a progress bar, pause and resume, a scan history and a filtered diagram. It lived in `Downloads\netmapper-web` until 2026-11-08 and now lives in `web/`. It imports the scanner rather than running it as a separate program.

## What a normal scan does (`--enhanced`)

1. **Find networks.** Reads this PC's adapters and routing table through PowerShell, then decides what it may sweep. The default scope is `attached`, meaning only networks this PC holds an address on.
2. **Find devices.** Reads Windows' neighbour (ARP) table, then pings every address on the swept networks. Each ping launch is paced by the rate limiter.
3. **Wi-Fi survey.** Reads what `netsh` already knows. It transmits nothing.
4. **Ask devices to identify themselves.** Sends mDNS and SSDP queries (link-local, TTL 1, so they cannot leave the subnet), then WS-Discovery probes for ONVIF cameras.
5. **Port check**, only with `--identify-silent`. TCP connect and close on 16 ports by default. Sends no data.
6. **Findings.** Compares against the previous baseline, checks for SSID impersonation, gateway tampering, duplicate MACs and weak Wi-Fi, rates channel crowding, and applies the watchlist.
7. **Write output.** Writes `secure_network_diagram.drawio.xml` for draw.io, `secure_network_dashboard.html`, `launch_secure.bat` (a Windows launcher that opens the dashboard), and `netmapper_baseline.json` for the next comparison.

## Before the refactor: the single file (6,255 lines)

| Lines | Section | Size | What it does |
|---|---|---|---|
| 1-177 | `Config` | 177 | Every setting, as class attributes on one global class |
| 179-362 | `SecurityValidator`, `RateLimiter`, `LegalDisclaimer` | 184 | Input checks, ping pacing, the disclaimer |
| 365-747 | `VendorDatabase` | 383 | MAC vendor lookup: about 130 built-in prefixes plus the `oui.csv` loader |
| 750-851 | `NetworkDevice` | 100 | The record kept for each device |
| 854-1295 | `SweepTarget`, `NetworkInterface`, `LocalNetworkEnumerator` | 440 | Adapter and route discovery |
| 1297-1969 | `SecureNetworkScanner` | 670 | Neighbour table, ping sweep, device type inference |
| 1972-2263 | `WifiNetwork`, `SecureWiFiScanner` | 290 | Wi-Fi model, `netsh` parsing, ours versus nearby |
| 2265-2747 | `EnhancedDiagramGenerator` | 480 | draw.io XML; one function is about 430 lines |
| 2749-3361 | `PassiveDiscovery`, `WSDiscovery` | 610 | Hand-written mDNS, SSDP and WS-Discovery |
| 3363-4181 | `ServiceProbe` | 820 | Port probing: depth tiers, target selection, banners |
| 4183-4371 | `ChannelAnalyzer` | 190 | Wi-Fi channel crowding |
| 4373-4490 | `VendorWatchlist` | 118 | Camera, storage and remote-access rules |
| 4493-4789 | `Finding`, `ThreatAnalyzer` | 297 | Findings, including the baseline comparison |
| 4791-5260 | `SecureDashboard` | 470 | The HTML page; one function is about 450 lines |
| 5261-5310 | baseline load and save | 50 | `netmapper_baseline.json` |
| 5312-5892 | `main_enhanced`, `main_original`, `main_probe_only` | 580 | The three scan modes |
| 5893-6255 | argument parsing, legal text, entry point | 360 | Command line and mode selection |

### Problems found

1. **The scan steps existed twice.** The web app's `run_scan()` (about 230 lines) repeated `main_enhanced()` instead of calling it, because `main_enhanced()` printed its results and returned nothing. The copies had already drifted: only the web copy supported progress, stop and pause.
2. **One global settings object**, mutated in 90 places. The web app worked around it with its own snapshot and restore of the defaults. Nothing needs two scans at once, so the fix is one shared way to reset and apply settings, not a redesign.
3. **Printing in the mode functions.** 110 of the 138 `print()` calls are in the three `main_*` functions. The scanner classes mostly report through `on_log` and `on_progress` hooks already. Printing never decides what the code does; it only meant the CLI's scan steps could not be reused.
4. **Two very long functions**: the diagram and the dashboard builders.
5. **Errors were hidden.** `main_enhanced()` caught every error and printed it, so a failed scan still exited with code 0.
6. **Overlap and leftovers.** `--original` ran a subset of `--enhanced` (enumerate, sweep, Wi-Fi, diagram, dashboard, with different file names and a different `.bat`) and none of discovery, probing, findings or baseline. `SecurityValidator.validate_mac_address` was never called. `RateLimiter` is used once, but that one use paces every ping, so it stays.
7. **Bugs seen in the 2026-11-08 scans**: sweep-only devices have no MAC, so baseline comparison reports them as gone and then new; Taichi's own Wi-Fi Direct network is labelled a neighbour; vendor names are cut at the first comma; the WSL VM's new MAC on each restart raises a warning.

## After the refactor: the `netmapper/` package (branch `refactor`, 2026-11-08)

`NET_MAPPER_PRO.py` is now a 24-line entry point. It puts its own folder on `sys.path` (`python -I` leaves it off), re-exports everything from the package, and calls `netmapper.cli.main()`.

| Module | Lines | Holds |
|---|---|---|
| `config.py` | 182 | `Config`, plus `Config.reset()` and the `SHOW_TRACEBACK` setting |
| `safety.py` | 203 | `SecurityValidator`, `RateLimiter`, `LegalDisclaimer` |
| `vendors.py` | 411 | `VendorDatabase`; looks for `oui.csv` in the repo root |
| `models.py` | 245 | `NetworkDevice`, `WifiNetwork`, `Finding`, `is_virtual_mac()` |
| `netenum.py` | 464 | `SweepTarget`, `NetworkInterface`, `LocalNetworkEnumerator` |
| `scanner.py` | 693 | `SecureNetworkScanner` |
| `wifi.py` | 220 | `SecureWiFiScanner` |
| `discovery.py` | 628 | `PassiveDiscovery`, `WSDiscovery` |
| `probe.py` | 835 | `ServiceProbe` |
| `channels.py` | 204 | `ChannelAnalyzer` |
| `watchlist.py` | 133 | `VendorWatchlist` |
| `threats.py` | 318 | `ThreatAnalyzer` |
| `diagram.py` | 501 | `EnhancedDiagramGenerator` |
| `dashboard.py` | 488 | `SecureDashboard` |
| `baseline.py` | 62 | baseline load and save |
| `pipeline.py` | 237 | `run_scan()`, `ScanResult`, `ScanCancelled`: the scan steps, once |
| `cli.py` | 814 | the three modes, file output, arguments, `main()` |

How the two front ends use it:

- **CLI:** `main_enhanced()` loads the baseline, calls `run_scan(on_log=print)`, then writes the diagram, dashboard, `.bat` launcher and new baseline, and prints the summary. `main_original()` calls `run_scan()` with discovery, probing and findings off. `main_probe_only()` is unchanged.
- **Web:** the worker loads the previous scan from `web/scans/`, calls `mapper.run_scan()` with its progress, stop and pause hooks, then writes the artifacts and `results.json` into the scan's folder. A stopped scan raises `ScanCancelled`, which carries the partial result.

Module dependencies run one way, except `netenum` and `scanner`, which use each other. `netenum` only calls `SecureNetworkScanner.run_cmd` inside functions, so its import sits at the bottom of the file, with a comment saying why.

### Web app before the move

- It imported `NET_MAPPER_PRO.py` from its parent folder, which was `Downloads`, not the repo.
- It wrote straight into `mapper.Config` and restored defaults by hand between scans.
- It kept its own scan history in `scans/<timestamp>/results.json`, separate from the CLI's `netmapper_baseline.json`.
