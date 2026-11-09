# Handoff: NetMapperPro

**Last updated:** 2026-11-08

NetMapperPro scans the local network and produces a draw.io diagram and an HTML dashboard. Tim picked it back up on 2026-11-08 and approved a four-step refactor, which is done and merged into `master`. The layout, the history and the reasoning are in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## State

- **Repo:** private GitHub repo https://github.com/WintermuteEntertainment/netmapperpro (`origin`). The refactor (`a4a3979` through `f9b8618`) was fast-forwarded into `master` and pushed on 2026-11-08, with Tim's OK. Branch `refactor` is also on GitHub; it can be deleted once Tim no longer wants it. Don't commit real scan data.
- **Code:** the `netmapper/` package (17 modules). `NET_MAPPER_PRO.py` is now a short entry point that re-exports the package, so old commands and `import NET_MAPPER_PRO` still work.
- **Web app:** `web/` (Flask, http://127.0.0.1:7890), copied from `Downloads\netmapper-web` on 2026-11-08. It imports the repo scanner. Flask 3.1.3 is installed in Tim's user site-packages, so start it with plain `python web\app.py` or `web\run.bat`, not `python -I`. Its scan history goes in `web/scans/`, which git ignores. Verified end to end on 2026-11-08: scan `web/scans/2026-11-08_201030` was started from the page with default settings (probing off). It finished in 44.6 seconds with no errors: 28 devices of ours, 1 nearby, 21 BSSIDs, 4 informational findings. The dashboard, diagram, filtered diagram, results.json and log all load. `.claude/launch.json` (untracked) starts the app from the Claude desktop app's preview pane.
- **Vendor registry:** `oui.csv` in the repo root (IEEE data dated 2026-08-20, 39,979 prefixes, git-ignored), loaded automatically. IEEE's site refuses automated downloads (HTTP 418), so a newer copy has to be downloaded by hand.
- **Downloads:** the original `NET_MAPPER_PRO.py`, `netmapper-web` (with its `.bak`, `server.log` and three August scans) and older versions are untouched.

## Hosted at https://nmpro.timcase.ca (2026-11-08)

The web app runs on BBB behind Cloudflare Access (team `wintermute2`, only `tim@timcase.info`, emailed one-time code) and checks Cloudflare's signed token itself, so it fails closed. Details, paths, update and takedown steps: [docs/DEPLOY_BBB.md](docs/DEPLOY_BBB.md). Existing tunnel sites were checked before and after the tunnel restart and were unchanged. Verified end to end the same evening: Tim logged in through Access, the app accepted the real token, and scan `2026-11-08_205745` ran on BBB as the logged-off task in 41.4 s (28 devices of ours, 1 nearby, and the Wi-Fi survey works from BBB: 39 BSSIDs).

## The refactor (2026-11-08)

1. **Split into a package.** Code moved verbatim; a parse-tree comparison confirmed it. One deliberate change: the vendor list is searched for in the repo root.
2. **One shared scan pipeline**, `netmapper/pipeline.py`. The CLI and the web app both call `run_scan()`, and the web app's duplicate copy of the scan steps is gone. Topology is now built after discovery, so devices found only by announcement appear in it.
3. **Settings and errors.** `Config.reset()` replaces the web app's own snapshot of the defaults. A failed CLI run exits with code 1 and prints one line; `--debug` adds the full traceback. Tim agreed running two scans side by side isn't needed, so settings are still one shared object.
4. **Bug fixes**, each replayed on real saved scans:
   - Sweep-only devices (no MAC) no longer show as "gone" and then "new".
   - Virtual adapters (WSL's Hyper-V VM) are left out of the device comparison.
   - Vendor names keep their commas and quotes.
   - **Not changed:** Taichi's Wi-Fi Direct network is still labelled a neighbour. The code deliberately refuses to call a network ours from its name alone, and that network's address is randomized. Tim to decide.

Verified with two live scans, both run with Tim's approval of the plan:
- `runs/2026-11-08_195556_refactor` (after steps 1 to 3) found the same 28 devices, vendors and hostnames as the 17:10 run, minus two phones.
- `runs/2026-11-08_200248_fixes` (after step 4) reported no false device changes.

## Latest scan

`runs/2026-11-08_200248_fixes`: 29 devices, 17 BSSIDs, 46.6 seconds, 1 warning (7 new access points: 5 neighbours, plus the A10's `462A_2.4G` and the printer's Wi-Fi Direct, both correctly marked ours).

Facts from the 2026-11-08 scans:
- The plan's `F56826172` is a Hikvision device: Tim's front doorbell.
- Noodlecart advertises RDP as well as SSH since the 17:10 scan.
- The A10 broadcasts `462A_2.4G` from its own LAN MAC (`…:5C:78`) and `462A_5G` from `…:5C:77`. That shows the A10 itself sits on the main network. It does **not** settle whether its Wi-Fi clients get `192.168.2.x`; the phone test still does that.

To scan from a new folder under `runs/` (copy the previous `netmapper_baseline.json` in first to get a comparison):

```bash
python -I ../../NET_MAPPER_PRO.py --enhanced --no-warning --no-open --identify-silent
```

## Next steps

1. Sweep MAC fix (`dc7cc41`, deployed to BBB 2026-11-08): `fill_missing_macs()` re-reads the neighbour table after the sweep and after discovery. The verification scan `2026-11-08_210911` had every device with a MAC and the A10's `462A_2.4G`/`462A_5G` as ours, but its sweep found nothing new (the table was still warm from the previous scan), so the fill path itself has not yet been seen doing work. Look for "Hardware address filled in" in the log of the next cold scan. The same scan flagged the Hikvision doorbell (.18) under the surveillance watchlist rule, as designed.
2. Bluebeard (.229, Unraid 7.3.2) Telnet **turned off 2026-11-08** over SSH at Tim's request: `USE_TELNET="no"` in `/boot/config/ident.cfg` (backup `ident.cfg.bak-telnet-20261108`, only that line differs), applied with Unraid's own `update_access` script. Port 23 now closed from PT; SSH, 80 and 443 unaffected. Caveat: Unraid's settings page still holds "Yes" in memory (`/var/local/emhttp/var.ini`) until a reboot, so if Tim saves Settings > Management Access before then, set Telnet to No on that page or it comes back. Port 514 is `rsyslogd` (Unraid's syslog server), confirmed. Bluebeard also has `USE_UPNP="yes"`.
3. Tim decides on the Taichi Wi-Fi Direct labelling. Claude recommends leaving it.
4. Network plan: Tim reviews `NETWORK_PLAN.md`, does the Archer A10 phone test and identifies the remaining unknown devices. The reservation steps conflict with the 2026-08-25 home-network notes (the Home Hub 4000 has no DHCP reservation control, and Tim chose not to pursue reservations); Tim to confirm before relying on them.

**Rules:** Tim makes router changes himself. Scan only his own network. Be careful with BBB, because JAZZ and other live sites depend on it.

## Later, not now

- JSON output so GPUDoc can inspect machines NetMapperPro finds.
- Splitting the two very long functions (the diagram and dashboard builders).
- Whether to keep `--original` mode, now a thin wrapper over the shared pipeline.
- `SecurityValidator.validate_mac_address` is never called.
