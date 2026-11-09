# Handoff: NetMapperPro

**Last updated:** 2026-11-08

NetMapperPro scans the local network and produces a draw.io diagram and an HTML dashboard. Tim picked it back up on 2026-11-08 and approved a four-step refactor, which is done on branch `refactor`. The layout, the history and the reasoning are in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## State

- **Repo:** private GitHub repo https://github.com/WintermuteEntertainment/netmapperpro (`origin`). `master` is at `a3a5f58` and pushed. The refactor is on local branch `refactor` (7 commits, `a4a3979` to `ae0d96b`), **not pushed or merged yet**. Don't commit real scan data.
- **Code:** the `netmapper/` package (17 modules). `NET_MAPPER_PRO.py` is now a short entry point that re-exports the package, so old commands and `import NET_MAPPER_PRO` still work.
- **Web app:** `web/` (Flask, http://127.0.0.1:7890), copied from `Downloads\netmapper-web` on 2026-11-08. It imports the repo scanner. Flask 3.1.3 is installed in Tim's user site-packages, so start it with plain `python web\app.py` or `web\run.bat`, not `python -I`. Its scan history goes in `web/scans/`, which git ignores. It was checked by loading pages with Flask's test client; **no scan has been run through the web app yet.**
- **Vendor registry:** `oui.csv` in the repo root (IEEE data dated 2026-08-20, 39,979 prefixes, git-ignored), loaded automatically. IEEE's site refuses automated downloads (HTTP 418), so a newer copy has to be downloaded by hand.
- **Downloads:** the original `NET_MAPPER_PRO.py`, `netmapper-web` (with its `.bak`, `server.log` and three August scans) and older versions are untouched.

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

1. Tim reviews the `refactor` branch, then decides whether to push it and merge it into `master`.
2. Run one scan through the web app to confirm it end to end.
3. Tim decides on the Taichi Wi-Fi Direct labelling.
4. Network plan, unchanged: Tim reviews `NETWORK_PLAN.md`, does the Archer A10 phone test, identifies the remaining unknown devices, reserves addresses lowest risk first with BBB last, then rescan.

**Rules:** Tim makes router changes himself. Scan only his own network. Be careful with BBB, because JAZZ and other live sites depend on it.

## Later, not now

- JSON output so GPUDoc can inspect machines NetMapperPro finds.
- Splitting the two very long functions (the diagram and dashboard builders).
- Whether to keep `--original` mode, now a thin wrapper over the shared pipeline.
- `SecurityValidator.validate_mac_address` is never called.
