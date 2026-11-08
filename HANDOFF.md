# Handoff: NetMapperPro

**Last updated:** 2026-11-08

NetMapperPro scans the local network and produces a draw.io diagram and an HTML dashboard. It's Tim's working tool, and he doesn't want more development on it for now.

## State

- **Repo:** branch `master`, pushed to the private GitHub repo https://github.com/WintermuteEntertainment/netmapperpro (created 2026-11-08 as `origin`). First commit `ee7637a` on 2026-11-08. Don't commit real scan data.
- **Script:** `NET_MAPPER_PRO.py`, an exact copy of `C:\Users\twwca\Downloads\NET_MAPPER_PRO.py`, last changed 2026-08-21. The Downloads copies remain untouched, including `netmapper-web` and older versions.
- **Vendor registry:** `oui.csv` sits beside the script (copied 2026-11-08 from `Downloads\oui.csv`, identical SHA-256, IEEE data dated 2026-08-20). The script loads it automatically from its own folder whatever the working folder is: confirmed, 39,982 prefixes. Git ignores it.
- **Older script:** `Downloads\ENHANCEDNETWORKMAPPERPRO.py` is an early version from 2026-03-10.

## Latest scan

`runs/2026-11-08_171034_vendors`, run 2026-11-08 at 17:10 with Tim's OK, the first with `oui.csv` loaded. Flags: `--enhanced --no-warning --no-open --identify-silent`, seeded with the 13:50 baseline:
- 30 devices, 15 BSSIDs (4 ours), 47.9 seconds. Every device with a factory MAC now has a vendor; only randomized phone addresses lack one.
- 2 warnings, both noise. The "8 new devices" were all seen before: 6 are the sweep-only devices from 13:50 that had no MAC then (the same bug as the "gone" list, in reverse), and 2 are iPhones back from the 11-07 scan. Of the 6 "new" access points, 5 are neighbours and 1 shares the main router's hardware prefix.
- Noodlecart now advertises RDP as well as SSH. At 13:50 it showed SSH only.
- The Hikvision device (Tim's doorbell) and the A10's `462A_2.4G` network were not seen in either 2026-11-08 run.

Earlier on 2026-11-08: `runs/2026-11-08_135050_identify`, run at 13:50 (who ran it isn't recorded). It added mDNS, SSDP, WS-Discovery and a 16-port probe on 9 devices:
- 29 devices, 11 Wi-Fi networks, 60.6 seconds. 3 warnings, 5 informational findings.
- All 3 warnings are explained and harmless: the WSL virtual machine got a new hardware address after a restart, the "new" devices are that VM and Tim's ThinkPad, and the "new" access points are neighbours plus Wi-Fi Direct from the ThinkPad and Taichi.
- Vendor lookup returned "Unknown" for every device because the repo had no `oui.csv` beside the script (fixed 2026-11-08, see State). The scanner loads one automatically from its own folder or the working folder. A copy of the IEEE registry is at `Downloads\oui.csv` (39,979 prefixes, dated 2026-08-20), which is why the Downloads copy and netmapper-web named vendors. IEEE's site refuses automated downloads (HTTP 418).
- On 2026-11-08 the saved MACs from both runs were looked up offline against that file and matched to the unknowns in `NETWORK_PLAN.md`. The notable result: the plan's `F56826172` is a **Hikvision** device (camera or recorder maker). It was present on 2026-11-07, absent on 2026-11-08, and the watchlist's surveillance rule would have flagged it if vendors had resolved. Tim confirmed on 2026-11-08 that it is his front doorbell.

Tool problems seen in this run (not fixed, project parked):
- Devices found only by the sweep have no MAC, so the comparison lists them as "no longer present" even though they are in the same scan. 6 of the 14 "gone" entries are this.
- Taichi's own Wi-Fi Direct network is labelled as a neighbour, not ours.
- The WSL VM's new hardware address on each restart is reported as a warning.
- `load_oui_file()` splits lines on every comma, so vendor names that contain a comma get cut short, for example "Hangzhou Hikvision Digital Technology Co." without the ",Ltd.". Matching still works.

Previous scan: `runs/2026-11-07_132339`, using the default `attached` scope with VPN and virtual networks off:
- 34 devices, 16 Wi-Fi networks, and 2 subnets in 44.6 seconds.
- 0 critical, 0 warning, and 3 informational findings. Only one of the three has been read, about 5 GHz channel sharing.
- Files: `secure_network_diagram.drawio.xml` and `secure_network_dashboard.html`. Output contains sensitive network data, and git ignores it.

To run it from a new folder under `runs/`:

```bash
PYTHONIOENCODING=utf-8 python -I ../../NET_MAPPER_PRO.py --enhanced --no-warning --no-open
```

## Next steps

1. Tim reviews `NETWORK_PLAN.md` and does the Archer A10 phone test.
2. Tim identifies the unknown devices listed there.
3. Tim reserves addresses in the main router, lowest risk first, with BBB last.
4. Rescan and compare.

**Rules:** Tim makes router changes himself. Scan only his own network. Be careful with BBB, because JAZZ and other live sites depend on it.

## Later, not now

A possible JSON output so GPUDoc can inspect machines NetMapperPro finds, and a possible refactor of the 6,254-line script. Tim parked both.
