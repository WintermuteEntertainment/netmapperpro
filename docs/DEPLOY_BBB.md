# Hosting on BBB: https://nmpro.timcase.ca

Set up 2026-11-08. The full web app (scans, history, delete) runs on BBB and is published through the existing "jazz" Cloudflare tunnel, behind two locks.

## The two locks

1. **Cloudflare Access** (Zero Trust team `wintermute2`, account tim@timcase.info). Application `nmpro`, destination `nmpro.timcase.ca`, policy `NMPro - Tim only`: Allow, Include Emails = `tim@timcase.info`. Login is an emailed one-time code. Sessions last 24 hours. Nobody reaches BBB without passing this.
2. **The app checks Cloudflare's token itself** (`web/access.py`). Every request must carry a valid `Cf-Access-Jwt-Assertion` token signed by `wintermute2.cloudflareaccess.com` for this application's Audience tag, or it gets 403. So if the Access policy were ever deleted or loosened by mistake, the app still refuses. Only `/healthz` (which returns "ok" and nothing else) is open, for the watchdog.

The app also listens on `127.0.0.1:7890` only, so nothing on the LAN can reach it directly.

To let someone else in, add their email to the policy in the Cloudflare dashboard (Zero Trust > Access controls > Applications > nmpro). They will see every device, MAC address and open port, and can start scans and delete history.

## What lives where on BBB

| Path | What |
|---|---|
| `A:\NetMapperPro\` | Code, deployed from the repo's committed HEAD |
| `A:\NetMapperPro\.venv\` | Python 3.12 virtual environment used only by NetMapperPro. Versions in `pip-freeze.txt` |
| `A:\NetMapperPro\access_env.bat` | `NMPRO_ACCESS_TEAM=wintermute2` and `NMPRO_ACCESS_AUD=...`. Not in git. Without it the app refuses to start |
| `A:\NetMapperPro\server.log` | App output |
| `A:\NetMapperPro\web\scans\` | Scan history (real network data) |
| Task `NMPro` | Runs `deploy\start_nmpro.bat` 45 s after boot, logged off (S4U), no time limit |
| `C:\Users\twwca\.cloudflared\config.yml` | Tunnel rule `nmpro.timcase.ca -> http://localhost:7890`. Backup before the change: `config.yml.bak-nmpro-20261108` |
| `A:\Jazz\bbb_watchdog.ps1` | Hourly check of `http://localhost:7890/healthz`; restarts task `NMPro` if it fails. Backup: `bbb_watchdog.ps1.bak-nmpro-20261108` |

DNS: CNAME `nmpro.timcase.ca` to the jazz tunnel, created with `cloudflared tunnel route dns jazz nmpro.timcase.ca`.

## Updating the app

Commit first (only committed code is shipped), then from PT:

```bash
powershell -File D:\Repos\netmapperpro\deploy\deploy_bbb.ps1 -Restart
```

`-Restart` stops and restarts the `NMPro` task and waits for `/healthz`. Leave it off for template-only changes you want to pick up at the next restart.

If `web/requirements.txt` changes, run the setup again on BBB (it reuses the venv):

```bash
ssh twwca@100.69.250.80 '/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File A:/NetMapperPro/deploy/setup_bbb.ps1 < /dev/null'
```

## Taking it offline

- Quickest: in the Cloudflare dashboard, change the `NMPro - Tim only` policy action to Block, or delete the `nmpro` application (the app's own check then still refuses everyone).
- Stop the app: `schtasks /End /TN NMPro` on BBB (and the watchdog will restart it within the hour unless the task is disabled: `schtasks /Change /TN NMPro /DISABLE`).
- Remove the route: restore `config.yml.bak-nmpro-20261108`, then `taskkill /IM cloudflared.exe /F` and `schtasks /Run /TN JazzTunnel` (a 5 to 10 s blip for every site on the tunnel), and delete the `nmpro` CNAME in the timcase.ca DNS.

## Verified 2026-11-08

- Unauthenticated `https://nmpro.timcase.ca/` returns 302 to `wintermute2.cloudflareaccess.com` login.
- On BBB: no token 403, forged token 403, `/healthz` 200, LAN address refused.
- Tunnel restart: jazz, photos, riff, tech, mcp, graph, newsroom and computeforhope.com returned the same codes before and after (breaks.timcase.ca was already 530).
- Watchdog dry run: nmpro up.
