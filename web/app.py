"""
Network Peek — a Flask front end for NET_MAPPER_PRO.

Run:  python app.py        then open  http://127.0.0.1:7890

The scanner is imported and driven IN-PROCESS rather than launched as a
subprocess. The subprocess design could only ever stream stdout, which meant
progress, pause/resume and structured results were impossible to offer no
matter what the UI did. Importing it gives us the scanner's own progress and
control hooks, so this app can report percentage complete, pause mid-sweep and
hand back real device objects instead of scraped console text.

Scan artefacts are still archived per-run under scans/<timestamp>/ so previous
scans stay browsable.
"""

import io
import os
import re
import sys
import json
import queue
import shutil
import threading
import traceback
from datetime import datetime
from pathlib import Path

from flask import Flask, render_template, jsonify, send_file, Response, abort, request

APP_DIR = Path(__file__).parent.resolve()
SCANS_DIR = APP_DIR / "scans"
SCANS_DIR.mkdir(exist_ok=True)

# NET_MAPPER_PRO.py lives one level up. Point at the canonical file: this used
# to reference "NET_MAPPER_PRO - Copy.py", a byte-identical duplicate, so edits
# to the real scanner silently had no effect on what the web app ran.
SCANNER_DIR = Path(os.environ.get("NETMAPPER_DIR", APP_DIR.parent)).resolve()
if str(SCANNER_DIR) not in sys.path:
    sys.path.insert(0, str(SCANNER_DIR))

try:
    import NET_MAPPER_PRO as mapper
except ImportError as exc:  # pragma: no cover - startup diagnostic
    sys.exit(
        f"Cannot import NET_MAPPER_PRO.py from {SCANNER_DIR}: {exc}\n"
        f"Set NETMAPPER_DIR to the folder containing it."
    )

SCAN_ID_RE = re.compile(r"^\d{4}-\d{2}-\d{2}_\d{6}$")

# Pick up a full IEEE vendor registry if one sits beside the scanner or here.
# Without it the built-in table resolves roughly a third of real hardware.
_OUI_COUNT = mapper.VendorDatabase.autoload([str(APP_DIR)])

app = Flask(__name__)


# ─────────────────────────── scan state ───────────────────────────

class Progress:
    """
    Weighted multi-stage progress.

    The sweep dominates wall-clock time, so it carries most of the weight;
    reporting six equal stages would make the bar sit at 33% for almost the
    entire scan.
    """

    STAGE_WEIGHTS = [
        ("enumerate", 3),
        ("neighbors", 7),
        ("ping", 52),
        ("enrich", 12),
        ("wifi", 8),
        ("announce", 8),
        # Only present when service probing is enabled. At the deeper tiers it
        # is the longest phase of the scan, so it needs real weight — without
        # a stage of its own the bar sits frozen for minutes.
        ("probe", 10),
        ("topology", 5),
        ("render", 5),
    ]

    def __init__(self, mode="all", probing=False):
        stages = list(self.STAGE_WEIGHTS)
        if not probing:
            stages = [s for s in stages if s[0] != "probe"]
        if mode == "wifi":
            stages = [s for s in stages
                      if s[0] not in ("neighbors", "ping", "enrich", "probe")]
        elif mode == "lan":
            stages = [s for s in stages if s[0] != "wifi"]
        total = sum(w for _, w in stages) or 1
        self.stages = [(n, w / total * 100.0) for n, w in stages]
        self.index = {n: i for i, (n, _) in enumerate(self.stages)}
        self.current = self.stages[0][0] if self.stages else "done"
        self.done = 0
        self.total = 1
        self.last_pct = -1

    def _base(self, name):
        i = self.index.get(name, 0)
        return sum(w for _, w in self.stages[:i])

    def pct(self):
        if self.current == "done":
            return 100
        i = self.index.get(self.current)
        if i is None:
            return self.last_pct if self.last_pct >= 0 else 0
        weight = self.stages[i][1]
        frac = self.done / max(1, self.total)
        return int(min(100, self._base(self.current) + weight * min(1.0, frac)))

    def update(self, stage, done, total):
        self.current = stage
        self.done = done
        self.total = max(1, total)
        pct = self.pct()
        if pct != self.last_pct:
            self.last_pct = pct
            return pct
        return None

    def finish(self):
        self.current = "done"
        self.last_pct = 100
        return 100


state_lock = threading.Lock()
subscribers = []          # one queue per connected SSE client
stop_event = threading.Event()
pause_event = threading.Event()
pause_event.set()         # set == running, cleared == paused

state = {
    "running": False,
    "paused": False,
    "scan_id": None,
    "started_at": None,
    "finished_at": None,
    "error": None,
    "results": None,
    "log": [],
    "progress": {"stage": "", "pct": 0, "detail": ""},
}


def publish(kind, payload):
    """
    Fan an event out to every connected client.

    The previous build handed the single live queue to whichever request asked
    for /stream, so a second browser tab stole log lines from the first. Each
    subscriber now gets its own queue.
    """
    event = {"kind": kind, **payload}
    with state_lock:
        if kind == "log":
            state["log"].append(payload)
        elif kind == "progress":
            state["progress"] = payload
        for q in list(subscribers):
            q.put(event)


def log(message):
    publish("log", {"t": datetime.now().strftime("%H:%M:%S"), "msg": str(message)})


# ─────────────────────────── serialisation ───────────────────────────

def device_to_dict(d):
    return {
        "ip": d.ip,
        "mac": d.mac,
        "hostname": d.hostname,
        "vendor": d.vendor,
        "device_type": d.device_type,
        "os_family": d.os_family,
        "subnet": d.subnet,
        "gateway": d.gateway,
        "interface": getattr(d, "interface", ""),
        "ownership": getattr(d, "ownership", "ours"),
        "discovered_via": getattr(d, "discovered_via", ""),
        "neighbor_state": getattr(d, "neighbor_state", ""),
        "ttl": d.ttl,
        "response_time": d.response_time,
        "services": sorted(d.services or []),
        "model": getattr(d, "model", ""),
        "ports_open": list(d.ports_open or []),
        # JSON object keys must be strings; the reader converts back.
        "banners": {str(p): t for p, t in (getattr(d, "banners", {}) or {}).items()},
        "management_url": getattr(d, "management_url", ""),
        "tags": sorted(d.tags),
        "is_gateway": d.is_gateway,
        "is_virtual": d.is_virtual,
    }


def wifi_to_dict(n):
    return {
        "ssid": n.ssid,
        "display_name": n.display_name,
        "bssid": n.bssid,
        "signal_percent": n.signal_percent,
        "band": n.band_label,
        "channel": n.channel,
        "radio_type": n.radio_type,
        "authentication": n.authentication,
        "encryption": n.encryption,
        "vendor": n.vendor,
        "is_virtual_bssid": n.is_virtual_bssid,
        "is_hidden": n.is_hidden,
        "is_open": n.is_open,
        "physical_radio": n.physical_radio,
        "ownership": n.ownership,
        "connected_stations": n.connected_stations,
        "channel_utilization": n.channel_utilization,
    }


def iface_to_dict(i):
    return {
        "alias": i.alias,
        "ip": i.ip,
        "prefix_length": i.prefix_length,
        "kind": i.kind,
        "network": i.network,
        "gateway": i.gateway,
        "mac": i.mac,
        "is_sweepable": i.is_sweepable,
    }


def load_previous_results(exclude_scan_id):
    """
    Most recent completed scan, used as the change-detection baseline.

    Scan folders are timestamp-named, so the newest that is not the run in
    progress is the one to diff against.
    """
    candidates = sorted(
        (d for d in SCANS_DIR.iterdir()
         if d.is_dir() and SCAN_ID_RE.match(d.name) and d.name != exclude_scan_id),
        key=lambda d: d.name, reverse=True,
    )
    for d in candidates:
        p = d / "results.json"
        if p.exists():
            try:
                return json.loads(p.read_text(encoding="utf-8")), d.name
            except (OSError, ValueError):
                continue
    return None, None


def wifi_history(exclude_scan_id, limit=12):
    """Every BSSID seen in recent scans, strongest observation kept."""
    out = {}
    dirs = sorted((d for d in SCANS_DIR.iterdir()
                   if d.is_dir() and SCAN_ID_RE.match(d.name)
                   and d.name != exclude_scan_id),
                  key=lambda d: d.name, reverse=True)[:limit]
    for d in dirs:
        p = d / "results.json"
        if not p.exists():
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for n in data.get("wifi_networks", []):
            b = n.get("bssid")
            if b and (b not in out or n.get("signal_percent", 0) >
                      out[b].get("signal_percent", 0)):
                out[b] = n
    return list(out.values())


def build_results(lan, wifi_networks, topology, interfaces, sweep_targets, duration):
    ours = [d for d in lan if getattr(d, "ownership", "ours") == "ours"]
    findings = topology.get("findings") or []
    return {
        "scan_time": round(duration, 2),
        "findings": [f.to_dict() for f in findings],
        "lan_devices": [device_to_dict(d) for d in lan],
        "wifi_networks": [wifi_to_dict(n) for n in wifi_networks],
        "interfaces": [iface_to_dict(i) for i in interfaces],
        "sweep_targets": [
            {"cidr": t.cidr, "origin": t.origin, "ownership": t.ownership}
            for t in sweep_targets
        ],
        "stats": {
            "devices_ours": len(ours),
            "devices_nearby": len(lan) - len(ours),
            "subnets": len({d.subnet for d in lan if d.subnet}),
            "gateways": sum(1 for d in lan if d.is_gateway),
            "wifi_ours": sum(1 for n in wifi_networks if n.ownership == "ours"),
            "wifi_nearby": sum(1 for n in wifi_networks if n.ownership != "ours"),
            "wifi_radios": len({n.physical_radio for n in wifi_networks}),
            "findings_critical": sum(1 for f in findings if f.severity == "critical"),
            "findings_warning": sum(1 for f in findings if f.severity == "warning"),
            "findings_info": sum(1 for f in findings if f.severity == "info"),
        },
    }


# ─────────────────────────── worker ───────────────────────────

def run_scan(scan_id, overrides):
    scan_dir = SCANS_DIR / scan_id
    scan_dir.mkdir(exist_ok=True)
    started = datetime.now()

    progress = Progress(
        overrides.get("scan_mode", mapper.Config.SCAN_MODE),
        probing=bool(overrides.get("identify_silent", mapper.Config.IDENTIFY_SILENT)),
    )

    def on_progress(stage, done, total):
        pct = progress.update(stage, done, total)
        if pct is not None:
            publish("progress", {"stage": stage, "pct": pct, "detail": f"{done}/{total}"})

    def should_stop():
        return stop_event.is_set()

    def wait_if_paused():
        pause_event.wait()

    def save_results(result, duration):
        results = build_results(result.lan_devices, result.wifi_networks,
                                result.topology, result.interfaces,
                                result.sweep_targets, duration)
        with state_lock:
            state["results"] = results
        (scan_dir / "results.json").write_text(
            json.dumps(results, indent=2), encoding="utf-8"
        )
        return results

    try:
        apply_config(overrides)

        # The previous scan is the change-detection baseline and also answers
        # probe_select='new' and the 'known'/'new' network names.
        baseline, baseline_id = load_previous_results(scan_id)
        if baseline_id:
            log(f"Comparing against previous scan {baseline_id}")

        # The scan itself is shared with the command line: see
        # netmapper/pipeline.py. Only what happens to the result differs.
        result = mapper.run_scan(
            baseline=baseline,
            # Channel advice uses every BSSID seen across recent scans, because
            # a single netsh snapshot is often too thin to advise from.
            wifi_history=wifi_history(scan_id),
            watchlist_rules=mapper.VendorWatchlist.load(
                str(APP_DIR / "netmapper_watchlist.json")),
            on_log=log,
            on_progress=on_progress,
            should_stop=should_stop,
            wait_if_paused=wait_if_paused,
        )

        write_artifacts(scan_dir, result.lan_devices, result.wifi_networks,
                        result.topology, result.duration, on_progress)

        duration = (datetime.now() - started).total_seconds()
        results = save_results(result, duration)
        progress.finish()
        publish("progress", {"stage": "done", "pct": 100, "detail": ""})
        log(f"Scan complete in {duration:.1f}s")
        publish("done", {"scan_id": scan_id, "results": results})

    except mapper.ScanCancelled as stopped:
        duration = (datetime.now() - started).total_seconds()
        log("Scan stopped by user — keeping partial results")
        try:
            results = save_results(stopped.partial, duration)
            publish("stopped", {"scan_id": scan_id, "results": results})
        except Exception:
            publish("stopped", {"scan_id": scan_id, "results": None})

    except Exception as exc:
        detail = traceback.format_exc()
        with state_lock:
            state["error"] = detail
        log(f"ERROR: {exc}")
        (scan_dir / "error.log").write_text(detail, encoding="utf-8")
        publish("error", {"message": str(exc)})

    finally:
        # Persist the console log for this run so past scans stay inspectable.
        try:
            with state_lock:
                lines = [f"[{e['t']}] {e['msg']}" for e in state["log"]]
            (scan_dir / "scan.log").write_text("\n".join(lines), encoding="utf-8")
        except Exception:
            pass
        with state_lock:
            state["running"] = False
            state["paused"] = False
            state["finished_at"] = datetime.now().isoformat(timespec="seconds")
        pause_event.set()
        stop_event.clear()
        publish("status", {"running": False, "paused": False})


def write_artifacts(scan_dir, lan, wifi_networks, topology, duration, on_progress):
    """Render the draw.io diagram and HTML dashboard into the scan folder."""
    on_progress("render", 0, 2)
    wifi_devices = [n.to_device() for n in wifi_networks]

    xml = mapper.EnhancedDiagramGenerator.generate_hierarchical_diagram(
        lan, wifi_devices, topology
    )
    (scan_dir / "secure_network_diagram.drawio.xml").write_text(xml, encoding="utf-8")
    on_progress("render", 1, 2)

    html = mapper.SecureDashboard.generate_dashboard(
        lan, wifi_devices, duration, topology
    )
    (scan_dir / "secure_network_dashboard.html").write_text(html, encoding="utf-8")
    on_progress("render", 2, 2)


CONFIG_FIELDS = {
    "scan_mode": ("SCAN_MODE", lambda v: v if v in ("all", "lan", "wifi") else "all"),
    "scan_scope": ("SCAN_SCOPE", lambda v: v if v in ("attached", "routed", "wide") else "attached"),
    "scan_threads": ("SCAN_THREADS", lambda v: max(1, min(200, int(v)))),
    "scan_timeout": ("SCAN_TIMEOUT", lambda v: max(1, min(30, int(v)))),
    "rate_limit_delay": ("RATE_LIMIT_DELAY", lambda v: max(0.0, float(v))),
    "resolve_hostnames": ("RESOLVE_HOSTNAMES", bool),
    "passive_discovery": ("PASSIVE_DISCOVERY", bool),
    "discovery_duration": ("DISCOVERY_DURATION", lambda v: max(1.0, min(120.0, float(v)))),
    "discovery_solicit": ("DISCOVERY_SOLICIT", bool),
    "use_watchlist": ("USE_WATCHLIST", bool),
    "identify_silent": ("IDENTIFY_SILENT", bool),
    "detect_os": ("DETECT_OS", bool),
    "include_virtual": ("SCAN_VIRTUAL_ADAPTERS", bool),
    "include_vpn": ("SCAN_VPN_ADAPTERS", bool),
    "max_sweep_hosts": ("MAX_SWEEP_HOSTS", lambda v: max(1, int(v))),
    # Service probing. 'exhaustive' is deliberately absent from the accepted
    # values: it is a 65535-connect-per-host operation that the CLI gates
    # behind --i-have-permission, and the UI must not be a way around that
    # gate any more than it is for scope 'wide'.
    "probe_depth": ("PROBE_DEPTH", lambda v: v if v in (
        "quick", "standard", "deep", "full") else "standard"),
    "probe_banners": ("PROBE_BANNERS", bool),
    "probe_select": ("PROBE_SELECT", lambda v: v if v in (
        "silent", "unidentified", "new", "all") else "silent"),
    "probe_nets": ("PROBE_NETS", lambda v: [
        s.strip() for s in (v if isinstance(v, list) else str(v).split(","))
        if s and s.strip()
    ]),
    "probe_timeout": ("PROBE_CONNECT_TIMEOUT", lambda v: max(0.05, min(30.0, float(v)))),
    "probe_sockets": ("PROBE_MAX_SOCKETS", lambda v: max(1, min(1024, int(v)))),
}


def reset_state(clear_config=True, clear_history=False):
    """
    Forget what previous runs left behind.

    Two independent things, because they fail differently: stale *settings*
    make the next scan behave unexpectedly, while stale *history* only skews
    the appeared/disappeared findings. Clearing history is destructive and
    therefore never the default.

    Note what this does NOT do: a scan has never hidden a device because an
    earlier scan already found it. Discovery re-enumerates and re-sweeps every
    time. History only feeds change detection and the 'new' selectors.
    """
    done = []
    if clear_config:
        # mapper.Config is module-level state, so settings from one scan
        # persist for the life of the process. The scanner keeps its own
        # snapshot of the shipped defaults; see Config.reset().
        mapper.Config.reset()
        done.append("settings restored to defaults")

    removed = 0
    if clear_history:
        for entry in SCANS_DIR.iterdir():
            if entry.is_dir() and SCAN_ID_RE.match(entry.name):
                shutil.rmtree(entry, ignore_errors=True)
                removed += 1
        done.append(f"{removed} saved scan(s) deleted")

    return {"actions": done, "scans_removed": removed}


def apply_config(overrides):
    for key, value in (overrides or {}).items():
        if key not in CONFIG_FIELDS or value is None:
            continue
        attr, coerce = CONFIG_FIELDS[key]
        try:
            setattr(mapper.Config, attr, coerce(value))
        except (TypeError, ValueError):
            log(f"Ignoring invalid value for {key}: {value!r}")

    # 'wide' probes addresses outside our own networks. The CLI gates this
    # behind an explicit acknowledgement; the UI must not be a way around that.
    if mapper.Config.SCAN_SCOPE == "wide" and not overrides.get("acknowledge_wide"):
        mapper.Config.SCAN_SCOPE = "attached"
        log("Scope 'wide' requires explicit acknowledgement — using 'attached'.")


def current_config():
    cfg = mapper.Config
    return {
        "scan_mode": cfg.SCAN_MODE,
        "scan_scope": cfg.SCAN_SCOPE,
        "scan_threads": cfg.SCAN_THREADS,
        "scan_timeout": cfg.SCAN_TIMEOUT,
        "rate_limit_delay": cfg.RATE_LIMIT_DELAY,
        "resolve_hostnames": cfg.RESOLVE_HOSTNAMES,
        "detect_os": cfg.DETECT_OS,
        "passive_discovery": cfg.PASSIVE_DISCOVERY,
        "discovery_duration": cfg.DISCOVERY_DURATION,
        "discovery_solicit": cfg.DISCOVERY_SOLICIT,
        "use_watchlist": cfg.USE_WATCHLIST,
        "identify_silent": cfg.IDENTIFY_SILENT,
        "include_virtual": cfg.SCAN_VIRTUAL_ADAPTERS,
        "include_vpn": cfg.SCAN_VPN_ADAPTERS,
        "max_sweep_hosts": cfg.MAX_SWEEP_HOSTS,
        "probe_depth": cfg.PROBE_DEPTH,
        "probe_banners": cfg.PROBE_BANNERS,
        "probe_select": cfg.PROBE_SELECT,
        "probe_nets": list(cfg.PROBE_NETS),
        "probe_timeout": cfg.PROBE_CONNECT_TIMEOUT,
        "probe_sockets": cfg.PROBE_MAX_SOCKETS,
    }


# ─────────────────────────── paths ───────────────────────────

def safe_scan_dir(scan_id):
    if not SCAN_ID_RE.match(scan_id):
        abort(400)
    p = (SCANS_DIR / scan_id).resolve()
    if SCANS_DIR not in p.parents and p != SCANS_DIR:
        abort(400)
    if not p.exists():
        abort(404)
    return p


# ─────────────────────────── routes ───────────────────────────

@app.route("/")
def index():
    scans = sorted(
        (d.name for d in SCANS_DIR.iterdir() if d.is_dir() and SCAN_ID_RE.match(d.name)),
        reverse=True,
    )
    with state_lock:
        running = state["running"]
        current = state["scan_id"]
    return render_template("index.html", scans=scans, running=running,
                           current=current, config=current_config())


@app.route("/api/config", methods=["GET", "POST"])
def api_config():
    if request.method == "GET":
        return jsonify(current_config())
    with state_lock:
        if state["running"]:
            return jsonify({"error": "cannot change config mid-scan"}), 409
    apply_config(request.get_json(silent=True) or {})
    return jsonify(current_config())


@app.route("/api/scan/start", methods=["POST"])
def start():
    with state_lock:
        if state["running"]:
            return jsonify({"error": "scan already running",
                            "scan_id": state["scan_id"]}), 409
        scan_id = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        state.update({
            "running": True,
            "paused": False,
            "scan_id": scan_id,
            "started_at": datetime.now().isoformat(timespec="seconds"),
            "finished_at": None,
            "error": None,
            "results": None,
            "log": [],
            "progress": {"stage": "", "pct": 0, "detail": ""},
        })
        for q in list(subscribers):
            while not q.empty():
                try:
                    q.get_nowait()
                except queue.Empty:
                    break

    stop_event.clear()
    pause_event.set()
    overrides = request.get_json(silent=True) or {}
    threading.Thread(target=run_scan, args=(scan_id, overrides), daemon=True).start()
    publish("status", {"running": True, "paused": False})
    return jsonify({"scan_id": scan_id})


@app.route("/api/scan/stop", methods=["POST"])
def stop():
    with state_lock:
        if not state["running"]:
            return jsonify({"error": "no scan running"}), 404
    stop_event.set()
    pause_event.set()  # unblock a paused worker so the stop can land
    log("Stop requested — finishing current probe...")
    return jsonify({"ok": True})


@app.route("/api/scan/pause", methods=["POST"])
def pause():
    with state_lock:
        if not state["running"]:
            return jsonify({"error": "no scan running"}), 404
        if state["paused"]:
            return jsonify({"ok": True, "paused": True})
        state["paused"] = True
    pause_event.clear()
    log("Scan paused")
    publish("status", {"running": True, "paused": True})
    return jsonify({"ok": True, "paused": True})


@app.route("/api/scan/resume", methods=["POST"])
def resume():
    with state_lock:
        if not state["running"]:
            return jsonify({"error": "no scan running"}), 404
        state["paused"] = False
    pause_event.set()
    log("Scan resumed")
    publish("status", {"running": True, "paused": False})
    return jsonify({"ok": True, "paused": False})


@app.route("/api/scan/status")
def status():
    with state_lock:
        return jsonify({
            "running": state["running"],
            "paused": state["paused"],
            "scan_id": state["scan_id"],
            "started_at": state["started_at"],
            "finished_at": state["finished_at"],
            "progress": state["progress"],
            "has_results": state["results"] is not None,
            "error": state["error"],
        })


@app.route("/api/scan/results")
def results():
    with state_lock:
        if state["results"] is None:
            return jsonify({"error": "no results yet"}), 404
        return jsonify(state["results"])


@app.route("/stream")
def stream():
    q = queue.Queue()
    with state_lock:
        subscribers.append(q)
        backlog = list(state["log"])
        snapshot = dict(state["progress"])
        running = state["running"]
        finished = state["results"] if not running else None

    def gen():
        try:
            for entry in backlog:
                yield sse({"kind": "log", **entry})
            if snapshot.get("pct"):
                yield sse({"kind": "progress", **snapshot})
            if finished is not None:
                yield sse({"kind": "done", "results": finished})
            while True:
                try:
                    event = q.get(timeout=15)
                except queue.Empty:
                    yield ": keepalive\n\n"
                    continue
                yield sse(event)
        finally:
            with state_lock:
                if q in subscribers:
                    subscribers.remove(q)

    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache",
                             "X-Accel-Buffering": "no",
                             "Connection": "keep-alive"})


def sse(obj):
    return f"data: {json.dumps(obj)}\n\n"


# ─────────────────────────── artefacts ───────────────────────────

@app.route("/scan/<scan_id>/dashboard")
def scan_dashboard(scan_id):
    p = safe_scan_dir(scan_id) / "secure_network_dashboard.html"
    if not p.exists():
        abort(404)
    return send_file(p)


@app.route("/scan/<scan_id>/diagram")
def scan_diagram(scan_id):
    """
    Download the draw.io diagram.

    ?filtered=1 re-renders from results.json with unidentifiable hosts removed
    — addresses that answered a ping but yielded no hostname, vendor or type.
    """
    scan_dir = safe_scan_dir(scan_id)
    if request.args.get("filtered") in ("1", "true", "yes"):
        xml = render_filtered_diagram(scan_dir)
        if xml is None:
            abort(404)
        return Response(
            xml, mimetype="application/xml",
            headers={"Content-Disposition":
                     f'attachment; filename="{scan_id}-filtered.drawio.xml"'},
        )
    p = scan_dir / "secure_network_diagram.drawio.xml"
    if not p.exists():
        abort(404)
    return send_file(p, as_attachment=True,
                     download_name=f"{scan_id}.drawio.xml")


def render_filtered_diagram(scan_dir):
    results_path = scan_dir / "results.json"
    if not results_path.exists():
        return None
    data = json.loads(results_path.read_text(encoding="utf-8"))

    def interesting(d):
        if d.get("is_gateway") or d.get("is_virtual"):
            return True
        if d.get("hostname"):
            return True
        if d.get("vendor") and d["vendor"] not in ("Unknown", ""):
            return True
        # A device with open ports is interesting whatever else we know about
        # it. Without this, the nameless unknown-vendor host running telnet —
        # exactly the one worth looking at — was filtered out of the diagram.
        if d.get("ports_open"):
            return True
        return d.get("device_type") not in ("unknown", "generic", "")

    lan = [dict_to_device(d) for d in data["lan_devices"] if interesting(d)]
    wifi = [dict_to_wifi(n) for n in data.get("wifi_networks", [])]
    scanner = mapper.SecureNetworkScanner(on_log=lambda m: None)
    topology = scanner.infer_network_topology(lan)
    topology["wifi"] = wifi
    topology["interfaces"] = []
    topology["sweep_targets"] = []
    return mapper.EnhancedDiagramGenerator.generate_hierarchical_diagram(
        lan, [w.to_device() for w in wifi], topology
    )


def dict_to_device(d):
    dev = mapper.NetworkDevice(ip=d["ip"])
    dev.mac = d.get("mac", "")
    dev.hostname = d.get("hostname", "")
    dev.vendor = d.get("vendor", "")
    dev.device_type = d.get("device_type", "unknown")
    dev.os_family = d.get("os_family", "unknown")
    dev.subnet = d.get("subnet", "")
    dev.gateway = d.get("gateway", "")
    dev.ttl = d.get("ttl", 0)
    dev.tags = set(d.get("tags", []))
    dev.ownership = d.get("ownership", "ours")
    dev.interface = d.get("interface", "")
    dev.neighbor_state = d.get("neighbor_state", "")
    dev.discovered_via = d.get("discovered_via", "")
    # Probe results, so a diagram re-rendered from a saved scan still shows
    # what the probe found. These were being dropped on the way back in.
    dev.services = list(d.get("services", []))
    dev.model = d.get("model", "")
    dev.ports_open = list(d.get("ports_open", []))
    dev.banners = {int(p): t for p, t in (d.get("banners") or {}).items()
                   if str(p).isdigit()}
    return dev


def dict_to_wifi(n):
    return mapper.WifiNetwork(
        ssid=n.get("ssid", ""),
        bssid=n.get("bssid", ""),
        signal_percent=n.get("signal_percent", 0),
        radio_type=n.get("radio_type", ""),
        band=n.get("band", ""),
        channel=n.get("channel", 0),
        authentication=n.get("authentication", ""),
        encryption=n.get("encryption", ""),
        vendor=n.get("vendor", ""),
        is_virtual_bssid=n.get("is_virtual_bssid", False),
        physical_radio=n.get("physical_radio", ""),
        ownership=n.get("ownership", "foreign"),
        connected_stations=n.get("connected_stations", 0),
        channel_utilization=n.get("channel_utilization", 0),
    )


@app.route("/scan/<scan_id>/results.json")
def scan_results_file(scan_id):
    p = safe_scan_dir(scan_id) / "results.json"
    if not p.exists():
        abort(404)
    return send_file(p, mimetype="application/json")


@app.route("/scan/<scan_id>/log")
def scan_log(scan_id):
    p = safe_scan_dir(scan_id) / "scan.log"
    if not p.exists():
        abort(404)
    return send_file(p, mimetype="text/plain; charset=utf-8")


@app.route("/scan/<scan_id>/delete", methods=["POST"])
def scan_delete(scan_id):
    with state_lock:
        if state["running"] and state["scan_id"] == scan_id:
            return jsonify({"error": "cannot delete a running scan"}), 409
    shutil.rmtree(safe_scan_dir(scan_id))
    return jsonify({"ok": True})


@app.route("/api/reset", methods=["POST"])
def api_reset():
    """
    Start clean.

    `config` restores every setting to the scanner's defaults. `history`
    additionally deletes saved scans, which is irreversible and so must be
    asked for explicitly rather than being implied by "reset".
    """
    with state_lock:
        if state["running"]:
            return jsonify({"error": "cannot reset while a scan is running"}), 409

    body = request.get_json(silent=True) or {}
    result = reset_state(
        clear_config=bool(body.get("config", True)),
        clear_history=bool(body.get("history", False)),
    )
    if result["scans_removed"]:
        # has_results is derived from state["results"], so clearing that is
        # what actually makes the UI stop offering a deleted scan.
        with state_lock:
            state["scan_id"] = None
            state["results"] = None
            state["finished_at"] = None
    for action in result["actions"]:
        log(f"Reset: {action}")
    return jsonify({"ok": True, "config": current_config(), **result})


if __name__ == "__main__":
    print("Network Peek -> http://127.0.0.1:7890")
    print(f"Scanner:  {SCANNER_DIR / 'NET_MAPPER_PRO.py'}")
    print(f"Scans:    {SCANS_DIR}")
    print(f"Vendors:  {_OUI_COUNT or len(mapper.VendorDatabase.VENDOR_DB)} prefixes"
          f"{'' if _OUI_COUNT else ' (built-in only — add oui.csv for full coverage)'}")
    app.run(host="127.0.0.1", port=7890, debug=False, threaded=True)
