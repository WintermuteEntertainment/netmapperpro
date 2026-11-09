"""The change-detection baseline file."""

import subprocess, re, time, os, json, ipaddress, socket, sys, math, statistics, html, argparse, shlex
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple, Optional, Any, DefaultDict
from collections import defaultdict, Counter
from pathlib import Path
import http.client, ssl, urllib.parse, base64, webbrowser, tempfile, hashlib, random, string, textwrap
import concurrent.futures
import itertools
import threading


BASELINE_FILE = "netmapper_baseline.json"


def load_baseline(args) -> Optional[Dict[str, Any]]:
    """
    Load the previous scan's results so this one can report what changed.

    Change detection is the earliest warning available and costs nothing on the
    wire, so the baseline is kept by default. --no-baseline skips it.
    """
    if getattr(args, "no_baseline", False):
        return None
    path = Path(getattr(args, "baseline", None) or BASELINE_FILE)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"  ! Could not read baseline {path}: {exc}")
        return None


def save_baseline(args, lan_devices, wifi_networks) -> None:
    """Record this scan so the next one has something to compare against."""
    if getattr(args, "no_baseline", False):
        return
    path = Path(getattr(args, "baseline", None) or BASELINE_FILE)
    snapshot = {
        "captured": datetime.now().isoformat(timespec="seconds"),
        "lan_devices": [
            # `subnet` is recorded so a later run can ask "which networks have
            # I seen before" without guessing a prefix from the address.
            {"ip": d.ip, "mac": d.mac, "hostname": d.hostname,
             "vendor": d.vendor, "ownership": getattr(d, "ownership", "ours"),
             "subnet": d.subnet}
            for d in lan_devices
        ],
        "wifi_networks": [
            {"bssid": n.bssid, "ssid": n.ssid, "ownership": n.ownership,
             "signal_percent": n.signal_percent, "channel": n.channel,
             "band": n.band_label}
            for n in wifi_networks
        ],
    }
    try:
        path.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
    except OSError as exc:
        print(f"  ! Could not write baseline {path}: {exc}")
