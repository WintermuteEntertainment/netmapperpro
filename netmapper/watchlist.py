"""Vendor and service watchlist rules."""

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

from .models import Finding, NetworkDevice, _ip_sort_key


# ==================== VENDOR WATCHLIST ====================
class VendorWatchlist:
    """
    Flag devices whose vendor or advertised services warrant a second look.

    This is not a blocklist and makes no claim that a matched device is
    compromised. It answers a narrower question: "is there anything on this
    network that I should be able to account for by name?" A camera, a NAS or
    an unmanaged embedded device is worth recognising because each runs network
    services and each is a thing an intruder would like to reach.

    The rules live in a JSON file so they can be edited without touching code.
    """

    DEFAULT_RULES = [
        {
            "category": "surveillance",
            "severity": "warning",
            "match_vendor": ["hikvision", "dahua", "uniview", "amcrest", "reolink",
                             "axis communications", "swann", "lorex", "annke",
                             "foscam", "wyze"],
            "match_service": ["camera", "onvif", "rtsp"],
            "note": ("Network cameras and recorders run always-on services and have "
                     "historically shipped remotely exploitable firmware. Confirm you "
                     "can account for this device, that its firmware is current, and "
                     "that it is not reachable from outside your network."),
        },
        {
            "category": "storage",
            "severity": "info",
            "match_vendor": ["synology", "qnap", "western digital", "netgear storage",
                             "buffalo", "terramaster"],
            "match_service": ["file-share"],
            "note": ("Network storage holds data worth taking and is a common ransomware "
                     "target. Check that it is not exposed beyond the LAN."),
        },
        {
            "category": "remote-access",
            "severity": "info",
            "match_service": ["ssh", "rdp", "vnc", "web-ui"],
            "note": ("This device advertises a remote-access or management interface on "
                     "the network. Confirm the credentials are not default."),
        },
        {
            "category": "unidentified",
            "severity": "info",
            "match_vendor": [],
            "match_service": [],
            "note": "",
        },
    ]

    WATCHLIST_FILE = "netmapper_watchlist.json"

    @staticmethod
    def load(path: Optional[str] = None) -> List[Dict[str, Any]]:
        """Load watchlist rules, falling back to the built-in defaults."""
        p = Path(path or VendorWatchlist.WATCHLIST_FILE)
        if p.exists():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    return data
                if isinstance(data, dict) and isinstance(data.get("rules"), list):
                    return data["rules"]
            except (OSError, ValueError):
                pass
        return [r for r in VendorWatchlist.DEFAULT_RULES if r.get("note")]

    @staticmethod
    def write_default(path: Optional[str] = None) -> str:
        """Write the default rules out so they can be edited."""
        p = Path(path or VendorWatchlist.WATCHLIST_FILE)
        payload = {
            "_comment": ("Rules for flagging devices worth accounting for. "
                         "match_vendor entries are case-insensitive substrings of the "
                         "resolved vendor name; match_service entries match the service "
                         "labels discovered via mDNS/SSDP. severity: critical|warning|info."),
            "rules": [r for r in VendorWatchlist.DEFAULT_RULES if r.get("note")],
        }
        p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return str(p)

    @staticmethod
    def check(devices: List[NetworkDevice],
              rules: Optional[List[Dict[str, Any]]] = None) -> List['Finding']:
        rules = rules if rules is not None else VendorWatchlist.load()
        findings = []
        for rule in rules:
            vendors = [v.lower() for v in rule.get("match_vendor", [])]
            services = [s.lower() for s in rule.get("match_service", [])]
            hits = []
            for d in devices:
                if getattr(d, "ownership", "ours") != "ours":
                    continue
                vendor = (d.vendor or "").lower()
                dsvcs = [s.lower() for s in (d.services or [])]
                matched_v = any(v in vendor for v in vendors) if vendors else False
                matched_s = any(s in dsvcs for s in services) if services else False
                if matched_v or matched_s:
                    why = []
                    if matched_v:
                        why.append(d.vendor)
                    if matched_s:
                        why.append("/".join(sorted(set(dsvcs) & set(services))))
                    hits.append(f"{d.ip}  {d.hostname or 'no hostname'}  "
                                f"[{' · '.join(why)}]")
            if hits:
                findings.append(Finding(
                    severity=rule.get("severity", "info"),
                    category=f"watchlist:{rule.get('category', 'other')}",
                    title=f"{len(hits)} device(s) matched the "
                          f"'{rule.get('category', 'watchlist')}' rule",
                    detail=rule.get("note", ""),
                    evidence=sorted(hits, key=lambda s: _ip_sort_key(s.split()[0])),
                ))
        return findings
