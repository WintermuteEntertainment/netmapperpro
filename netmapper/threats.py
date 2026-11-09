"""Findings from passive analysis and baseline comparison."""

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

from .vendors import VendorDatabase
from .models import Finding, NetworkDevice, _ip_sort_key


class ThreatAnalyzer:
    """
    Derive early-warning signals from data we already hold.

    Every check here is passive. Nothing in this class transmits anything to
    anyone: it reasons over beacon frames the radio had already received and
    over our own host's neighbour table. That is deliberate and not merely a
    safety posture — an active sweep is the single loudest thing a host can do,
    landing in the logs of everything it touches. If the goal is to notice a
    problem before the other side notices you, the collection has to be silent.

    What this CANNOT do, and no amount of scanning would: enumerate hosts
    inside a neighbour's LAN. Their network is behind their own router on a
    separate broadcast domain, so there is no path to it. The reachable threat
    surface is (a) what is broadcast over the air, and (b) what is on our own
    wire — which is also where an attacker has to arrive to do us harm.
    """

    # Authentication strings that mean "no meaningful protection".
    WEAK_AUTH = ("open", "none", "wep", "wpa-personal", "wpa-enterprise")

    @staticmethod
    def analyze(devices: List[NetworkDevice],
                wifi: List['WifiNetwork'],
                interfaces: List['NetworkInterface'],
                baseline: Optional[Dict[str, Any]] = None) -> List[Finding]:
        findings: List[Finding] = []
        findings += ThreatAnalyzer.detect_ssid_impersonation(wifi)
        findings += ThreatAnalyzer.detect_gateway_tampering(devices, interfaces)
        findings += ThreatAnalyzer.detect_duplicate_macs(devices)
        findings += ThreatAnalyzer.detect_weak_wireless(wifi)
        if baseline:
            findings += ThreatAnalyzer.compare_to_baseline(devices, wifi, baseline)

        order = {"critical": 0, "warning": 1, "info": 2}
        findings.sort(key=lambda f: (order.get(f.severity, 3), f.category, f.title))
        return findings

    @staticmethod
    def detect_ssid_impersonation(wifi: List['WifiNetwork']) -> List[Finding]:
        """
        An SSID of ours being advertised by hardware that is not ours.

        This is the attack that actually matters over the air: stand up an AP
        with the victim's network name so their devices associate to it. It is
        visible in beacons without touching anything, because the impostor has
        to broadcast to be useful to the attacker.

        A network is only 'ours' here if it passed the strict hardware-evidence
        test, so a foreign BSSID carrying one of those SSIDs is a genuine
        mismatch rather than a naming coincidence.
        """
        findings = []
        our_ssids = {n.ssid for n in wifi if n.ownership == "ours" and n.ssid.strip()}
        for ssid in sorted(our_ssids):
            impostors = [n for n in wifi
                         if n.ssid == ssid and n.ownership != "ours"]
            if not impostors:
                continue
            ours = [n.bssid for n in wifi if n.ssid == ssid and n.ownership == "ours"]
            findings.append(Finding(
                severity="critical",
                category="impersonation",
                title=f"'{ssid}' is being advertised by hardware that is not yours",
                detail=(
                    "One or more access points are broadcasting a network name that "
                    "belongs to you, from radios that do not match any device on your "
                    "network. A device of yours that trusts this SSID may associate to "
                    "the wrong access point. Verify before connecting anything."
                ),
                evidence=[f"not ours: {n.bssid} ({n.signal_percent}%, {n.band_label}, "
                          f"ch{n.channel}, {n.authentication or 'no auth'})"
                          for n in impostors]
                         + [f"ours: {b}" for b in sorted(ours)],
            ))
        return findings

    @staticmethod
    def detect_gateway_tampering(devices: List[NetworkDevice],
                                 interfaces: List['NetworkInterface']) -> List[Finding]:
        """
        Anything odd about the router we send all our traffic through.

        Two signals: more than one hardware address claiming a gateway IP, and a
        gateway whose MAC is locally administered. Both are consistent with an
        on-path attacker answering ARP for the gateway, which is how traffic
        gets silently redirected on a switched LAN.
        """
        findings = []
        gateway_ips = {i.gateway for i in interfaces if i.gateway}
        for gw in sorted(gateway_ips):
            macs = {d.mac for d in devices if d.ip == gw and d.mac}
            if len(macs) > 1:
                findings.append(Finding(
                    severity="critical",
                    category="mitm",
                    title=f"Gateway {gw} is claimed by more than one hardware address",
                    detail=(
                        "Two or more MAC addresses are answering for your default "
                        "gateway. On a switched network this is what ARP spoofing "
                        "looks like: traffic you believe is going to the router may be "
                        "passing through something else first."
                    ),
                    evidence=sorted(macs),
                ))
            for mac in macs:
                if VendorDatabase.is_locally_administered(mac):
                    findings.append(Finding(
                        severity="warning",
                        category="mitm",
                        title=f"Gateway {gw} has a locally-administered MAC",
                        detail=(
                            "Your gateway's hardware address has the locally-administered "
                            "bit set, meaning it is software-assigned rather than burned "
                            "in. Some routers and virtual appliances do this legitimately, "
                            "but it is also what a spoofed gateway looks like."
                        ),
                        evidence=[mac],
                    ))
        return findings

    @staticmethod
    def detect_duplicate_macs(devices: List[NetworkDevice]) -> List[Finding]:
        """
        One hardware address holding several addresses on our network.

        Legitimate for a router or a multi-homed host, so this is reported as
        information rather than an alarm — but it is also how a single machine
        masquerades as several, so it is worth surfacing rather than hiding.
        """
        findings = []
        by_mac = defaultdict(list)
        for d in devices:
            if d.mac and d.ownership == "ours":
                by_mac[d.mac].append(d.ip)
        for mac, ips in sorted(by_mac.items()):
            if len(ips) > 1:
                findings.append(Finding(
                    severity="info",
                    category="rogue",
                    title=f"{mac} holds {len(ips)} addresses",
                    detail=("One network adapter is answering for several addresses. "
                            "Normal for a router or a multi-homed host; unexpected "
                            "otherwise."),
                    evidence=sorted(ips, key=_ip_sort_key),
                ))
        return findings

    @staticmethod
    def detect_weak_wireless(wifi: List['WifiNetwork']) -> List[Finding]:
        """
        Open or obsolete encryption on networks in range.

        Reported for our own networks as a problem to fix. For networks that are
        not ours it is recorded as context only: it describes the radio
        environment we sit in, and an open AP nearby is a plausible staging
        point for someone targeting this area.
        """
        findings = []
        weak_ours, weak_near = [], []
        for n in wifi:
            auth = (n.authentication or "").strip().lower()
            if n.is_open or any(w in auth for w in ("wep",)) or auth in ("wpa-personal",):
                label = (f"{n.display_name} [{n.bssid}] "
                         f"{n.authentication or 'open'} · {n.signal_percent}%")
                (weak_ours if n.ownership == "ours" else weak_near).append(label)

        if weak_ours:
            findings.append(Finding(
                severity="critical",
                category="weak-crypto",
                title="One of your wireless networks uses weak or no encryption",
                detail=("Traffic on this network can be read or joined by anyone in "
                        "range. Move it to WPA2 or WPA3."),
                evidence=sorted(weak_ours),
            ))
        if weak_near:
            findings.append(Finding(
                severity="info",
                category="weak-crypto",
                title=f"{len(weak_near)} nearby network(s) use weak or no encryption",
                detail=("Context only — these are not yours and were not contacted. "
                        "An open access point in range is a convenient position for "
                        "someone operating in this area."),
                evidence=sorted(weak_near),
            ))
        return findings

    @staticmethod
    def compare_to_baseline(devices: List[NetworkDevice],
                            wifi: List['WifiNetwork'],
                            baseline: Dict[str, Any]) -> List[Finding]:
        """
        Diff against the previous scan.

        Change is the earliest signal available. A device that was not on the
        network yesterday, or an access point that has just appeared, is worth
        knowing about long before anything about it looks individually
        suspicious — and noticing it requires no traffic at all.
        """
        findings = []

        prev_devices = {d.get("mac"): d for d in baseline.get("lan_devices", [])
                        if d.get("mac")}
        now_devices = {d.mac: d for d in devices if d.mac and d.ownership == "ours"}

        new_macs = sorted(set(now_devices) - set(prev_devices))
        if new_macs:
            findings.append(Finding(
                severity="warning",
                category="change",
                title=f"{len(new_macs)} device(s) appeared since the last scan",
                detail="These hardware addresses were not present previously.",
                evidence=[f"{now_devices[m].ip}  {m}  "
                          f"{now_devices[m].hostname or 'no hostname'}  "
                          f"{now_devices[m].vendor or 'unknown vendor'}"
                          for m in new_macs],
            ))

        gone = sorted(set(prev_devices) - set(now_devices))
        if gone:
            findings.append(Finding(
                severity="info",
                category="change",
                title=f"{len(gone)} device(s) are no longer present",
                detail="Present in the previous scan, absent now.",
                evidence=[f"{prev_devices[m].get('ip','?')}  {m}  "
                          f"{prev_devices[m].get('hostname') or 'no hostname'}"
                          for m in gone],
            ))

        # An address changing hands is more interesting than one appearing.
        prev_by_ip = {d.get("ip"): d.get("mac") for d in baseline.get("lan_devices", [])
                      if d.get("ip") and d.get("mac")}
        changed = []
        for d in devices:
            was = prev_by_ip.get(d.ip)
            if was and d.mac and was != d.mac:
                changed.append(f"{d.ip}: {was} -> {d.mac}")
        if changed:
            findings.append(Finding(
                severity="warning",
                category="change",
                title=f"{len(changed)} address(es) changed hardware address",
                detail=("The same IP is now answered by different hardware. Usually a "
                        "DHCP lease moving between devices; also what an impersonation "
                        "attempt looks like."),
                evidence=sorted(changed),
            ))

        prev_bssids = {n.get("bssid"): n for n in baseline.get("wifi_networks", [])
                       if n.get("bssid")}
        now_bssids = {n.bssid: n for n in wifi}
        new_aps = sorted(set(now_bssids) - set(prev_bssids))
        if new_aps:
            near = [b for b in new_aps if now_bssids[b].ownership != "ours"]
            findings.append(Finding(
                severity="info" if not any(now_bssids[b].ownership == "ours"
                                           for b in new_aps) else "warning",
                category="change",
                title=f"{len(new_aps)} access point(s) appeared since the last scan",
                detail=("New radios in range. A new AP carrying a familiar name is the "
                        "one to look at closely."),
                evidence=[f"{b}  {now_bssids[b].display_name}  "
                          f"{now_bssids[b].signal_percent}%  "
                          f"{'OURS' if now_bssids[b].ownership == 'ours' else 'nearby'}"
                          for b in new_aps],
            ))
        return findings
