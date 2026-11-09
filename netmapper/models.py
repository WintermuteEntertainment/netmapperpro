"""Records shared across the scanner: devices, Wi-Fi networks, findings."""

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


# ==================== ENHANCED DATA MODELS ====================
@dataclass
class NetworkDevice:
    """
    ENHANCED NETWORK DEVICE MODEL WITH TOPOLOGY INFO
    
    This class represents a network device with all its attributes.
    It's the core data structure used throughout the application.
    
    KEY ATTRIBUTES:
    - ip: Device IP address
    - mac: Device MAC address
    - hostname: Device name (if resolvable)
    - vendor: Manufacturer (from MAC address)
    - device_type: Category (router, computer, IoT, etc.)
    - subnet: Network subnet the device belongs to
    - gateway: Associated gateway/router
    - tags: Set of labels (wireless, gateway, virtual, etc.)
    """
    ip: str
    mac: str = ""
    hostname: str = ""
    vendor: str = ""
    device_type: str = "unknown"
    network_type: str = "unknown"
    os_family: str = "unknown"
    subnet: str = ""
    prefix_length: int = 0  # real prefix from the interface, 0 if unknown
    interface: str = ""  # adapter alias this device was seen on
    ownership: str = "unknown"  # ours | nearby | unknown
    discovered_via: str = ""  # neighbor | sweep
    origin: str = ""  # attached | routed | adjacent | declared
    gateway: str = ""  # Associated gateway/router
    wifi_ap: str = ""  # WiFi access point MAC if connected via WiFi
    parent_device: str = ""  # Parent device in topology (for hierarchy)
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    response_time: float = 0.0
    ttl: int = 0  # Time To Live from ping (used for OS detection)
    neighbor_state: str = ""  # Reachable / Stale / Probe, from the neighbour table
    ports_open: List[int] = field(default_factory=list)
    # port -> what the service said for itself, when banner reading was on.
    # Kept per-port rather than collapsed into one string: an SSH version and
    # an HTTP Server header on the same host are two separate facts.
    banners: Dict[int, str] = field(default_factory=dict)
    services: List[str] = field(default_factory=list)
    model: str = ""            # exact model, when a device tells us
    management_url: str = ""   # device service / admin URL, when advertised
    confidence: float = 0.5  # Confidence level in device identification
    is_default_gateway: bool = False  # set from the ROUTING TABLE, not guessed
    tags: Set[str] = field(default_factory=set)  # Labels: wireless, gateway, virtual, etc.

    def __post_init__(self):
        """
        Derive the subnet from the IP and the REAL prefix length.

        The previous version hardcoded /24 for every address, which silently
        mislabelled every device on any other prefix. When the prefix is not
        known (0) the subnet is left empty rather than fabricated; the scanner
        fills it in from the owning interface.
        """
        self.assign_subnet(self.prefix_length)

    def assign_subnet(self, prefix_length: int):
        """Recompute the subnet label using a known prefix length."""
        if not self.ip or '.' not in self.ip or not prefix_length:
            return
        try:
            net = ipaddress.ip_network(f"{self.ip}/{prefix_length}", strict=False)
            self.subnet = str(net)
            self.prefix_length = prefix_length
        except ValueError:
            pass

    @property
    def is_gateway(self) -> bool:
        """
        True only when we have evidence, not when the IP merely looks like one.

        The previous version returned True for any address ending in .1 or .254,
        which invented a router in every subnet it touched. Gateways are now
        established from the routing table (is_default_gateway) or from an
        explicit classification.
        """
        return (self.is_default_gateway or
                self.device_type == 'router' or
                'gateway' in self.tags)
    
    @property
    def is_wifi_ap(self) -> bool:
        """Check if device is a WiFi access point."""
        return (self.device_type in ['wifi', 'wifi_5g', 'wifi_2g'] or
                'access point' in (self.vendor or '').lower() or
                'wireless' in (self.vendor or '').lower())
    
    @property
    def is_virtual(self) -> bool:
        """Check if device is virtual (VMware, Hyper-V, etc.)."""
        if not self.mac:
            return False
        # Common virtual machine MAC address prefixes
        virtual_macs = ['00:50:56', '00:0C:29', '00:05:69', '00:1C:14', '00:1C:42']
        return any(self.mac.upper().startswith(prefix) for prefix in virtual_macs)


# ==================== WIRELESS DATA MODEL ====================
@dataclass
class WifiNetwork:
    """
    One visible BSSID: a single radio advertising a single SSID.

    Modelled per-BSSID rather than per-SSID because that is what the radio
    actually reports. A mesh or multi-band router publishes the same SSID from
    several BSSIDs, and collapsing them (as the old code did, by overwriting)
    threw away both the count and every per-radio measurement.
    """
    ssid: str
    bssid: str
    signal_percent: int = 0
    radio_type: str = ""       # 802.11ac, 802.11be, ...
    band: str = ""             # "2.4 GHz" / "5 GHz" / "6 GHz", as reported
    channel: int = 0
    authentication: str = ""
    encryption: str = ""
    network_type: str = ""     # Infrastructure / Adhoc
    connected_stations: int = 0
    channel_utilization: int = 0
    vendor: str = ""
    is_virtual_bssid: bool = False
    physical_radio: str = ""
    ownership: str = "foreign"  # ours | foreign

    @property
    def is_hidden(self) -> bool:
        return not self.ssid.strip()

    @property
    def display_name(self) -> str:
        return self.ssid if self.ssid.strip() else "[Hidden SSID]"

    @property
    def band_label(self) -> str:
        """
        Band as measured, falling back to the channel number.

        The old code inferred this from whether the SSID string contained
        "5G", so a network named 'Fibre5G' broadcasting on 2.4 GHz was
        mislabelled and one named 'Home' was always called 2.4 GHz.
        """
        if self.band:
            return self.band
        if self.channel:
            if self.channel <= 14:
                return "2.4 GHz"
            if self.channel <= 177:
                return "5 GHz"
            return "6 GHz"
        return "unknown"

    @property
    def is_open(self) -> bool:
        """True if the network advertises no authentication."""
        return self.authentication.strip().lower() in ("open", "none", "")

    def to_device(self) -> NetworkDevice:
        """
        Adapt to a NetworkDevice so the existing diagram and dashboard
        generators can consume wireless results unchanged.
        """
        device = NetworkDevice(
            ip="",
            mac=self.bssid,
            hostname=self.display_name,
            vendor=self.vendor or VendorDatabase.lookup(self.bssid),
            network_type="wifi",
        )
        band = self.band_label
        if band.startswith("5"):
            device.device_type = "wifi_5g"
        elif band.startswith("6"):
            device.device_type = "wifi_6g"
        elif band.startswith("2"):
            device.device_type = "wifi_2g"
        else:
            device.device_type = "wifi"
        device.ownership = self.ownership
        if self.is_hidden:
            device.tags.add("hidden")
        if self.is_virtual_bssid:
            device.tags.add("virtual_bssid")
        if self.is_open:
            device.tags.add("open")
        device.tags.add(self.ownership)
        return device


# ==================== PASSIVE THREAT ANALYSIS ====================
@dataclass
class Finding:
    """One observation worth a human's attention."""
    severity: str      # critical | warning | info
    category: str      # impersonation | mitm | rogue | weak-crypto | change
    title: str
    detail: str
    evidence: List[str] = field(default_factory=list)

    def to_dict(self):
        return {
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "detail": self.detail,
            "evidence": list(self.evidence),
        }


def _ip_sort_key(ip: str):
    """Sort IPv4 addresses numerically rather than as strings, so .9 precedes .10."""
    try:
        return (0,) + tuple(int(o) for o in ip.split('.'))
    except (ValueError, AttributeError):
        return (1, ip)
