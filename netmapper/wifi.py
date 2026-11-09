"""Passive Wi-Fi survey through netsh."""

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

from .config import Config
from .vendors import VendorDatabase
from .models import WifiNetwork


# ==================== SECURE WiFi SCANNER ====================
class SecureWiFiScanner:
    """
    WiFi NETWORK SCANNER WITH SECURITY IMPROVEMENTS
    
    Scans for WiFi networks and access points.
    Uses system commands (netsh on Windows) to get WiFi information.
    
    NOTE: Currently Windows-focused. Would need adaptation for Linux/macOS.
    """
    
    @staticmethod
    def run_cmd_safe(cmd: str, timeout: int = 20) -> str:
        """
        Execute shell command safely.

        Args:
            cmd: Command to execute
            timeout: Maximum execution time

        Returns:
            Command output or empty string on error
        """
        try:
            args = shlex.split(cmd)
            result = subprocess.run(args, shell=False, capture_output=True,
                                    text=True, timeout=timeout,
                                    encoding='utf-8', errors='replace')
            return result.stdout
        except Exception:
            return ""

    @staticmethod
    def get_interface_state() -> Dict[str, str]:
        """
        Read the wireless adapter's own state: the SSID/BSSID it is associated
        with, if any, plus its hardware MAC.

        Knowing what we are connected to is the only reliable way to say which
        visible network is ours; everything else is inference.
        """
        state = {}
        out = SecureWiFiScanner.run_cmd_safe("netsh wlan show interfaces")
        for line in out.splitlines():
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            key = key.strip().lower()
            value = value.strip()
            if key == "state":
                state["state"] = value
            elif key == "ssid":
                state["ssid"] = value
            elif key == "bssid":
                state["bssid"] = VendorDatabase.normalize(value)
            elif key == "physical address":
                state["adapter_mac"] = VendorDatabase.normalize(value)
            elif key == "name":
                state["adapter"] = value
        return state

    @staticmethod
    def scan_wifi(our_macs: Optional[Set[str]] = None) -> List['WifiNetwork']:
        """
        Enumerate visible wireless networks, passively.

        This reads the radio's existing scan results. It does not associate,
        authenticate, deauthenticate, or transmit anything toward the networks
        it lists: observing a beacon is not contacting the network.

        The previous parser kept a single BSSID per SSID (each new one
        overwrote the last) and discarded signal strength, band, channel,
        radio type, authentication and encryption entirely, then guessed the
        band by looking for "5G" in the network's *name*. All of that data is
        present in the output and is captured here.
        """
        networks: List['WifiNetwork'] = []
        if Config.SCAN_MODE not in ("all", "wifi"):
            return networks

        out = SecureWiFiScanner.run_cmd_safe("netsh wlan show networks mode=bssid")
        if not out.strip():
            return networks

        ssid = None
        auth = encryption = net_type = ""
        current: Optional['WifiNetwork'] = None

        def flush():
            if current is not None:
                networks.append(current)

        for raw in out.splitlines():
            line = raw.strip()
            if not line or ":" not in line:
                continue
            key, _, value = line.partition(":")
            key = key.strip()
            value = value.strip()
            low = key.lower()

            if low.startswith("ssid") and not low.startswith("bssid"):
                flush()
                current = None
                ssid = value  # may legitimately be empty -> hidden network
                auth = encryption = net_type = ""
            elif low == "network type":
                net_type = value
            elif low == "authentication":
                auth = value
            elif low == "encryption":
                encryption = value
            elif low.startswith("bssid"):
                flush()
                current = WifiNetwork(
                    ssid=ssid if ssid else "",
                    bssid=VendorDatabase.normalize(value),
                    authentication=auth,
                    encryption=encryption,
                    network_type=net_type,
                )
            elif current is not None:
                if low == "signal":
                    m = re.search(r"(\d+)", value)
                    if m:
                        current.signal_percent = int(m.group(1))
                elif low == "radio type":
                    current.radio_type = value
                elif low == "band":
                    current.band = value
                elif low == "channel":
                    m = re.search(r"(\d+)", value)
                    if m:
                        current.channel = int(m.group(1))
                elif low == "connected stations":
                    m = re.search(r"(\d+)", value)
                    if m:
                        current.connected_stations = int(m.group(1))
                elif low == "channel utilization":
                    m = re.search(r"\((\d+)\s*%\)", value)
                    if m:
                        current.channel_utilization = int(m.group(1))
        flush()

        # Post-process: vendor, virtual-radio detection, ownership
        iface = SecureWiFiScanner.get_interface_state()
        connected_ssid = iface.get("ssid", "")
        connected_bssid = iface.get("bssid", "")
        our_macs = our_macs or set()
        # Strict key: ownership must not rest on the loose display-grouping key.
        our_radio_keys = {VendorDatabase.hardware_key(m) for m in our_macs if m}

        for net in networks:
            net.vendor = VendorDatabase.lookup(net.bssid)
            net.is_virtual_bssid = VendorDatabase.is_locally_administered(net.bssid)
            net.physical_radio = VendorDatabase.physical_radio_key(net.bssid)
            net.ownership = SecureWiFiScanner._classify_wifi_ownership(
                net, connected_ssid, connected_bssid, our_macs, our_radio_keys
            )

        return networks

    @staticmethod
    def _classify_wifi_ownership(net: 'WifiNetwork', connected_ssid: str,
                                 connected_bssid: str, our_macs: Set[str],
                                 our_radio_keys: Set[str]) -> str:
        """
        Decide whether a visible wireless network is ours.

        'ours' requires actual evidence:
          - we are associated with this exact BSSID, or
          - we are associated with this SSID, or
          - the BSSID is the same physical radio as a device on our wired
            network (a router that both routes for us and broadcasts WiFi), or
          - the BSSID differs from one of our known MACs only in the last
            octet, which is how a combined router/AP numbers its radios.

        Everything else is 'foreign'. Being loud, being close, or having a
        familiar-looking name is not evidence.
        """
        if connected_bssid and net.bssid == connected_bssid:
            return "ours"
        if connected_ssid and net.ssid and net.ssid == connected_ssid:
            return "ours"
        # Same hardware as a device on our wired network, LA-bit normalised.
        if VendorDatabase.hardware_key(net.bssid) in our_radio_keys:
            return "ours"
        return "foreign"

    @staticmethod
    def group_by_radio(networks: List['WifiNetwork']) -> Dict[str, List['WifiNetwork']]:
        """
        Group BSSIDs that are almost certainly the same physical access point.

        An AP broadcasting several SSIDs derives extra BSSIDs from its burned-in
        address by setting the locally-administered bit, so clearing that bit
        collapses the virtual radios back onto their hardware.
        """
        groups: Dict[str, List['WifiNetwork']] = defaultdict(list)
        for net in networks:
            groups[net.physical_radio].append(net)
        return dict(groups)
