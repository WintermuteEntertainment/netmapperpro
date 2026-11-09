"""MAC address to manufacturer lookup."""

import subprocess, re, time, os, json, ipaddress, socket, sys, math, statistics, html, argparse, shlex
import csv
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple, Optional, Any, DefaultDict
from collections import defaultdict, Counter
from pathlib import Path
import http.client, ssl, urllib.parse, base64, webbrowser, tempfile, hashlib, random, string, textwrap
import concurrent.futures
import itertools
import threading


# ==================== SIMPLIFIED VENDOR DATABASE ====================
class VendorDatabase:
    """
    LOCAL MAC VENDOR LOOKUP DATABASE - COMPACT VERSION
    
    This provides device manufacturer identification from MAC addresses
    using a local database (no internet queries for privacy).
    
    HOW IT WORKS:
    - MAC addresses have a unique prefix (OUI) assigned to manufacturers
    - This database maps those prefixes to vendor names
    - Works offline for privacy and speed
    """
    
    # Common vendor prefixes - focused on most common devices
    VENDOR_DB = {
        "00:50:56": "VMware",
        "00:0C:29": "VMware",
        "00:05:69": "VMware",
        "00:1C:14": "VMware",
        "00:1C:42": "Parallels",
        "00:15:5D": "Microsoft Hyper-V",
        
        # Network Equipment
        "00:1C:0E": "Cisco",
        "00:1C:58": "Cisco",
        "00:21:D8": "Cisco",
        "00:22:55": "Cisco",
        "00:23:04": "Cisco",
        "A0:21:B7": "NETGEAR",
        "14:91:82": "TP-Link",
        "C4:12:F5": "D-Link",
        # NOTE: a malformed "B0:04:E:26" -> Xiaomi entry lived here. It had only
        # five hex digits in the OUI, so it could never match a normalised MAC.
        # Removed rather than guessed at; see load_oui_file() for real coverage.
        "F8:1A:67": "Linksys",
        "A8:AD:3D": "ASUSTek",
        "88:25:2C": "Ubiquiti",
        "74:83:C2": "Ubiquiti",
        "F0:9F:C2": "Ubiquiti",
        "04:18:D6": "Ubiquiti",
        "B4:FB:E4": "Ubiquiti",
        "E0:63:DA": "Ubiquiti",
        
        # Apple Devices
        "A4:83:E7": "Apple",
        "B8:E9:37": "Apple",
        "DC:41:A9": "Apple",
        "F0:18:98": "Apple",
        "F0:1F:AF": "Apple",
        "F4:5C:89": "Apple",
        "F8:1E:DF": "Apple",
        "00:03:93": "Apple",
        "00:17:F2": "Apple",
        "00:1B:63": "Apple",
        "00:1E:52": "Apple",
        "00:23:6C": "Apple",
        "00:25:00": "Apple",
        "00:26:08": "Apple",
        "00:26:4A": "Apple",
        
        # Samsung Devices
        "00:00:F0": "Samsung",
        "00:07:AB": "Samsung",
        "00:12:47": "Samsung",
        "00:15:99": "Samsung",
        "00:16:32": "Samsung",
        "00:17:D5": "Samsung",
        "00:1A:8A": "Samsung",
        "00:1D:25": "Samsung",
        "00:23:39": "Samsung",
        "00:24:54": "Samsung",
        "00:25:38": "Samsung",
        "5C:F8:A1": "Samsung",
        "5C:E0:C5": "Samsung",
        "5C:49:7D": "Samsung",
        
        # Google Devices
        "08:9E:08": "Google",
        "0C:8B:FD": "Google",
        "1C:1A:DF": "Google",
        "20:DF:B9": "Google",
        "28:16:AD": "Google",
        "30:FD:38": "Google",
        "3C:5A:B4": "Google",
        "40:F4:EC": "Google",
        "44:07:0B": "Google",
        "50:F0:D3": "Google",
        "54:60:09": "Google",
        "60:D9:C7": "Google",
        "64:A7:DD": "Google",
        "68:EB:AE": "Google",
        "74:23:44": "Google",
        "78:71:9C": "Google",
        "7C:DD:90": "Google",
        "84:0D:8E": "Google",
        "88:AD:43": "Google",
        "94:EB:2C": "Google",
        "AC:67:84": "Google",
        "B8:F9:34": "Google",
        "C0:84:7A": "Google",
        "D0:31:69": "Google",
        "E4:F0:42": "Google",
        "F4:F5:D8": "Google",
        "F8:8F:CA": "Google",
        
        # IoT Devices
        "B8:27:EB": "Raspberry Pi",
        "DC:A6:32": "Raspberry Pi",
        "E4:5F:01": "Raspberry Pi",
        "28:CD:C1": "Sonos",
        "94:9F:3E": "Sonos",
        "78:28:CA": "Belkin (Wemo)",
        "EC:1A:59": "Belkin (Wemo)",
        "D8:A6:FD": "Philips Hue",
        "00:17:88": "Philips Hue",
        "70:CE:8C": "Ring",
        "34:EA:34": "Nest",
        "18:B4:30": "Nest",
        "30:8C:FB": "Arlo",
        "44:65:0D": "Amazon Echo",
        "68:54:5A": "Amazon Fire TV",
        "F0:27:2D": "Google Home",
        "38:87:D5": "SmartThings",
        # NOTE: "84:0D:8E" was listed twice (once as Google above, once as
        # Google Chromecast here). In a dict literal the later key silently
        # wins, so every Google device was being labelled Chromecast. The
        # duplicate is removed; the Google entry above stands.

        # Dell Computers
        "00:14:22": "Dell",
        "00:1A:A0": "Dell",
        "00:1D:09": "Dell",
        "00:21:9B": "Dell",
        "00:22:19": "Dell",
        "00:24:E8": "Dell",
        "00:26:B9": "Dell",
        "08:18:1A": "Dell",
        "0C:1D:AF": "Dell",
        "10:29:A6": "Dell",
        "14:77:3F": "Dell",
        "18:03:73": "Dell",
        "1C:39:47": "Dell",
        "20:47:ED": "Dell",
        "24:6E:96": "Dell",
        "28:B2:BD": "Dell",
        "30:39:26": "Dell",
        
        # HP Devices
        "00:01:E6": "HP",
        "00:04:EA": "HP",
        "00:08:02": "HP",
        "00:0B:CD": "HP",
        "00:0E:7F": "HP",
        "00:0F:20": "HP",
        "00:11:0A": "HP",
        "00:13:21": "HP",
        "00:14:38": "HP",
        "00:15:60": "HP",
        "00:17:A4": "HP",
        "00:18:FE": "HP",
        "00:19:BB": "HP",
        "00:1A:4B": "HP",
        "00:1B:24": "HP",
        "00:1C:C4": "HP",
        
        # Microsoft Devices
        "00:50:F2": "Microsoft",
        # NOTE: "00:15:5D" was duplicated here, overwriting the more specific
        # "Microsoft Hyper-V" entry defined above and hiding every Hyper-V and
        # WSL virtual NIC. Removed; the Hyper-V entry stands.
        "00:0D:3A": "Microsoft",
        "00:1D:D8": "Microsoft",
        "00:22:48": "Microsoft",
        "00:25:AE": "Microsoft",
        "00:26:55": "Microsoft",
        
    }

    # Populated by load_oui_file() if a real IEEE registry is available.
    # Kept separate from VENDOR_DB so the built-in table always works offline.
    EXTERNAL_OUI: Dict[str, str] = {}

    @staticmethod
    def normalize(mac_address: str) -> str:
        """Normalise a MAC to uppercase colon-separated form, or '' if unusable."""
        if not mac_address:
            return ""
        return mac_address.upper().replace('-', ':').replace('.', ':').strip()

    @staticmethod
    def is_broadcast(mac: str) -> bool:
        return VendorDatabase.normalize(mac) == "FF:FF:FF:FF:FF:FF"

    @staticmethod
    def is_multicast(mac: str) -> bool:
        """
        True if the multicast bit (least significant bit of the first octet)
        is set. This is the actual IEEE rule, not a prefix guess.
        """
        mac = VendorDatabase.normalize(mac)
        if len(mac) < 2:
            return False
        try:
            return bool(int(mac[:2], 16) & 0x01)
        except ValueError:
            return False

    @staticmethod
    def is_locally_administered(mac: str) -> bool:
        """
        True if the locally-administered bit (bit 1 of the first octet) is set.

        This matters for wireless mapping: an access point broadcasting several
        SSIDs derives extra BSSIDs from its burned-in address by flipping this
        bit, so 0E:, 1A:, 7E: and A2: prefixes are virtual radios rather than
        distinct hardware. Checking the bit catches all of them; the previous
        code only tested for a literal '02:' prefix and missed the rest.
        """
        mac = VendorDatabase.normalize(mac)
        if len(mac) < 2:
            return False
        try:
            return bool(int(mac[:2], 16) & 0x02)
        except ValueError:
            return False

    @staticmethod
    def physical_radio_key(mac: str) -> str:
        """
        Loose grouping key: octets 2-5 of the BSSID.

        Intended for DISPLAY grouping only — collapsing an access point's
        virtual radios back onto one row. Do not use it as ownership evidence;
        four bytes is not enough to assert a device is yours.

        Clearing the locally-administered bit alone is not sufficient, which is
        what an earlier version of this did. Real hardware in range derives its
        virtual BSSIDs by altering the first AND last octet together:

            78:D2:94:C5:D7:54  ->  7E:D2:94:C5:D7:51
            08:36:C9:0C:63:D8  ->  0E:36:C9:0C:63:D5
            14:59:C0:2E:08:09  ->  1A:59:C0:2E:08:06

        Clearing the LA bit on 7E gives 7C, not 78, so that key never matched
        and every BSSID looked like separate hardware. Octets 2-5 are stable
        across all of these.
        """
        mac = VendorDatabase.normalize(mac)
        if len(mac) < 17:
            return mac
        return mac[3:14]  # octets 2-5, e.g. "D2:94:C5:D7"

    @staticmethod
    def hardware_key(mac: str) -> str:
        """
        Strict identity key: octets 1-5, with the locally-administered bit
        cleared on the first octet.

        Used as ownership evidence. It matches a combined router/AP's extra
        radios against its wired MAC (36:5D:9E:EF:C8:80 normalises to
        34:5D:9E:EF:C8, matching gateway 34:5D:9E:EF:C8:84) without being loose
        enough to sweep in a neighbour's hardware.
        """
        mac = VendorDatabase.normalize(mac)
        if len(mac) < 17:
            return mac
        try:
            first = int(mac[:2], 16) & ~0x02  # clear the LA bit
            return f"{first:02X}{mac[2:14]}"
        except ValueError:
            return mac[:14]

    # Filenames searched for automatically, in preference order. The IEEE
    # registry is ~40,000 assignments against the ~130 that ship inline, so
    # when one of these is present it is worth loading without being asked.
    OUI_FILENAMES = ("oui.csv", "manuf", "nmap-mac-prefixes", "oui.txt")
    _autoloaded = False

    @staticmethod
    def autoload(extra_dirs: Optional[List[str]] = None) -> int:
        """
        Load a vendor registry from beside the script, if one is present.

        Returns the number of prefixes loaded, or 0 if no file was found. Safe
        to call repeatedly: it only acts once.
        """
        if VendorDatabase._autoloaded:
            return 0
        VendorDatabase._autoloaded = True

        # The repo root, where NET_MAPPER_PRO.py and oui.csv live. This module
        # sits one level down, in netmapper/.
        search = [Path(__file__).resolve().parent.parent]
        search += [Path(d) for d in (extra_dirs or [])]
        search.append(Path.cwd())
        for directory in search:
            for name in VendorDatabase.OUI_FILENAMES:
                candidate = directory / name
                if candidate.exists() and candidate.is_file():
                    loaded = VendorDatabase.load_oui_file(str(candidate))
                    if loaded:
                        return loaded
        return 0

    @staticmethod
    def load_oui_file(path: str) -> int:
        """
        Optionally load a full IEEE OUI registry to replace the small built-in
        table. Accepts the standard 'oui.csv' (Registry,Assignment,Organization
        Name,...) or a simple 'AABBCC<sep>Vendor' text file.

        Returns the number of prefixes loaded. Never raises: if the file is
        missing or unparseable the built-in table simply stays in use.
        """
        loaded = 0
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.lower().startswith("registry,"):
                        continue
                    if "," in line:
                        # IEEE quotes names that contain commas, e.g.
                        # "Hangzhou Hikvision Digital Technology Co.,Ltd.",
                        # so a plain split cut them at the first comma.
                        parts = next(csv.reader([line]))
                        if not (len(parts) >= 3 and len(parts[1]) == 6):
                            # 'AABBCC,Vendor, Inc.': keep the rest whole.
                            parts = line.split(",", 1)
                    else:
                        parts = line.split(None, 1)
                    if len(parts) >= 3 and len(parts[1]) == 6:
                        # csv.reader has already removed the quoting; names
                        # such as 'UAB "Teltonika Telematics"' keep their own.
                        oui, name = parts[1], parts[2].strip()
                    elif len(parts) == 2 and len(parts[0].replace(":", "").replace("-", "")) == 6:
                        oui = parts[0].replace(":", "").replace("-", "")
                        name = parts[1].strip()
                    else:
                        continue
                    oui = oui.upper()
                    if len(oui) != 6:
                        continue
                    key = f"{oui[0:2]}:{oui[2:4]}:{oui[4:6]}"
                    VendorDatabase.EXTERNAL_OUI[key] = name
                    loaded += 1
        except Exception:
            return 0
        return loaded

    @staticmethod
    def lookup(mac_address: str) -> str:
        """
        Look up vendor from MAC address.

        Resolution order:
          1. Structural cases decided by the MAC's own bits (broadcast/multicast)
          2. External IEEE registry, if one was loaded
          3. Built-in table, longest matching prefix wins
          4. Locally-administered / randomised
          5. Unknown

        The previous version iterated the table and returned the FIRST prefix
        that matched, which made the result depend on dict insertion order.
        Longest-prefix matching makes it deterministic.
        """
        mac = VendorDatabase.normalize(mac_address)
        if not mac:
            return "Unknown"

        if VendorDatabase.is_broadcast(mac):
            return "Broadcast"
        if mac.startswith("33:33:"):
            return "IPv6 Multicast"
        if VendorDatabase.is_multicast(mac):
            return "Multicast"

        oui = mac[:8]  # AA:BB:CC
        if oui in VendorDatabase.EXTERNAL_OUI:
            return VendorDatabase.EXTERNAL_OUI[oui]

        best_key = ""
        best_vendor = ""
        for key, vendor in VendorDatabase.VENDOR_DB.items():
            if mac.startswith(key) and len(key) > len(best_key):
                best_key, best_vendor = key, vendor
        if best_vendor:
            return best_vendor

        # A locally-administered address with no OUI match is either a virtual
        # interface or a privacy-randomised client. Say so rather than "Unknown".
        if VendorDatabase.is_locally_administered(mac):
            return "Randomised/Virtual"

        return "Unknown"
