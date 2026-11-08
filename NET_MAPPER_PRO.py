#!/usr/bin/env python3
"""
🌐 NETWORK INTELLIGENCE MAPPER PRO 
Security improvements without compromising visualization accuracy

MAIN PURPOSE:
This script scans and visualizes network topology with enhanced security features.
It discovers devices, maps network structure, and generates interactive diagrams
while implementing security best practices.

KEY FEATURES:
1. Network Discovery: Scans LAN and WiFi devices
2. Topology Mapping: Creates hierarchical network diagrams
3. Security Focus: Includes input validation, rate limiting, and ethical guidelines
4. Visualization: Generates interactive draw.io diagrams and HTML dashboards
5. Privacy Protection: Skips multicast addresses, validates all inputs
"""

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

# ==================== ENHANCED SECURITY CONFIGURATION ====================
class Config:
    """
    Central configuration class with security enhancements.
    All scan parameters and security settings are defined here.
    
    SECURITY FEATURES:
    - Rate limiting to prevent network flooding
    - Input validation to prevent command injection
    - Legal and ethical usage warnings
    - Skip multicast/broadcast addresses for privacy
    - Thread-safe scanning operations
    """
    
    # ===== DISPLAY AND BEHAVIOUR =====
    AUTO_OPEN = True
    SCAN_MODE = "all"  # all, lan, wifi

    # ===== SCAN SCOPE =====
    # Networks are ENUMERATED from the live adapter and routing tables, never
    # guessed from IP arithmetic. SCAN_SCOPE decides how far the active sweep
    # reaches.
    #
    #   "attached" — only networks this host holds an address on  (DEFAULT)
    #   "routed"   — attached + networks with a real next-hop route, i.e.
    #                other subnets reachable through our own gateways/VLANs
    #   "wide"     — routed + the /24s adjacent to each attached network
    #
    # Default is "attached". Discovering what is nearby is a goal of this tool,
    # but that is satisfied by the PASSIVE wireless survey, which sees the
    # neighbours' networks without sending them anything. Actively sweeping an
    # adjacent /24 is a different act: those addresses belong to someone else,
    # and probing them is not ours to do by default.
    #
    # "wide" therefore requires an explicit acknowledgement (--i-have-permission
    # on the CLI, a confirmation in the UI) and is appropriate only where you
    # have authority over the ranges concerned — a lab, or a site you run.
    SCAN_SCOPE = "attached"

    # ===== PROBE INTRUSIVENESS =====
    # How hard we are willing to poke something. Reachability testing is
    # ordinary traffic; anything past it starts to look like an attack to an
    # IDS and is therefore opt-in, per-run, with the operator saying so.
    #
    # The sweep itself is ICMP echo only and always has been. Everything past
    # that lives in the PROBE_* settings further down and is driven by
    # ServiceProbe, which is opt-in per run.
    #
    # NOTE: this block previously declared PROBE_LEVEL and PROBE_PORTS. They
    # were documented at length and printed in one log line, but nothing read
    # them — there was no --probe flag and no code path that acted on either.
    # They are replaced by the PROBE_* settings below, which are wired up.

    # Additional CIDRs to sweep that this machine has no interface or route for
    # (e.g. a segment you know exists but is not in the routing table). Opt-in.
    EXTRA_SUBNETS: List[str] = []
    SCAN_VIRTUAL_ADAPTERS = False  # sweep Hyper-V / WSL / VMware host networks
    SCAN_VPN_ADAPTERS = False      # sweep VPN / overlay networks (Tailscale etc.)
    MAX_SWEEP_HOSTS = 8192  # refuse to sweep a network larger than this (a /19)

    # ===== SECURITY & PRIVACY =====
    LEGAL_WARNING_REQUIRED = True  # Show legal disclaimer (disable via --no-warning)
    SHOW_ETHICAL_GUIDELINES = True  # Display ethical usage tips
    SKIP_MULTICAST_IPS = True  # Exclude multicast/broadcast from results
    VALIDATE_COMMAND_INPUTS = True  # Prevent command injection attacks

    # ===== SCAN TUNING =====
    SCAN_TIMEOUT = 5      # per-probe timeout, seconds
    SCAN_THREADS = 50     # parallel ping workers
    RATE_LIMIT_SCANS = True  # pace probes to avoid flooding the network
    RATE_LIMIT_DELAY = 0.01  # minimum seconds between probe launches (global)

    # ===== ENRICHMENT =====
    RESOLVE_HOSTNAMES = True  # reverse-DNS each responding device
    DETECT_OS = True  # infer OS family from ping TTL
    SHOW_VENDOR_INFO = True  # resolve MAC OUI to a vendor name
    USE_MULTITHREADING = True  # parallel scanning

    # ===== DISCOVERY FEATURES =====
    MAP_WIFI_CONNECTIONS = True  # include wireless infrastructure in outputs
    INFER_NETWORK_TOPOLOGY = True  # build the hierarchy/relationship model
    ANALYZE_PROXIMITY = True  # correlate nearby wireless networks against ours

    # ===== ANNOUNCEMENT LISTENING =====
    # Devices broadcast their own identity over mDNS and SSDP. Reading those is
    # quieter and far more informative than probing: a ping proves an address
    # answers, an mDNS record names the model.
    PASSIVE_DISCOVERY = True
    DISCOVERY_DURATION = 12.0  # seconds to listen
    # Solicit rather than only listen. Required in practice on Windows: the
    # host firewall drops unsolicited inbound UDP to 5353/1900, so pure passive
    # listening returns nothing. Queries are link-local (TTL 1) and cannot
    # leave the subnet.
    DISCOVERY_SOLICIT = True

    # ===== WATCHLIST =====
    USE_WATCHLIST = True  # flag devices worth being able to account for

    # ===== SERVICE PROBING (TCP connect) =====
    # Probe devices for open management ports. More intrusive than anything
    # else here, restricted to our own networks unless explicitly permitted,
    # and off by default.
    IDENTIFY_SILENT = False

    # How many ports a probe touches. Each step up is louder and slower.
    #
    #   quick         10 ports  the most diagnostic handful
    #   standard      16 ports  the original fixed table (unchanged behaviour)
    #   deep         315 ports  well-known + embedded / NVR / NAS / printer
    #   full        1270 ports  every privileged port plus common high ports
    #   exhaustive 65535 ports  every TCP port
    #
    # Tiers are cumulative — each is a superset of the one above it, so
    # raising the depth can only find more, never a different set.
    #
    # "exhaustive" is unmistakably a port scan in any firewall log and takes
    # minutes per host, so it requires --i-have-permission the same way
    # --scope wide does.
    PROBE_DEPTH = "standard"

    # Read what a service volunteers on connect (SSH version string, HTTP
    # Server header, RTSP greeting). Far better identification than a bare
    # open/closed list. Off by default because it is a second round trip and,
    # on HTTP ports only, sends one minimal HEAD request — see
    # ServiceProbe.read_banner for exactly what goes on the wire.
    PROBE_BANNERS = False

    # Which devices a probe touches:
    #   silent        announced no service at all  (default; today's behaviour)
    #   unidentified  silent, or still typed unknown/generic
    #   new           not present in the change-detection baseline
    #   all           every device in scope
    PROBE_SELECT = "silent"

    # Restrict probing to these networks. Accepts CIDRs and the symbolic names
    # attached / routed / known / new / all. Empty means every network the
    # scan enumerated.
    PROBE_NETS: List[str] = []

    # Explicit probe targets: IP, CIDR, 192.168.2.10-40, or
    # 192.168.2.10-192.168.2.40. Non-empty means the probe goes straight at
    # these instead of selecting from discovered devices.
    PROBE_TARGETS: List[str] = []

    PROBE_CONNECT_TIMEOUT = 1.0  # seconds to wait for a TCP handshake
    PROBE_BANNER_TIMEOUT = 1.5   # seconds to wait for a service to greet us
    PROBE_MAX_SOCKETS = 128      # concurrent connects in flight, all hosts

# ==================== SECURITY ENHANCEMENTS ====================
class SecurityValidator:
    """
    INPUT VALIDATION AND SECURITY CHECKS
    
    This class provides methods to validate and sanitize all inputs
    to prevent security vulnerabilities like command injection.
    
    CRITICAL SECURITY:
    - All user inputs pass through these validators
    - Shell commands are sanitized before execution
    - Network addresses are validated before use
    """
    
    @staticmethod
    def validate_ip_address(ip: str) -> bool:
        """
        Validate IP address format and range.
        
        Args:
            ip: IP address string to validate
            
        Returns:
            True if valid, False otherwise
            
        SECURITY: Prevents using malformed or dangerous IP addresses
        """
        try:
            # Check if it's a valid IP using Python's ipaddress module
            ip_obj = ipaddress.ip_address(ip)
            
            # Skip problematic addresses if configured (privacy feature)
            if Config.SKIP_MULTICAST_IPS:
                if ip_obj.is_multicast or ip_obj.is_link_local:
                    return False
                    
            # Skip loopback addresses (127.0.0.1, etc.)
            if ip_obj.is_loopback:
                return False
                
            return True
        except ValueError:
            return False  # Not a valid IP address
    
    @staticmethod
    def validate_mac_address(mac: str) -> bool:
        """
        Validate MAC address format using regex.
        
        Args:
            mac: MAC address string
            
        Returns:
            True if valid format, False otherwise
        """
        # Standard MAC address patterns: 00:11:22:33:44:55 or 00-11-22-33-44-55
        mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
        return bool(mac_pattern.match(mac))
    
    @staticmethod
    def sanitize_command_input(input_str: str) -> str:
        """
        Sanitize input for shell commands to prevent injection attacks.
        
        Args:
            input_str: Raw input string
            
        Returns:
            Sanitized string with dangerous characters removed
            
        SECURITY CRITICAL: This prevents command injection vulnerabilities
        """
        if not Config.VALIDATE_COMMAND_INPUTS:
            return input_str  # Only if validation is disabled (not recommended)
            
        # Remove potentially dangerous shell characters
        dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '{', '}', '[', ']', '<', '>', '!', '\n', '\r']
        for char in dangerous_chars:
            input_str = input_str.replace(char, '')
        return input_str.strip()

class RateLimiter:
    """
    RATE LIMITER TO PREVENT NETWORK FLOODING
    
    This class ensures that scans don't overwhelm the network
    by adding delays between probes.
    
    IMPORTANT FOR:
    - Avoiding network congestion
    - Preventing detection by intrusion detection systems
    - Being respectful to network resources
    """
    def __init__(self):
        self.next_slot = 0.0  # monotonic timestamp of the next free probe slot
        self.lock = threading.Lock()  # Thread-safe operations

    def wait_if_needed(self):
        """
        Pace probe launches to at most one per RATE_LIMIT_DELAY seconds.

        The lock is held only long enough to CLAIM a time slot; the sleep
        happens outside it. Holding the lock across the sleep (the previous
        behaviour) serialised the whole thread pool, so 50 workers performed
        exactly like 1. Now each worker reserves a distinct slot and then
        waits for its own, which paces the aggregate probe rate without
        destroying parallelism.
        """
        if not Config.RATE_LIMIT_SCANS or Config.RATE_LIMIT_DELAY <= 0:
            return  # Rate limiting disabled

        interval = Config.RATE_LIMIT_DELAY
        with self.lock:
            now = time.monotonic()
            slot = max(now, self.next_slot)
            self.next_slot = slot + interval

        delay = slot - time.monotonic()
        if delay > 0:
            time.sleep(delay)

class LegalDisclaimer:
    """
    LEGAL AND ETHICAL GUIDELINES DISPLAY
    
    This class ensures users understand the legal implications
    of network scanning and promotes ethical usage.
    """
    
    @staticmethod
    def display_warning(skip=False):
        """
        Display legal warning if enabled.
        
        Args:
            skip: If True, skip the warning (not recommended)
            
        Returns:
            True if user consents, False otherwise
        """
        if skip and not Config.LEGAL_WARNING_REQUIRED:
            return True
        
        warning_text = """
        ⚠️  LEGAL NOTICE: Network Scanning Tool
        
        This tool scans networks for mapping and visualization purposes.
        
        IMPORTANT: Only scan networks you own or have explicit permission to scan.
        Unauthorized scanning may be illegal in your jurisdiction.
        
        By using this tool, you acknowledge that:
        1. You have permission to scan the target network
        2. You understand local laws regarding network scanning
        3. You accept responsibility for proper use
        
        Continue? (yes/no): """
        
        print(warning_text)
        response = input().strip().lower()
        return response in ['yes', 'y', '']
    
    @staticmethod
    def show_ethical_guidelines():
        """
        Display ethical usage tips.
        
        These guidelines help users understand responsible
        network scanning practices.
        """
        if not Config.SHOW_ETHICAL_GUIDELINES:
            return
            
        guidelines = """
        📋 ETHICAL USAGE GUIDELINES:
        
        1. Scan only networks you own or have explicit permission to scan
        2. Respect network policies and terms of service
        3. Use during off-hours for production networks
        4. Be transparent about scanning activities
        5. Secure generated files (they contain sensitive info)
        6. Delete scans when no longer needed
        
        """
        print(guidelines)

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

        search = [Path(__file__).parent]
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
                    parts = line.split(",") if "," in line else line.split(None, 1)
                    if len(parts) >= 3 and len(parts[1]) == 6:
                        oui, name = parts[1], parts[2].strip().strip('"')
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

# ==================== LOCAL NETWORK ENUMERATION ====================
@dataclass
class SweepTarget:
    """
    One network queued for an active sweep, with the reason it qualified.

    `origin` is what keeps the report truthful. The old code produced a flat
    list of subnet prefixes with no record of where each came from, so a range
    invented by adding 1 to an octet was indistinguishable in the output from
    the network the machine was actually plugged into.

      attached — this host holds an address on it. Ours.
      routed   — the routing table has a real route to it. Probably ours.
      adjacent — exploratory guess next to an attached network. NOT ours.
      declared — the operator listed it in EXTRA_SUBNETS. Ours by assertion.
    """
    cidr: str
    origin: str
    interface: Optional['NetworkInterface'] = None
    next_hop: str = ""

    @property
    def is_ours(self) -> bool:
        """Whether responders here may be folded into our own topology."""
        return self.origin in ("attached", "declared", "routed")

    @property
    def ownership(self) -> str:
        return "ours" if self.is_ours else "nearby"


@dataclass
class NetworkInterface:
    """
    A network this host is genuinely attached to.

    Every field here comes from the operating system's own adapter and routing
    tables. Nothing in this class is inferred from IP arithmetic.
    """
    alias: str  # adapter name, e.g. "Ethernet"
    description: str = ""  # hardware description
    ip: str = ""
    prefix_length: int = 0
    mac: str = ""
    gateway: str = ""  # next hop for the default route on this interface, if any
    kind: str = "physical"  # physical | virtual | vpn | linklocal | loopback
    status: str = ""

    @property
    def network(self) -> str:
        """CIDR of the attached network, e.g. '192.168.2.0/24'."""
        if not self.ip or not self.prefix_length:
            return ""
        try:
            return str(ipaddress.ip_network(f"{self.ip}/{self.prefix_length}", strict=False))
        except ValueError:
            return ""

    @property
    def host_count(self) -> int:
        """Number of usable host addresses in this network."""
        if not self.network:
            return 0
        try:
            net = ipaddress.ip_network(self.network)
            return max(0, net.num_addresses - 2) if net.prefixlen < 31 else net.num_addresses
        except ValueError:
            return 0

    @property
    def is_sweepable(self) -> bool:
        """
        Whether an active sweep of this network makes sense.

        Excludes link-local (APIPA) ranges, loopback, and single-host prefixes
        such as a /32 overlay address, none of which describe a LAN worth
        probing. Virtual and VPN adapters are gated by their own Config flags.
        """
        if self.kind in ("linklocal", "loopback"):
            return False
        if not self.network or self.prefix_length >= 31:
            return False
        if self.kind == "virtual" and not Config.SCAN_VIRTUAL_ADAPTERS:
            return False
        if self.kind == "vpn" and not Config.SCAN_VPN_ADAPTERS:
            return False
        return True


class LocalNetworkEnumerator:
    """
    DISCOVER THE NETWORKS THIS HOST IS ACTUALLY ON

    This replaces the old discover_subnets(), which built a candidate list by
    taking the local IP, adding and subtracting from the third octet, and
    appending 192.168.1/2/3 as fallbacks. That approach asserted ownership of
    ranges belonging to whoever happened to be next door, while missing every
    network that did not fit the 192.168.x /24 shape: overlays, Hyper-V and WSL
    host networks, and anything on a prefix other than /24.

    Everything below is read from the OS. If a network is not in the adapter or
    routing table, it is not treated as ours.
    """

    # Adapter name/description fragments that identify non-physical networks.
    VIRTUAL_HINTS = ("vethernet", "hyper-v", "vmware", "virtualbox", "vbox",
                     "virtual adapter", "docker", "default switch", "loopback")
    VPN_HINTS = ("tailscale", "wireguard", "wintun", "openvpn", "tap-windows",
                 "zerotier", "nordlynx", "expressvpn", "proton", "anyconnect",
                 "globalprotect", "vpn")

    @staticmethod
    def _run_powershell(script: str, timeout: int = 20) -> str:
        """Run a PowerShell snippet and return stdout. Returns '' on any failure."""
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                shell=False, capture_output=True, text=True,
                timeout=timeout, encoding="utf-8", errors="replace",
            )
            return result.stdout or ""
        except Exception:
            return ""

    @staticmethod
    def _json(script: str, timeout: int = 20) -> List[dict]:
        """Run PowerShell that emits JSON and return it as a list of dicts."""
        raw = LocalNetworkEnumerator._run_powershell(script, timeout=timeout).strip()
        if not raw:
            return []
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return []
        if isinstance(data, dict):
            return [data]
        return [d for d in data if isinstance(d, dict)]

    @classmethod
    def _classify(cls, alias: str, description: str, ip: str, prefix: int) -> str:
        """Decide what sort of network an adapter represents."""
        blob = f"{alias} {description}".lower()
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_loopback:
                return "loopback"
            if addr.is_link_local:  # 169.254.0.0/16 APIPA: adapter has no real network
                return "linklocal"
        except ValueError:
            pass
        if any(h in blob for h in cls.VPN_HINTS):
            return "vpn"
        if any(h in blob for h in cls.VIRTUAL_HINTS):
            return "virtual"
        # A /32 on a non-loopback adapter is an overlay host address
        if prefix == 32:
            return "vpn"
        return "physical"

    @classmethod
    def enumerate_windows(cls) -> List[NetworkInterface]:
        """Enumerate interfaces via Get-NetIPAddress / Get-NetAdapter / Get-NetRoute."""
        addrs = cls._json(
            "@(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
            "Select-Object IPAddress,PrefixLength,InterfaceIndex,InterfaceAlias) | "
            "ConvertTo-Json -Compress"
        )
        if not addrs:
            return []

        adapters = {}
        for a in cls._json(
            "@(Get-NetAdapter -ErrorAction SilentlyContinue | "
            "Select-Object ifIndex,Name,InterfaceDescription,MacAddress,Status) | "
            "ConvertTo-Json -Compress"
        ):
            if a.get("ifIndex") is not None:
                adapters[a["ifIndex"]] = a

        gateways = {}
        for r in cls._json(
            "@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' "
            "-ErrorAction SilentlyContinue | Select-Object InterfaceIndex,NextHop) | "
            "ConvertTo-Json -Compress"
        ):
            idx, hop = r.get("InterfaceIndex"), r.get("NextHop")
            if idx is not None and hop and hop != "0.0.0.0":
                gateways[idx] = hop

        interfaces = []
        for a in addrs:
            ip = a.get("IPAddress", "")
            prefix = a.get("PrefixLength") or 0
            idx = a.get("InterfaceIndex")
            alias = a.get("InterfaceAlias", "") or ""
            if not ip:
                continue
            try:
                if ipaddress.ip_address(ip).is_loopback:
                    continue
            except ValueError:
                continue

            meta = adapters.get(idx, {})
            description = meta.get("InterfaceDescription", "") or ""
            interfaces.append(NetworkInterface(
                alias=alias or meta.get("Name", "") or f"if{idx}",
                description=description,
                ip=ip,
                prefix_length=int(prefix),
                mac=VendorDatabase.normalize(meta.get("MacAddress", "") or ""),
                gateway=gateways.get(idx, ""),
                kind=cls._classify(alias, description, ip, int(prefix)),
                status=meta.get("Status", "") or "",
            ))
        return interfaces

    @classmethod
    def enumerate_posix(cls) -> List[NetworkInterface]:
        """Enumerate interfaces via `ip -o -4 addr` and `ip route` on Linux/macOS."""
        interfaces = []
        out = SecureNetworkScanner.run_cmd("ip -o -4 addr show")
        default_hop, default_dev = "", ""
        route_out = SecureNetworkScanner.run_cmd("ip route show default")
        m = re.search(r"default\s+via\s+(\S+)\s+dev\s+(\S+)", route_out)
        if m:
            default_hop, default_dev = m.group(1), m.group(2)

        for line in out.splitlines():
            m = re.search(r"^\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
            if not m:
                continue
            dev, ip, prefix = m.group(1), m.group(2), int(m.group(3))
            try:
                if ipaddress.ip_address(ip).is_loopback:
                    continue
            except ValueError:
                continue
            interfaces.append(NetworkInterface(
                alias=dev,
                ip=ip,
                prefix_length=prefix,
                gateway=default_hop if dev == default_dev else "",
                kind=cls._classify(dev, "", ip, prefix),
            ))
        return interfaces

    @classmethod
    def enumerate(cls) -> List[NetworkInterface]:
        """Enumerate every IPv4 network this host is attached to."""
        if sys.platform.startswith("win"):
            interfaces = cls.enumerate_windows()
            if interfaces:
                return interfaces
            return cls._enumerate_windows_fallback()
        return cls.enumerate_posix()

    @classmethod
    def _enumerate_windows_fallback(cls) -> List[NetworkInterface]:
        """
        Parse `ipconfig` when the Get-Net* cmdlets are unavailable.

        Less precise than the cmdlets (no MAC, no adapter description) but it
        still reports real addresses and real masks, which is the point.
        """
        interfaces = []
        out = SecureNetworkScanner.run_cmd("ipconfig")
        alias, ip, mask, gw = "", "", "", ""

        def flush():
            if not ip or not mask:
                return
            try:
                prefix = ipaddress.ip_network(f"0.0.0.0/{mask}").prefixlen
            except ValueError:
                return
            try:
                if ipaddress.ip_address(ip).is_loopback:
                    return
            except ValueError:
                return
            interfaces.append(NetworkInterface(
                alias=alias or "unknown",
                ip=ip, prefix_length=prefix, gateway=gw,
                kind=cls._classify(alias, "", ip, prefix),
            ))

        for line in out.splitlines():
            stripped = line.strip()
            if stripped.endswith(":") and not line.startswith(" "):
                flush()
                alias, ip, mask, gw = stripped.rstrip(":"), "", "", ""
                for prefix_word in ("Ethernet adapter ", "Wireless LAN adapter ",
                                    "Unknown adapter ", "PPP adapter "):
                    if alias.startswith(prefix_word):
                        alias = alias[len(prefix_word):]
                        break
            elif "IPv4 Address" in stripped:
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)", stripped)
                if m:
                    ip = m.group(1)
            elif "Subnet Mask" in stripped:
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)", stripped)
                if m:
                    mask = m.group(1)
            elif "Default Gateway" in stripped:
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)", stripped)
                if m:
                    gw = m.group(1)
        flush()
        return interfaces

    @classmethod
    def routed_networks(cls) -> List[Tuple[str, str]]:
        """
        Networks the routing table says are reachable but that we hold no
        interface address on: other VLANs, segments behind a second router,
        anything a static route points at.

        Returns a list of (cidr, next_hop).

        Excluded: the default route (it means "everywhere", not a network),
        link-local, multicast, loopback and broadcast destinations, and on-link
        routes. An on-link route carries next hop 0.0.0.0 and simply restates a
        network we already hold an interface on — including them re-admitted the
        Hyper-V and WSL ranges that is_sweepable had deliberately excluded, and
        put 8,000 dead virtual addresses into the sweep. A "routed" network here
        means one genuinely reachable *through a router*.
        """
        out = []
        if not sys.platform.startswith("win"):
            route_out = SecureNetworkScanner.run_cmd("ip route show")
            for line in route_out.splitlines():
                m = re.match(r"^(\d+\.\d+\.\d+\.\d+/\d+)\s+via\s+(\S+)", line.strip())
                if m:
                    out.append((m.group(1), m.group(2)))
            return out

        for r in cls._json(
            "@(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
            "Select-Object DestinationPrefix,NextHop) | ConvertTo-Json -Compress"
        ):
            dest = (r.get("DestinationPrefix") or "").strip()
            hop = (r.get("NextHop") or "").strip()
            if not dest or dest == "0.0.0.0/0":
                continue
            try:
                net = ipaddress.ip_network(dest, strict=False)
            except ValueError:
                continue
            if (net.is_multicast or net.is_loopback or net.is_link_local
                    or net.network_address.is_unspecified):
                continue
            if net.prefixlen >= 31:  # host route or point-to-point, not a network
                continue
            if not hop or hop == "0.0.0.0":  # on-link: an attached network, not a routed one
                continue
            out.append((str(net), hop))
        return out

    @classmethod
    def adjacent_networks(cls, interfaces: List[NetworkInterface]) -> List[str]:
        """
        The /24s immediately either side of each attached network.

        This is exploratory: unlike the old discover_subnets() these are NOT
        presented as ours, and they are only swept when SCAN_SCOPE is "wide".
        Anything that answers gets labelled 'nearby', not 'ours'.
        """
        out = []
        for iface in interfaces:
            if iface.kind != "physical" or not iface.network:
                continue
            try:
                net = ipaddress.ip_network(iface.network)
            except ValueError:
                continue
            if net.prefixlen != 24:
                continue
            octets = str(net.network_address).split(".")
            third = int(octets[2])
            for offset in (-1, 1):
                nxt = third + offset
                if 0 <= nxt <= 255:
                    out.append(f"{octets[0]}.{octets[1]}.{nxt}.0/24")
        return out

    @classmethod
    def sweep_targets(cls, interfaces: List[NetworkInterface]) -> List['SweepTarget']:
        """
        Build the list of networks eligible for an active sweep, honouring
        Config.SCAN_SCOPE.

        Each target carries an `origin` explaining why it is in the list, so the
        report can distinguish a network we are attached to from one we reached
        by route or by exploration. Networks larger than MAX_SWEEP_HOSTS are
        skipped with a warning rather than silently truncated.
        """
        scope = (Config.SCAN_SCOPE or "routed").lower()
        targets: List['SweepTarget'] = []
        seen: Set[str] = set()

        def add(cidr: str, origin: str, iface: Optional[NetworkInterface] = None,
                next_hop: str = "") -> bool:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                print(f"    ! Ignoring malformed network: {cidr}")
                return False
            key = str(net)
            if key in seen:
                return False
            hosts = max(0, net.num_addresses - 2)
            if hosts > Config.MAX_SWEEP_HOSTS:
                print(f"    ! Skipping {key} ({origin}): {hosts} hosts exceeds "
                      f"MAX_SWEEP_HOSTS ({Config.MAX_SWEEP_HOSTS})")
                return False
            seen.add(key)
            targets.append(SweepTarget(cidr=key, origin=origin,
                                       interface=iface, next_hop=next_hop))
            return True

        # 1. Networks we hold an address on
        for iface in interfaces:
            if iface.network and iface.is_sweepable:
                add(iface.network, "attached", iface)

        # 2. Networks reachable by a real route
        if scope in ("routed", "wide"):
            for cidr, hop in cls.routed_networks():
                add(cidr, "routed", None, hop)

        # 3. Exploratory adjacent ranges
        if scope == "wide":
            for cidr in cls.adjacent_networks(interfaces):
                add(cidr, "adjacent")

        # 4. Explicitly declared extras always apply
        for raw in Config.EXTRA_SUBNETS:
            add(raw, "declared")

        return targets


# ==================== SECURE NETWORK SCANNER ====================
class SecureNetworkScanner:
    """
    ENHANCED NETWORK SCANNER WITH SECURITY IMPROVEMENTS
    
    This is the main scanning engine that discovers devices on the network.
    It includes multiple scanning techniques with security controls.
    
    SCANNING METHODS:
    1. ARP scanning (fast, local subnet only)
    2. Ping scanning (broader, across multiple subnets)
    3. Parallel execution for speed (with controlled threading)
    
    SECURITY FEATURES:
    - Rate limiting between probes
    - Input validation for all network addresses
    - Thread-safe operations
    - Command injection prevention
    """
    
    def __init__(self, on_progress=None, on_log=None, should_stop=None, wait_if_paused=None):
        """
        Args:
            on_progress:    callable(stage: str, done: int, total: int)
            on_log:         callable(message: str)
            should_stop:    callable() -> bool, polled between probes
            wait_if_paused: callable(), blocks while the scan is paused

        These four hooks are first-class so a front end can drive progress,
        pausing and cancellation without monkey-patching the scanner's methods
        from outside, which is how the FastAPI build had to do it.
        """
        self.scan_lock = threading.Lock()  # For thread-safe operations
        self.devices_found = []  # List of discovered devices
        self.subnets_detected = defaultdict(list)  # Devices grouped by subnet
        self.gateways = []  # Discovered gateway devices
        self.wifi_aps = []  # Discovered WiFi access points
        self.rate_limiter = RateLimiter()  # Rate limiting controller
        self.validator = SecurityValidator()  # Input validation
        self.interfaces: List['NetworkInterface'] = []
        self.sweep_targets: List['SweepTarget'] = []
        self._own_addresses: Set[str] = set()  # every IP bound to this host

        self.on_progress = on_progress or (lambda stage, done, total: None)
        self.on_log = on_log or (lambda message: print(message))
        self.should_stop = should_stop or (lambda: False)
        self.wait_if_paused = wait_if_paused or (lambda: None)
    
    @staticmethod
    def run_cmd(cmd: str, timeout: int = 10) -> str:
        """
        Execute shell command safely with input validation.
        
        Args:
            cmd: Command string to execute
            timeout: Maximum execution time in seconds
            
        Returns:
            Command output as string
            
        SECURITY: Uses shlex.split() to safely parse command strings
        and prevent shell injection attacks.
        """
        try:
            # Use shlex to safely split command string (prevents injection)
            args = shlex.split(cmd)
            result = subprocess.run(args, shell=False, capture_output=True, 
                                  text=True, timeout=timeout, encoding='utf-8', errors='ignore')
            return result.stdout
        except Exception as e:
            return f"Command execution failed: {str(e)}"
    
    @staticmethod
    def safe_ping_command(ip: str) -> str:
        """
        Build a safe ping command with input validation.
        
        Args:
            ip: IP address to ping
            
        Returns:
            Safe ping command string or empty string if invalid
            
        SECURITY: Validates IP before using in command to prevent injection.
        """
        # Validate IP before using in command
        if not SecurityValidator.validate_ip_address(ip):
            return ""
            
        # Sanitize IP for command injection prevention
        safe_ip = SecurityValidator.sanitize_command_input(ip)
        
        # Build platform-specific command
        if sys.platform.startswith('win'):
            return f"ping -n 1 -w {Config.SCAN_TIMEOUT * 1000} {safe_ip}"
        else:
            return f"ping -c 1 -W {Config.SCAN_TIMEOUT} {safe_ip}"
    
    @staticmethod
    def get_local_ip() -> str:
        """Get local IP address of this machine."""
        try:
            # Connect to Google DNS to determine local interface IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"  # Fallback to localhost
    
    @staticmethod
    def get_default_gateways(interfaces: Optional[List['NetworkInterface']] = None) -> Set[str]:
        """
        Return the set of real default-gateway addresses from the routing table.

        The previous get_default_gateway() fell back to "local IP with .1 on the
        end", and ultimately to a hardcoded 192.168.1.1, so it always returned
        something that looked plausible whether or not it existed. This returns
        only next hops the OS actually reports, and an empty set if there are
        none.
        """
        if interfaces is None:
            interfaces = LocalNetworkEnumerator.enumerate()
        return {i.gateway for i in interfaces if i.gateway}
    
    def detect_subnets(self, devices: List[NetworkDevice]) -> Dict[str, List[NetworkDevice]]:
        """
        Group devices by their subnet.
        
        Args:
            devices: List of network devices
            
        Returns:
            Dictionary mapping subnets to devices
        """
        subnets = defaultdict(list)
        for device in devices:
            if device.subnet:
                subnets[device.subnet].append(device)
        return subnets
    
    def infer_network_topology(self, devices: List[NetworkDevice]) -> Dict[str, Any]:
        """
        Infer network hierarchy and relationships.
        
        Analyzes devices to understand network structure:
        - Identifies gateways and subnets
        - Maps WiFi networks and clients
        - Builds connection relationships
        
        Args:
            devices: List of discovered devices
            
        Returns:
            Topology dictionary with gateways, subnets, and connections
        """
        topology = {
            'gateways': [],  # List of gateway IPs
            'subnets': {},   # Devices grouped by subnet
            'wifi_networks': {},  # WiFi APs and their clients
            'connections': []  # Network connections
        }
        
        # Identify gateways (routers)
        for device in devices:
            if device.is_gateway:
                topology['gateways'].append(device.ip)
        
        # Group devices by subnet
        topology['subnets'] = self.detect_subnets(devices)
        
        # Identify WiFi APs and associate clients
        wifi_aps = [d for d in devices if d.is_wifi_ap]
        for ap in wifi_aps:
            # Find potential clients (devices on same subnet without wires)
            clients = []
            for device in devices:
                if (device.subnet == ap.subnet and 
                    not device.is_gateway and 
                    device.ip != ap.ip and
                    'wired' not in device.tags):  # Not tagged as wired
                    clients.append(device.ip)
            
            topology['wifi_networks'][ap.ip] = {
                'ssid': ap.hostname,
                'clients': clients,
                'vendor': ap.vendor
            }
        
        return topology
    
    def scan_neighbors(self, interfaces: List['NetworkInterface']) -> List[NetworkDevice]:
        """
        Read the OS neighbour (ARP/ND) table.

        Prefers Get-NetNeighbor on Windows, which reports the owning interface
        and a reachability state (Reachable / Stale / Probe). `arp -a` provides
        neither, so the old parser could not tell which adapter a neighbour was
        seen on, nor whether the entry was live or a stale leftover.

        Falls back to `arp -a` where the cmdlet is unavailable.
        """
        gateways = {i.gateway for i in interfaces if i.gateway}
        by_alias = {i.alias: i for i in interfaces}
        devices = []
        seen = set()

        rows = []
        if sys.platform.startswith("win"):
            # State is an enum; ConvertTo-Json renders it as a bare integer, so
            # stringify it in PowerShell rather than hardcoding the numeric map.
            rows = LocalNetworkEnumerator._json(
                "@(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
                "Select-Object IPAddress,LinkLayerAddress,InterfaceAlias,"
                "@{n='State';e={[string]$_.State}}) | ConvertTo-Json -Compress"
            )

        if rows:
            for r in rows:
                ip = (r.get("IPAddress") or "").strip()
                mac = VendorDatabase.normalize(r.get("LinkLayerAddress") or "")
                state = (r.get("State") or "").strip()
                alias = (r.get("InterfaceAlias") or "").strip()
                if not ip or len(mac) != 17:
                    continue
                if state in ("Unreachable", "Incomplete"):
                    continue
                dev = self._make_neighbor_device(ip, mac, alias, state,
                                                 gateways, by_alias, seen)
                if dev:
                    devices.append(dev)
        else:
            output = self.run_cmd("arp -a")
            patterns = [
                r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:-]{17})",          # Windows
                r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:-]{17})",  # Linux/macOS
            ]
            for line in output.splitlines():
                for pattern in patterns:
                    match = re.search(pattern, line)
                    if not match:
                        continue
                    ip, mac = match.groups()
                    mac = VendorDatabase.normalize(mac)
                    if len(mac) != 17:
                        break
                    dev = self._make_neighbor_device(ip, mac, "", "",
                                                     gateways, by_alias, seen)
                    if dev:
                        devices.append(dev)
                    break

        return devices

    def _make_neighbor_device(self, ip: str, mac: str, alias: str, state: str,
                              gateways: Set[str], by_alias: Dict[str, 'NetworkInterface'],
                              seen: Set[str]) -> Optional[NetworkDevice]:
        """Build a NetworkDevice from one neighbour-table row, or None to skip it."""
        if ip in seen:
            return None

        # Structural exclusions. These are not devices: they are the protocol's
        # own reserved addresses, and including them inflated every device count
        # the old dashboard printed.
        try:
            addr = ipaddress.IPv4Address(ip)
            if addr.is_multicast or addr.is_loopback or addr.is_unspecified:
                return None
        except ValueError:
            return None
        if VendorDatabase.is_broadcast(mac) or VendorDatabase.is_multicast(mac):
            return None
        if Config.SKIP_MULTICAST_IPS and addr.is_link_local:
            return None

        iface = by_alias.get(alias)
        # Only claim a device is on one of our networks if its address actually
        # falls inside that network.
        if iface and iface.network:
            try:
                if addr not in ipaddress.ip_network(iface.network):
                    iface = None
            except ValueError:
                iface = None

        seen.add(ip)
        device = NetworkDevice(ip=ip, mac=mac, network_type="lan",
                               interface=alias, neighbor_state=state)
        if iface:
            device.assign_subnet(iface.prefix_length)
            if iface.kind in ("virtual", "vpn"):
                device.tags.add(iface.kind)

        if ip in gateways:
            device.is_default_gateway = True
            device.device_type = "router"
            device.tags.add("gateway")

        return device
    
    def ping_single(self, ip: str) -> Optional[NetworkDevice]:
        """
        Ping a single IP with rate limiting (thread-safe).
        
        Args:
            ip: IP address to ping
            
        Returns:
            NetworkDevice if responsive, None otherwise
            
        SECURITY: Uses rate limiting to prevent network flooding.
        """
        # Cooperative cancellation. Returning None rather than raising matters:
        # ThreadPoolExecutor captures exceptions per-future, so raising here
        # would let every remaining thread run its full ping timeout while the
        # pool drained. Returning immediately makes a stop feel instant.
        if self.should_stop():
            return None
        self.wait_if_paused()
        if self.should_stop():
            return None

        # Apply rate limiting (wait between probes)
        self.rate_limiter.wait_if_needed()

        # Skip our own addresses
        if ip in self._own_addresses:
            return None


        # Build safe ping command with validation
        cmd = self.safe_ping_command(ip)
        if not cmd:
            return None
            
        result = self.run_cmd(cmd, timeout=Config.SCAN_TIMEOUT + 1)
        upper = result.upper()

        # A live host is one that returned a TTL. Nothing else counts.
        #
        # The previous test was `"TTL=" in result or "Reply from" in result`,
        # but on Windows an address with no host behind it produces:
        #     Reply from 192.168.2.31: Destination host unreachable.
        # — a reply from OUR OWN adapter reporting failure, which contains the
        # substring "Reply from". Every dead address therefore registered as a
        # device: a 50-address sample of this network reported 46 responders.
        # ICMP error replies carry no TTL field, so requiring TTL rejects them.
        if "TTL=" not in upper:
            return None
        # Belt and braces: some localised builds do emit a TTL alongside an
        # error string, so reject the known failure phrasings explicitly.
        if "UNREACHABLE" in upper or "REQUEST TIMED OUT" in upper or "100% LOSS" in upper:
            return None

        ttl_match = re.search(r'TTL=(\d+)', upper)
        ttl = int(ttl_match.group(1)) if ttl_match else 0

        device = NetworkDevice(ip=ip, network_type="lan", ttl=ttl)

        # Round-trip time, when the platform reports it.
        rtt = re.search(r'TIME[=<](\d+)\s*MS', upper)
        if rtt:
            device.response_time = float(rtt.group(1))

        # Infer OS from TTL value (different OSes use different default TTLs)
        if Config.DETECT_OS and ttl > 0:
            if ttl <= 64:
                device.os_family = "linux/unix"
            elif ttl <= 128:
                device.os_family = "windows"
            else:
                device.os_family = "cisco/router"

        return device
    
    def scan_ping_parallel(self, ip_list: List[str]) -> List[NetworkDevice]:
        """
        Parallel ping scanning with validation.
        
        Uses thread pool to ping multiple IPs simultaneously
        while maintaining rate limiting and validation.
        
        Args:
            ip_list: List of IP addresses to scan
            
        Returns:
            List of responsive devices
        """
        devices = []

        # Filter IPs through validation.
        #
        # The previous version appended `ip` inside the valid branch AND again
        # unconditionally at the bottom of the loop, so every valid address was
        # queued twice and every invalid one was queued anyway. That doubled the
        # probe count and made the validator a no-op. One decision, one append.
        valid_ips = []
        for ip in ip_list:
            if self.validator.validate_ip_address(ip):
                valid_ips.append(ip)

        total = len(valid_ips)
        done = 0
        self.on_progress("ping", 0, total)

        # Choose scanning method based on configuration
        if not Config.USE_MULTITHREADING:
            # Fallback to sequential scanning (slower but simpler)
            for ip in valid_ips:
                if self.should_stop():
                    break
                device = self.ping_single(ip)
                done += 1
                self.on_progress("ping", done, total)
                if device:
                    devices.append(device)
        else:
            # Use thread pool for parallel scanning (faster)
            with concurrent.futures.ThreadPoolExecutor(max_workers=Config.SCAN_THREADS) as executor:
                # Submit all ping tasks
                future_to_ip = {executor.submit(self.ping_single, ip): ip for ip in valid_ips}

                # Collect results as they complete
                for future in concurrent.futures.as_completed(future_to_ip):
                    try:
                        device = future.result()
                        if device:
                            with self.scan_lock:  # Thread-safe append
                                devices.append(device)
                    except Exception:
                        pass  # Silently handle individual ping failures
                    done += 1
                    self.on_progress("ping", done, total)

        return devices
    
    def our_known_macs(self, devices: List[NetworkDevice]) -> Set[str]:
        """
        Every hardware address we have grounds to call ours: this host's own
        adapters, plus each device found on a network we are attached to.

        This is the evidence set handed to the wireless classifier. Passing only
        the gateway (an earlier version) meant a device of ours that also runs
        its own access point — a printer's WiFi-Direct AP, a phone hotspot —
        was reported as a foreign network sitting next to us. On this machine
        that mislabelled the OfficeJet at 192.168.2.20, whose broadcast BSSID
        F4:30:B9:42:D0:EC differs from its wired MAC by one octet.
        """
        macs = {i.mac for i in self.interfaces if i.mac}
        for d in devices:
            if d.mac and d.ownership == "ours":
                macs.add(d.mac)
        return macs

    @staticmethod
    def _classify_ownership(ip: str, attached_nets: List[str]) -> str:
        """
        'ours' if the address falls inside a network this host is attached to,
        otherwise 'nearby'. Deliberately evidence-based: proximity, a similar
        looking address, or being one octet away does not make something ours.
        """
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return "unknown"
        for net in attached_nets:
            try:
                if addr in ipaddress.ip_network(net):
                    return "ours"
            except ValueError:
                continue
        return "nearby"

    def hosts_in(self, cidr: str) -> List[str]:
        """
        Every usable host address in a network.

        The old scan_subnet() took a dotted prefix like "192.168.1." and walked
        1..254, which only ever worked for a /24 and stopped early once
        MAX_PING_SCAN addresses had been produced. This enumerates the real
        network object, so a /23 or /25 sweeps correctly and nothing is
        truncated part-way through.
        """
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return []
        return [str(h) for h in net.hosts()]
    
    def scan_lan_enhanced(self) -> List[NetworkDevice]:
        """
        Enhanced LAN scanning with security improvements.
        
        Main scanning method that combines multiple techniques:
        1. ARP scanning (fast, local)
        2. Ping scanning (broader, parallel)
        3. Device enrichment (hostnames, vendors, types)
        
        Returns:
            Comprehensive list of discovered devices
        """
        self.on_log("  🔍 Scanning networks this host is attached to...")

        # 1. Enumerate the networks we are genuinely on. Nothing is guessed.
        self.on_progress("enumerate", 0, 1)
        self.interfaces = LocalNetworkEnumerator.enumerate()
        self._own_addresses = {i.ip for i in self.interfaces if i.ip}
        self.sweep_targets = LocalNetworkEnumerator.sweep_targets(self.interfaces)

        for iface in self.interfaces:
            net = iface.network or "(no network)"
            mark = "sweep" if iface.is_sweepable else "observe only"
            self.on_log(f"    • {iface.alias}: {iface.ip}/{iface.prefix_length} "
                        f"[{iface.kind}] {net} -> {mark}")
        for tgt in self.sweep_targets:
            self.on_log(f"    → target {tgt.cidr} [{tgt.origin}/{tgt.ownership}]")
        if not self.sweep_targets:
            self.on_log("    ! No sweepable networks found. Nothing will be probed.")
        self.on_progress("enumerate", 1, 1)

        devices = []

        # 2. Neighbour table (fast, passive, covers every interface at once)
        self.on_log("    Reading neighbour table...")
        self.on_progress("neighbors", 0, 1)
        neighbor_devices = self.scan_neighbors(self.interfaces)
        devices.extend(neighbor_devices)
        self.on_progress("neighbors", 1, 1)
        self.on_log(f"      Found {len(neighbor_devices)} devices in the neighbour table")

        # Label neighbour-table finds: anything sitting inside a network we hold
        # an address on is ours, anything else we simply do not claim.
        attached_nets = [i.network for i in self.interfaces if i.network]
        for device in devices:
            device.discovered_via = "neighbor"
            device.ownership = self._classify_ownership(device.ip, attached_nets)

        # 3. Active sweep. Reach is deliberately broad (see Config.SCAN_SCOPE);
        # what stays narrow is what we probe WITH. The sweep is ICMP echo and
        # nothing else — TCP probing is a separate, opt-in phase run later by
        # ServiceProbe (see Config.PROBE_DEPTH).
        if self.sweep_targets and not self.should_stop():
            all_ips = []
            for tgt in self.sweep_targets:
                all_ips.extend(self.hosts_in(tgt.cidr))

            existing_ips = {d.ip for d in devices}
            all_ips = [ip for ip in all_ips
                       if ip not in existing_ips and ip not in self._own_addresses]

            if all_ips:
                nets = ", ".join(f"{t.cidr}[{t.ownership}]" for t in self.sweep_targets)
                self.on_log(f"    Sweeping {len(all_ips)} addresses across {nets}...")
                self.on_log("    Sweep method: ICMP echo (reachability only)")
                ping_devices = self.scan_ping_parallel(all_ips)

                # Attribute each responder to the target network it fell in
                for device in ping_devices:
                    device.discovered_via = "sweep"
                    for tgt in self.sweep_targets:
                        try:
                            net = ipaddress.ip_network(tgt.cidr)
                            if ipaddress.ip_address(device.ip) in net:
                                device.assign_subnet(net.prefixlen)
                                device.origin = tgt.origin
                                device.ownership = tgt.ownership
                                if tgt.interface:
                                    device.interface = tgt.interface.alias
                                break
                        except ValueError:
                            continue

                devices.extend(ping_devices)
                ours = sum(1 for d in ping_devices if d.ownership == "ours")
                nearby = len(ping_devices) - ours
                self.on_log(f"      Found {len(ping_devices)} additional devices via sweep "
                            f"({ours} on our networks, {nearby} nearby)")

        # 4. Mark real gateways from the routing table
        gateways = self.get_default_gateways(self.interfaces)
        for device in devices:
            if device.ip in gateways:
                device.is_default_gateway = True
                device.device_type = "router"
                device.tags.add("gateway")

        # 5. Enrich devices with additional information
        self.on_log("    Enriching device information...")
        total = len(devices)
        for idx, device in enumerate(devices, 1):
            if self.should_stop():
                break
            self.wait_if_paused()

            # Get hostname via DNS reverse lookup
            if Config.RESOLVE_HOSTNAMES and not device.hostname:
                try:
                    device.hostname = socket.gethostbyaddr(device.ip)[0]
                except Exception:
                    pass  # No hostname resolvable

            # Get vendor from MAC address
            if Config.SHOW_VENDOR_INFO and device.mac:
                device.vendor = VendorDatabase.lookup(device.mac)

            # Infer device type based on various characteristics
            self._infer_device_type(device)
            self.on_progress("enrich", idx, total)

        # 6. Associate devices with the gateway serving their network
        if Config.INFER_NETWORK_TOPOLOGY:
            self.on_log("    Inferring network topology...")
            by_subnet = defaultdict(list)
            for device in devices:
                if device.subnet:
                    by_subnet[device.subnet].append(device)
            for subnet, subnet_devices in by_subnet.items():
                subnet_gateways = [d for d in subnet_devices if d.is_gateway]
                if not subnet_gateways:
                    continue
                for device in subnet_devices:
                    if not device.is_gateway:
                        device.gateway = subnet_gateways[0].ip

        return devices
    
    def _infer_device_type(self, device: NetworkDevice):
        """
        Enhanced device type inference.
        
        Uses vendor information, IP patterns, and other
        characteristics to categorize devices.
        
        Args:
            device: Device to categorize
        """
        # Check for gateway devices first
        if device.is_gateway:
            device.device_type = "router"
            device.tags.add("gateway")
        elif device.is_virtual:
            device.device_type = "virtual"
            device.tags.add("virtual")
        elif device.vendor:
            vendor_lower = device.vendor.lower()
            if any(x in vendor_lower for x in ['apple', 'iphone', 'ipad', 'macbook']):
                device.device_type = "apple"
                device.tags.add("wireless")  # Most Apple devices are wireless
            elif any(x in vendor_lower for x in ['samsung', 'galaxy']):
                device.device_type = "samsung"
                device.tags.add("wireless")
            elif any(x in vendor_lower for x in ['google', 'pixel']):
                device.device_type = "google"
                device.tags.add("wireless")
            elif any(x in vendor_lower for x in ['raspberry', 'pi']):
                device.device_type = "raspberry_pi"
            elif any(x in vendor_lower for x in ['philips', 'hue', 'nest', 'ring', 'arlo']):
                device.device_type = "iot"
                device.tags.add("wireless")
            elif any(x in vendor_lower for x in ['cisco', 'ubiquiti', 'netgear', 'tp-link', 'd-link']):
                device.device_type = "network"
            elif any(x in vendor_lower for x in ['dell', 'hp', 'lenovo', 'microsoft']):
                device.device_type = "computer"
            else:
                device.device_type = "generic"
        else:
            device.device_type = "unknown"
        
        # Check for wired devices (servers, NAS, etc.)
        if device.device_type in ['computer', 'server', 'network', 'printer']:
            if 'wireless' not in device.tags:
                device.tags.add("wired")

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

# ==================== ENHANCED DIAGRAM GENERATOR ====================
class EnhancedDiagramGenerator:
    """
    GENERATE HIERARCHICAL NETWORK DIAGRAMS
    
    Creates draw.io (diagrams.net) compatible XML files that
    visualize the network topology in an interactive diagram.
    
    KEY FEATURES:
    - Hierarchical layout (Internet -> Gateway -> Subnets -> Devices)
    - Color coding by subnet
    - Device icons based on type
    - WiFi network visualization
    - Security notices in the diagram
    """
    
    @staticmethod
    def generate_hierarchical_diagram(lan_devices: List[NetworkDevice], 
                                      wifi_devices: List[NetworkDevice],
                                      topology: Dict[str, Any]) -> str:
        """
        Generate hierarchical network diagram with deduplication.
        
        Args:
            lan_devices: List of LAN devices
            wifi_devices: List of WiFi networks
            topology: Network topology information
            
        Returns:
            draw.io XML string for the diagram
            
        FIX APPLIED: Uses modulo arithmetic to handle any number of subnets
        without IndexError by arranging them in a grid.
        """
        timestamp = datetime.now().isoformat()
        
        # ===== STEP 1: GROUP DEVICES BY SUBNET AND REMOVE DUPLICATES =====
        subnets = defaultdict(list)
        seen_ips = set()
        unique_lan_devices = []
        
        for device in lan_devices:
            if device.ip and device.ip not in seen_ips:
                seen_ips.add(device.ip)
                unique_lan_devices.append(device)
                if device.subnet:
                    subnets[device.subnet].append(device)
        
        # ===== STEP 2: REMOVE DUPLICATE WiFi DEVICES =====
        seen_wifi_keys = set()
        unique_wifi_devices = []
        for wifi in wifi_devices:
            wifi_key = f"{wifi.mac}_{wifi.hostname}"
            if wifi_key not in seen_wifi_keys:
                seen_wifi_keys.add(wifi_key)
                unique_wifi_devices.append(wifi)
        
        total_devices = len(unique_lan_devices)
        
        # ===== STEP 3: BUILD XML DOCUMENT =====
        xml_parts = []
        
        # XML Header with metadata
        xml_parts.append(f'''<?xml version="1.0" encoding="UTF-8"?>
<mxfile host="app.diagrams.net" modified="{timestamp}" agent="SecureNetworkMapper" version="21.6.5">
  <diagram name="Secure Network Map - {total_devices} Devices" id="secure_network_map">
    <mxGraphModel dx="2800" dy="2200" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="2800" pageHeight="2200">
      <root>
        <mxCell id="0"/>
        <mxCell id="1" parent="0"/>''')
        
        # ===== STEP 4: DIAGRAM TITLE WITH SECURITY NOTE =====
        xml_parts.append(f'''
        <!-- Title -->
        <mxCell id="title" value="🔒 SECURE NETWORK MAP\\n{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}\\n{total_devices} Devices • {len(unique_wifi_devices)} WiFi Networks • {len(subnets)} Subnets\\n⚠️ Contains sensitive information - Secure this file" 
                style="text;html=1;strokeColor=none;fillColor=none;align=center;verticalAlign=middle;whiteSpace=wrap;rounded=0;fontSize=24;fontStyle=1;fontColor=#3b82f6;" 
                vertex="1" parent="1">
          <mxGeometry x="800" y="50" width="1200" height="100" as="geometry"/>
        </mxCell>''')
        
        # ===== STEP 5: INTERNET SYMBOL =====
        xml_parts.append('''
        <!-- Internet -->
        <mxCell id="internet" value="🌐 INTERNET" 
                style="shape=cloud;whiteSpace=wrap;html=1;fontSize=24;fillColor=#1e293b;strokeColor=#3b82f6;fontColor=#ffffff;gradientColor=#0f172a;" 
                vertex="1" parent="1">
          <mxGeometry x="1200" y="200" width="200" height="120" as="geometry"/>
        </mxCell>''')
        
        # ===== STEP 6: MAIN GATEWAY/ROUTER =====
        main_gateway = None
        for device in unique_lan_devices:
            if device.is_gateway and device.ip.endswith('.1'):
                main_gateway = device
                break
        
        # Fallback gateway if none detected
        if not main_gateway:
            main_gateway = NetworkDevice(ip="192.168.2.1", device_type="router", hostname="Main Gateway")
        
        cell_id = 2
        xml_parts.append(f'''
        <!-- Main Gateway -->
        <mxCell id="{cell_id}" value="🏠 {main_gateway.hostname or main_gateway.ip}\\nMain Network Gateway" 
                style="shape=mxgraph.cisco.routers.router;html=1;whiteSpace=wrap;fontSize=20;fillColor=#1e40af;strokeColor=#1e3a8a;fontColor=#ffffff;gradientDirection=north;gradientColor=#1e3a8a;" 
                vertex="1" parent="1">
          <mxGeometry x="1150" y="350" width="300" height="180" as="geometry"/>
        </mxCell>''')
        
        gateway_id = cell_id
        cell_id += 1
        
        # ===== STEP 7: INTERNET TO GATEWAY CONNECTION =====
        xml_parts.append(f'''
        <mxCell id="{cell_id}" value="WAN Connection" 
                style="endArrow=classic;html=1;rounded=0;strokeColor=#3b82f6;strokeWidth=4;dashed=0;fontSize=16;fontColor=#3b82f6;" 
                edge="1" parent="1" source="internet" target="{gateway_id}">
          <mxGeometry relative="1" as="geometry"/>
        </mxCell>''')
        cell_id += 1
        
        # ===== STEP 8: SUBNET VISUALIZATION =====
        # Color coding for different subnets
        subnet_colors = {
            '192.168.1.0/24': '#10b981',  # Green
            '192.168.2.0/24': '#3b82f6',  # Blue
            '192.168.3.0/24': '#8b5cf6',  # Purple
        }
        
        # Define 3 column positions for subnet containers
        subnet_x_positions = [300, 1100, 1900]  # Three columns
        subnet_y_start = 600  # Starting Y position
        
        # Diagram-wide ID registry. draw.io silently drops cells that reuse an
        # id, so uniqueness has to hold across the whole document, not within
        # one subnet. The previous per-subnet set combined with a per-AP client
        # index meant the same client drawn under two access points produced two
        # cells with identical ids, and one of them vanished on open.
        used_ids: Set[str] = set()

        def create_safe_id(raw: str, prefix: str = "device") -> str:
            """Allocate a document-unique, XML-safe cell id."""
            safe = re.sub(r'[^A-Za-z0-9_]', '_', raw)
            candidate = f"{prefix}_{safe}"
            if candidate not in used_ids:
                used_ids.add(candidate)
                return candidate
            counter = 1
            while f"{candidate}_{counter}" in used_ids:
                counter += 1
            candidate = f"{candidate}_{counter}"
            used_ids.add(candidate)
            return candidate
        
        # Convert subnets to list for processing. Ours first, then nearby, so
        # the reader's own network is at the top of the page.
        def _subnet_sort_key(item):
            _sub, devs = item
            is_ours = any(getattr(d, 'ownership', 'ours') == 'ours' for d in devs)
            return (0 if is_ours else 1, -len(devs))

        subnet_list = sorted(subnets.items(), key=_subnet_sort_key)

        # Precompute each subnet's box height so containers fit their contents.
        # Every subnet found is drawn: an earlier version stopped at 24 and cut
        # each one to 9 devices, producing a diagram that looked complete while
        # omitting both networks and hosts.
        # Boxes grow when there are open ports to show, rather than letting a
        # fourth line of label overflow a box sized for three.
        any_ports = any(d.ports_open for d in unique_lan_devices)
        device_width, device_height, devices_per_row = 220, (110 if any_ports else 90), 3
        subnet_heights = []
        for _sub, devs in subnet_list:
            drawn = max(1, sum(1 for d in devs if not d.is_gateway))
            rows_needed = (drawn + devices_per_row - 1) // devices_per_row
            subnet_heights.append(100 + rows_needed * (device_height + 20) + 40)

        # Row heights: each grid row is as tall as its tallest subnet box.
        row_heights = {}
        for i, h in enumerate(subnet_heights):
            r = i // 3
            row_heights[r] = max(row_heights.get(r, 0), h)
        row_offsets, running = {}, subnet_y_start
        for r in sorted(row_heights):
            row_offsets[r] = running
            running += row_heights[r] + 80

        for idx in range(len(subnet_list)):
            subnet, subnet_devices = subnet_list[idx]

            col = idx % 3
            row = idx // 3

            x_pos = subnet_x_positions[col]
            y_pos = row_offsets[row]
            box_h = subnet_heights[idx]

            # Get color for this subnet (default gray if not in color map)
            color = subnet_colors.get(subnet, '#6b7280')

            owned = any(getattr(d, 'ownership', 'ours') == 'ours' for d in subnet_devices)
            scope_label = "OUR NETWORK" if owned else "NEARBY — not ours"
            if not owned:
                color = '#64748b'

            subnet_container_id = create_safe_id(subnet, prefix="subnet")
            xml_parts.append(f'''
        <!-- Subnet: {subnet} -->
        <mxCell id="{subnet_container_id}" value="📡 {html.escape(subnet)}\\n{scope_label} • {len(subnet_devices)} devices"
                style="rounded=1;whiteSpace=wrap;html=1;verticalAlign=top;fillColor=#1e293b;strokeColor={color};strokeWidth=3;fontSize=18;fontColor={color};"
                vertex="1" parent="1">
          <mxGeometry x="{x_pos}" y="{y_pos}" width="800" height="{box_h}" as="geometry"/>
        </mxCell>''')

            # ===== GATEWAY TO SUBNET CONNECTION =====
            xml_parts.append(f'''
        <mxCell id="{cell_id}" value="LAN" 
                style="endArrow=classic;html=1;rounded=0;strokeColor={color};strokeWidth=3;dashed=1;fontSize=14;fontColor={color};" 
                edge="1" parent="1" source="{gateway_id}" target="{subnet_container_id}">
          <mxGeometry relative="1" as="geometry"/>
        </mxCell>''')
            cell_id += 1
            
            # ===== FIND SUBNET GATEWAY (IF ANY) =====
            subnet_gateway = None
            for device in subnet_devices:
                if device.is_gateway:
                    subnet_gateway = device
                    break
            
            # ===== DEVICES WITHIN SUBNET =====
            device_start_x = x_pos + 50
            device_start_y = y_pos + 100  # Position devices inside subnet container

            # Every device in the subnet is drawn; the container was sized to
            # fit them above. Positions are driven by a separate counter so
            # skipping the gateway does not leave a hole in the grid.
            drawn_idx = 0
            for device in subnet_devices:
                if device.is_gateway:
                    continue  # Already shown as main gateway

                row_pos = drawn_idx // devices_per_row
                col_pos = drawn_idx % devices_per_row
                drawn_idx += 1
                
                x = device_start_x + (col_pos * (device_width + 20))
                y = device_start_y + (row_pos * (device_height + 20))
                
                # Get icon and format label
                icon = EnhancedDiagramGenerator._get_icon_for_device(device)
                device_type = device.device_type.replace('_', ' ').title()
                
                label = f"{icon} {device.hostname or device.ip}\\n{device_type}"
                if device.vendor and device.vendor != "Unknown":
                    label += f"\\n{device.vendor}"

                # Open ports, when a probe found any. Named services read
                # better than bare numbers at diagram scale, and the list is
                # capped so one busy host cannot blow out its box — the full
                # set is always in the dashboard and results.json.
                if device.ports_open:
                    shown = device.ports_open[:5]
                    labels = ", ".join(ServiceProbe.label_for(p) for p in shown)
                    if len(device.ports_open) > len(shown):
                        labels += f" +{len(device.ports_open) - len(shown)}"
                    label += f"\\n🔌 {labels}"

                label_escaped = html.escape(label)
                
                unique_id = create_safe_id(device.ip)

                # ===== DEVICE RECTANGLE =====
                xml_parts.append(f'''
        <!-- Device: {device.ip} -->
        <mxCell id="{unique_id}" value="{label_escaped}" 
                style="shape=rectangle;whiteSpace=wrap;html=1;rounded=1;fontSize=12;fillColor=#1f2937;strokeColor={color};fontColor=#ffffff;" 
                vertex="1" parent="1">
          <mxGeometry x="{x}" y="{y}" width="{device_width}" height="{device_height}" as="geometry"/>
        </mxCell>''')
                
                device_id = unique_id
                
                # ===== CONNECT DEVICE TO SUBNET =====
                target = subnet_container_id  # Default: connect to subnet container
                
                # If this device is the subnet gateway, create special connection
                if subnet_gateway and device.ip == subnet_gateway.ip:
                    subnet_gateway_id = create_safe_id(subnet, prefix="subnet_gateway")
                    xml_parts.append(f'''
        <!-- Subnet Gateway -->
        <mxCell id="{subnet_gateway_id}" value="🔀 Subnet Router" 
                style="shape=mxgraph.cisco.routers.router;html=1;whiteSpace=wrap;fontSize=14;fillColor={color};strokeColor={color};fontColor=#ffffff;" 
                vertex="1" parent="1">
          <mxGeometry x="{x + device_width/2 - 60}" y="{y - 40}" width="120" height="60" as="geometry"/>
        </mxCell>''')
                
                    # Connect main gateway to subnet gateway
                    xml_parts.append(f'''
        <mxCell id="{cell_id}" value="" 
                style="endArrow=none;html=1;rounded=0;strokeColor={color};strokeWidth=2;dashed=1;" 
                edge="1" parent="1" source="{gateway_id}" target="{subnet_gateway_id}">
          <mxGeometry relative="1" as="geometry"/>
        </mxCell>''')
                    cell_id += 1
                
                    # Connect subnet gateway to device
                    target = subnet_gateway_id
                
                # Create connection line
                xml_parts.append(f'''
        <mxCell id="{cell_id}" value="" 
                style="endArrow=none;html=1;rounded=0;strokeColor={color};strokeWidth=1;dashed=1;" 
                edge="1" parent="1" source="{target}" target="{device_id}">
          <mxGeometry relative="1" as="geometry"/>
        </mxCell>''')
                cell_id += 1
        
        # ===== STEP 9: WIRELESS =====
        # Drawn in two clearly separated zones. Networks we can prove are ours
        # hang off our gateway; everything else is placed in an "observed
        # nearby" band with no edge connecting it to our infrastructure.
        #
        # The previous version attached the same wireless LAN devices beneath
        # EVERY visible SSID, so a neighbour's access point was rendered with
        # our laptops and phones drawn as its clients. It also reused cell ids
        # across access points, so draw.io dropped the duplicates on open.
        wifi_networks = topology.get('wifi') or []
        if unique_wifi_devices and Config.MAP_WIFI_CONNECTIONS:
            by_bssid = {n.bssid: n for n in wifi_networks}

            def ownership_of(dev):
                net = by_bssid.get(dev.mac)
                if net is not None:
                    return net.ownership
                return getattr(dev, 'ownership', 'foreign')

            ours_wifi = [w for w in unique_wifi_devices if ownership_of(w) == 'ours']
            near_wifi = [w for w in unique_wifi_devices if ownership_of(w) != 'ours']

            # `running` is the bottom of the last subnet row, computed from the
            # real box heights above rather than a fixed 550px-per-row guess.
            wifi_y = running + 60

            def draw_wifi_band(items, title, title_color, fill, stroke, y_top, attach_to):
                """Draw one wireless band; returns the y coordinate below it."""
                if not items:
                    return y_top
                nonlocal cell_id
                header_id = create_safe_id(title, prefix="wifi_header")
                xml_parts.append(f'''
        <mxCell id="{header_id}" value="{html.escape(title)}"
                style="text;html=1;strokeColor=none;fillColor=none;align=center;verticalAlign=middle;whiteSpace=wrap;rounded=0;fontSize=22;fontStyle=1;fontColor={title_color};"
                vertex="1" parent="1">
          <mxGeometry x="300" y="{y_top}" width="900" height="50" as="geometry"/>
        </mxCell>''')

                cols = 4
                cell_w, cell_h = 340, 130
                row_y = y_top + 70
                for idx, wifi in enumerate(items):
                    col = idx % cols
                    row = idx // cols
                    x = 300 + col * (cell_w + 30)
                    y = row_y + row * (cell_h + 40)

                    net = by_bssid.get(wifi.mac)
                    if net is not None:
                        band = net.band_label
                        detail = f"{net.signal_percent}% • {band} • ch{net.channel}"
                        second = f"{net.authentication or 'unknown auth'}"
                        if net.is_virtual_bssid:
                            second += " • virtual BSSID"
                    else:
                        detail = wifi.device_type.replace('_', ' ')
                        second = wifi.vendor or "Wireless"

                    icon = "📡" if "5" in detail or "6" in detail else "📶"
                    label = (f"{icon} {wifi.hostname}\\n{wifi.mac}\\n"
                             f"{detail}\\n{second}")
                    node_id = create_safe_id(wifi.mac or wifi.hostname, prefix="wifi")
                    xml_parts.append(f'''
        <mxCell id="{node_id}" value="{html.escape(label)}"
                style="shape=ellipse;whiteSpace=wrap;html=1;fontSize=12;fillColor={fill};strokeColor={stroke};fontColor=#ffffff;"
                vertex="1" parent="1">
          <mxGeometry x="{x}" y="{y}" width="{cell_w}" height="{cell_h}" as="geometry"/>
        </mxCell>''')

                    # Only our own access points are wired into our topology.
                    if attach_to:
                        xml_parts.append(f'''
        <mxCell id="{cell_id}" value=""
                style="endArrow=none;html=1;rounded=0;strokeColor={stroke};strokeWidth=2;dashed=1;"
                edge="1" parent="1" source="{attach_to}" target="{node_id}">
          <mxGeometry relative="1" as="geometry"/>
        </mxCell>''')
                        cell_id += 1

                rows_used = (len(items) + cols - 1) // cols
                return row_y + rows_used * (cell_h + 40) + 40

            next_y = draw_wifi_band(
                ours_wifi,
                f"📶 OUR WIRELESS — {len(ours_wifi)} BSSID(s)",
                "#8b5cf6", "#4c1d95", "#8b5cf6", wifi_y, gateway_id,
            )

            if near_wifi:
                note_id = create_safe_id("nearby_note", prefix="wifi_note")
                xml_parts.append(f'''
        <mxCell id="{note_id}" value="Observed passively from beacon frames. Not scanned, not contacted, not ours."
                style="text;html=1;strokeColor=none;fillColor=none;align=center;verticalAlign=middle;whiteSpace=wrap;rounded=0;fontSize=13;fontColor=#94a3b8;"
                vertex="1" parent="1">
          <mxGeometry x="300" y="{next_y + 46}" width="900" height="30" as="geometry"/>
        </mxCell>''')
                draw_wifi_band(
                    near_wifi,
                    f"📡 NEARBY WIRELESS — {len(near_wifi)} BSSID(s), not ours",
                    "#64748b", "#334155", "#64748b", next_y, None,
                )

        # ===== STEP 10: SECURITY NOTICE =====
        xml_parts.append(f'''
        <!-- Security Notice -->
        <mxCell id="security_notice" value="🔒 SECURITY NOTICE\\nThis file contains sensitive network information.\\nEncrypt or secure this file appropriately." 
                style="text;html=1;strokeColor=none;fillColor=none;align=center;verticalAlign=middle;whiteSpace=wrap;rounded=0;fontSize=12;fontStyle=1;fontColor=#ef4444;" 
                vertex="1" parent="1">
          <mxGeometry x="800" y="2000" width="1200" height="50" as="geometry"/>
        </mxCell>''')
        
        # ===== STEP 11: STATISTICS AND LEGEND =====
        xml_parts.append(f'''
        <!-- Statistics -->
        <mxCell id="stats" value="📊 Network Statistics: {len(unique_lan_devices)} Total Devices • {len(subnets)} Subnets • {len(unique_wifi_devices)} WiFi Networks • {sum(1 for d in unique_lan_devices if 'wireless' in d.tags)} Wireless Clients" 
                style="text;html=1;strokeColor=none;fillColor=none;align=center;verticalAlign=middle;whiteSpace=wrap;rounded=0;fontSize=14;fontColor=#9ca3af" 
                vertex="1" parent="1">
          <mxGeometry x="800" y="2050" width="1200" height="30" as="geometry"/>
        </mxCell>''')
        
        # ===== STEP 12: CLOSE XML DOCUMENT =====
        xml_parts.append('''      </root>
    </mxGraphModel>
  </diagram>
</mxfile>''')
        
        return '\n'.join(xml_parts)
    
    @staticmethod
    def _get_icon_for_device(device: NetworkDevice) -> str:
        """
        Get appropriate emoji icon for device type.
        
        Args:
            device: Network device
            
        Returns:
            Emoji icon string
        """
        device_type = device.device_type.lower()
        
        icon_map = {
            "router": "🏠",
            "gateway": "🏠",
            "computer": "💻",
            "server": "🖥️",
            "virtual": "☁️",
            "iot": "🏠",
            "apple": "🍎",
            "samsung": "📱",
            "google": "📱",
            "raspberry_pi": "🍓",
            "network": "🔌",
            "printer": "🖨️",
            "camera": "📹",
            "phone": "📱",
            "tablet": "📱",
            "tv": "📺",
            "gaming": "🎮",
            "wired": "🔌",
            "wireless": "📶",
        }
        
        return icon_map.get(device_type, "💻")  # Default icon

# ==================== PASSIVE ANNOUNCEMENT LISTENING ====================
class PassiveDiscovery:
    """
    Learn what devices are by listening to what they already broadcast.

    Consumer devices announce themselves continuously over multicast — mDNS
    (Bonjour) on 224.0.0.251:5353 and SSDP (UPnP) on 239.255.255.250:1900 —
    publishing hostnames, model names and the services they offer. Joining
    those groups and reading is entirely receive-only: no packet is sent, and
    nothing on the network can tell we are listening.

    This yields identification a ping sweep never can. A ping proves an address
    answers; an mDNS record says "HP OfficeJet Pro 8710, _ipp._tcp, here is my
    model number". It is both quieter and more informative than probing.

    An optional active mode sends one mDNS service-enumeration query and one
    SSDP M-SEARCH. Those are link-local multicasts that never leave the subnet
    and are indistinguishable from what every phone on the network emits
    constantly — but they are transmissions, so they are off by default and
    restricted to networks we are attached to.
    """

    MDNS_GROUP, MDNS_PORT = "224.0.0.251", 5353
    SSDP_GROUP, SSDP_PORT = "239.255.255.250", 1900

    # Service types worth translating into something a person can read.
    SERVICE_HINTS = {
        "_ipp": "printer", "_ipps": "printer", "_printer": "printer",
        "_pdl-datastream": "printer", "_scanner": "scanner", "_uscan": "scanner",
        "_airplay": "airplay", "_raop": "airplay-audio",
        "_googlecast": "chromecast", "_spotify-connect": "speaker",
        "_sonos": "sonos", "_hap": "homekit", "_matter": "matter",
        "_homekit": "homekit", "_esphomelib": "esphome",
        "_smb": "file-share", "_afpovertcp": "file-share", "_nfs": "file-share",
        "_ssh": "ssh", "_sftp-ssh": "ssh", "_rfb": "vnc", "_rdp": "rdp",
        "_http": "web-ui", "_https": "web-ui", "_workstation": "workstation",
        "_device-info": "device-info", "_companion-link": "apple-device",
        "_touch-able": "apple-device", "_sleep-proxy": "apple-device",
        "_axis-video": "camera", "_onvif": "camera", "_rtsp": "camera",
        "_dahua": "camera", "_hikvision": "camera",
    }

    @staticmethod
    def _decode_name(data: bytes, offset: int, depth: int = 0):
        """
        Decode a DNS name, following compression pointers.

        Returns (name, next_offset). Depth-limited because a malformed or
        hostile packet can point a label back at itself, and this parser runs
        against unauthenticated input from the network.
        """
        labels = []
        jumped = False
        next_offset = offset
        while depth < 12:
            if offset >= len(data):
                break
            length = data[offset]
            if length == 0:
                offset += 1
                if not jumped:
                    next_offset = offset
                break
            if length & 0xC0 == 0xC0:  # compression pointer
                if offset + 1 >= len(data):
                    break
                pointer = ((length & 0x3F) << 8) | data[offset + 1]
                if not jumped:
                    next_offset = offset + 2
                    jumped = True
                if pointer >= len(data) or pointer == offset:
                    break
                offset = pointer
                depth += 1
                continue
            offset += 1
            labels.append(data[offset:offset + length].decode("utf-8", "replace"))
            offset += length
            if not jumped:
                next_offset = offset
        return ".".join(labels), next_offset

    @staticmethod
    def _parse_mdns(data: bytes) -> Dict[str, Any]:
        """Pull names, service types and A-record addresses out of an mDNS packet."""
        out = {"names": set(), "services": set(), "addresses": set(), "types": set()}
        if len(data) < 12:
            return out
        try:
            qd, an, ns, ar = (int.from_bytes(data[i:i + 2], "big") for i in (4, 6, 8, 10))
            offset = 12
            for _ in range(min(qd, 64)):
                name, offset = PassiveDiscovery._decode_name(data, offset)
                offset += 4
                PassiveDiscovery._classify_name(name, out)
            for _ in range(min(an + ns + ar, 128)):
                if offset >= len(data):
                    break
                name, offset = PassiveDiscovery._decode_name(data, offset)
                if offset + 10 > len(data):
                    break
                rtype = int.from_bytes(data[offset:offset + 2], "big")
                rdlen = int.from_bytes(data[offset + 8:offset + 10], "big")
                offset += 10
                rdata = data[offset:offset + rdlen]
                PassiveDiscovery._classify_name(name, out)
                if rtype == 1 and rdlen == 4:  # A record
                    out["addresses"].add(".".join(str(b) for b in rdata))
                elif rtype in (12, 33):  # PTR / SRV -> another name
                    target, _ = PassiveDiscovery._decode_name(
                        data, offset + (6 if rtype == 33 else 0))
                    PassiveDiscovery._classify_name(target, out)
                offset += rdlen
        except (IndexError, ValueError):
            pass
        return out

    @staticmethod
    def _classify_name(name: str, out: Dict[str, Any]):
        """Split an mDNS name into a device name and/or a service hint."""
        if not name or not name.endswith(".local") and ".local" not in name:
            if not name.startswith("_"):
                return
        low = name.lower()
        for key, label in PassiveDiscovery.SERVICE_HINTS.items():
            if low.startswith(key + ".") or f".{key}." in low:
                out["services"].add(label)

        # A bare service type such as "_ipp._tcp.local" is the answer to the
        # service-enumeration meta-query. Record it so a follow-up round can ask
        # who actually offers it — that second answer carries the device name.
        if low.startswith("_") and low.endswith(".local") and "types" in out:
            parts = low[: -len(".local")].rstrip(".").split(".")
            if len(parts) == 2 and parts[1] in ("_tcp", "_udp"):
                out["types"].add(f"{parts[0]}.{parts[1]}.local")
        if low.endswith(".local") and not low.startswith("_"):
            host = name[: -len(".local")].rstrip(".")
            # Instance names look like "Office Printer._ipp._tcp"; keep the head.
            if "._" in host:
                host = host.split("._")[0]
            if host and not host.startswith("_"):
                out["names"].add(host)

    @staticmethod
    def _parse_ssdp(text: str) -> Dict[str, Any]:
        """Pull the useful headers out of an SSDP NOTIFY / M-SEARCH response."""
        out = {"server": "", "model": "", "services": set(), "location": ""}
        for line in text.splitlines():
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            key, value = key.strip().lower(), value.strip()
            if key == "server":
                out["server"] = value
            elif key == "location":
                out["location"] = value
            elif key in ("st", "nt"):
                v = value.lower()
                if "mediarenderer" in v or "mediaserver" in v:
                    out["services"].add("dlna")
                elif "internetgatewaydevice" in v:
                    out["services"].add("gateway")
                elif "printer" in v:
                    out["services"].add("printer")
                elif "basic" in v or "rootdevice" in v:
                    out["services"].add("upnp")
        return out

    @staticmethod
    def collect(interfaces: List['NetworkInterface'], duration: float = 12.0,
                active: bool = False, on_log=None,
                should_stop=None) -> Dict[str, Dict[str, Any]]:
        """
        Listen for announcements and return {ip: {names, services, server}}.

        Args:
            duration: seconds to listen. Devices re-announce on their own
                      schedule, so longer windows find more.
            active:   also emit one mDNS query and one SSDP M-SEARCH. Link-local
                      only; still a transmission, so opt-in.
        """
        on_log = on_log or (lambda m: None)
        should_stop = should_stop or (lambda: False)
        found: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {"names": set(), "services": set(), "server": "", "via": set()}
        )

        local_ips = [i.ip for i in interfaces if i.is_sweepable and i.ip]
        if not local_ips:
            local_ips = [i.ip for i in interfaces
                         if i.kind == "physical" and i.ip]
        if not local_ips:
            on_log("    No suitable interface for multicast listening")
            return {}

        socks = []

        # Path 1: join the groups and wait for unsolicited announcements. Purely
        # receive-only, but a host firewall that drops unsolicited inbound UDP
        # will silently deliver nothing here — which is exactly what happens on
        # a default Windows configuration.
        for group, port, label in (
            (PassiveDiscovery.MDNS_GROUP, PassiveDiscovery.MDNS_PORT, "mdns"),
            (PassiveDiscovery.SSDP_GROUP, PassiveDiscovery.SSDP_PORT, "ssdp"),
        ):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("", port))
                for ip in local_ips:
                    try:
                        mreq = socket.inet_aton(group) + socket.inet_aton(ip)
                        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                    except OSError:
                        continue  # interface may not support multicast
                s.setblocking(False)
                socks.append((s, label))
            except OSError as exc:
                on_log(f"    Could not listen on {group}:{port} ({exc})")

        # Path 2: solicit. Replies arrive on the querying socket as return
        # traffic, which the firewall permits.
        if active:
            socks += PassiveDiscovery._solicit(local_ips, on_log)

        if not socks:
            return {}

        service_types: Set[str] = set()
        follow_up_done = not active  # only chase instances when soliciting

        deadline = time.monotonic() + duration
        # Chase service instances partway through the window, once the
        # enumeration answers have had a moment to arrive.
        follow_up_at = time.monotonic() + min(4.0, duration / 3)
        try:
            import select
            while time.monotonic() < deadline and not should_stop():
                if not follow_up_done and time.monotonic() >= follow_up_at:
                    follow_up_done = True
                    socks += PassiveDiscovery._solicit_types(
                        local_ips, sorted(service_types), on_log)

                ready, _, _ = select.select([s for s, _ in socks], [], [], 0.5)
                for s in ready:
                    try:
                        data, addr = s.recvfrom(9000)
                    except OSError:
                        continue
                    ip = addr[0]
                    kind = next((k for so, k in socks if so is s), "")
                    if kind == "mdns":
                        parsed = PassiveDiscovery._parse_mdns(data)
                        entry = found[ip]
                        entry["names"] |= parsed["names"]
                        entry["services"] |= parsed["services"]
                        entry["via"].add("mDNS")
                        service_types |= parsed.get("types", set())
                        for a in parsed["addresses"]:
                            if a != ip:
                                found[a]["names"] |= parsed["names"]
                                found[a]["services"] |= parsed["services"]
                                found[a]["via"].add("mDNS")
                    else:
                        text = data.decode("utf-8", "replace")
                        parsed = PassiveDiscovery._parse_ssdp(text)
                        entry = found[ip]
                        entry["services"] |= parsed["services"]
                        entry["via"].add("SSDP")
                        if parsed["server"] and not entry["server"]:
                            entry["server"] = parsed["server"]
        finally:
            for s, _ in socks:
                try:
                    s.close()
                except OSError:
                    pass

        return {ip: v for ip, v in found.items() if v["names"] or v["services"] or v["server"]}

    @staticmethod
    def _mdns_query_for(qname: str, unicast_response: bool = True) -> bytes:
        """Build an mDNS PTR query for an arbitrary name."""
        pkt = bytearray(b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        for label in qname.rstrip(".").split("."):
            pkt.append(len(label))
            pkt += label.encode()
        pkt += b"\x00\x00\x0c"
        pkt += b"\x80\x01" if unicast_response else b"\x00\x01"
        return bytes(pkt)

    @staticmethod
    def _mdns_query(unicast_response: bool = True) -> bytes:
        """
        Build an mDNS PTR query for _services._dns-sd._udp.local.

        With unicast_response set, the QU bit (top bit of QCLASS) asks
        responders to answer directly to our source port rather than to the
        multicast group. That matters on a firewalled host: a unicast reply to
        an outbound flow is permitted, whereas unsolicited multicast to
        224.0.0.251:5353 is dropped before it reaches us.
        """
        pkt = bytearray(b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        for label in ("_services", "_dns-sd", "_udp", "local"):
            pkt.append(len(label))
            pkt += label.encode()
        pkt += b"\x00"                     # end of name
        pkt += b"\x00\x0c"                 # QTYPE = PTR
        pkt += b"\x80\x01" if unicast_response else b"\x00\x01"  # QU|IN or IN
        return bytes(pkt)

    SSDP_MSEARCH = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 2\r\n"
        "ST: ssdp:all\r\n\r\n"
    ).encode()

    @staticmethod
    def _solicit(local_ips: List[str], on_log) -> List[Tuple[socket.socket, str]]:
        """
        Send link-local queries and return the sockets to read the answers on.

        Replies must be read from the socket that sent the query. A stateful
        firewall permits return traffic for an outbound flow, which is why this
        path works where joining the multicast group and waiting does not.
        Both queries carry TTL 1 and therefore cannot leave the subnet.
        """
        socks = []
        for ip in local_ips:
            for payload, group, port, label in (
                (PassiveDiscovery._mdns_query(), PassiveDiscovery.MDNS_GROUP,
                 PassiveDiscovery.MDNS_PORT, "mdns"),
                (PassiveDiscovery.SSDP_MSEARCH, PassiveDiscovery.SSDP_GROUP,
                 PassiveDiscovery.SSDP_PORT, "ssdp"),
            ):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    s.bind((ip, 0))  # ephemeral port; replies come back here
                    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                                 socket.inet_aton(ip))
                    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
                    s.sendto(payload, (group, port))
                    s.setblocking(False)
                    socks.append((s, label))
                except OSError:
                    continue
        if socks:
            on_log("    Sent link-local mDNS + SSDP queries (TTL 1 — cannot leave "
                   "the subnet); listening for replies")
        return socks

    @staticmethod
    def _solicit_types(local_ips: List[str], types: List[str],
                       on_log) -> List[Tuple[socket.socket, str]]:
        """
        Ask who offers each discovered service type.

        The enumeration query returns types ("_ipp._tcp.local"); this asks for
        instances, and instance names are what carry a human-readable device
        name such as "HP OfficeJet Pro 8710 [F4D0EB]". Capped so a network
        advertising many service types cannot turn this into a flood.
        """
        if not types:
            return []
        socks = []
        for ip in local_ips[:2]:
            for qname in types[:24]:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    s.bind((ip, 0))
                    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                                 socket.inet_aton(ip))
                    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
                    s.sendto(PassiveDiscovery._mdns_query_for(qname),
                             (PassiveDiscovery.MDNS_GROUP, PassiveDiscovery.MDNS_PORT))
                    s.setblocking(False)
                    socks.append((s, "mdns"))
                except OSError:
                    continue
        if socks:
            on_log(f"    Resolving {min(len(types), 24)} service type(s) to instances")
        return socks

    @staticmethod
    def apply(devices: List[NetworkDevice],
              discovered: Dict[str, Dict[str, Any]]) -> int:
        """Merge announcement data onto matching devices. Returns devices enriched."""
        by_ip = {d.ip: d for d in devices}
        enriched = 0
        for ip, info in discovered.items():
            dev = by_ip.get(ip)
            if not dev:
                continue
            changed = False
            if not dev.hostname and info["names"]:
                dev.hostname = sorted(info["names"])[0]
                changed = True
            for svc in info["services"]:
                if svc not in dev.services:
                    dev.services.append(svc)
                    changed = True
            for source in info["via"]:
                dev.tags.add(f"announces-{source.lower()}")
            if info.get("server"):
                dev.tags.add("upnp")
            # Service types identify a device better than a MAC prefix — but a
            # service is something a device OFFERS, not what it IS. A desktop
            # sharing a printer advertises _ipp._tcp, and an earlier version
            # therefore relabelled this very workstation as a printer. Markers
            # of a general-purpose host outrank any single service.
            svcs = info["services"]
            general_purpose = {"workstation", "ssh", "rdp", "file-share",
                               "apple-device", "device-info"} & svcs
            if "camera" in svcs:
                dev.device_type = "camera"
                changed = True
            elif dev.device_type in ("unknown", "generic"):
                if {"printer", "scanner"} & svcs and not general_purpose:
                    dev.device_type = "printer"
                    changed = True
                elif {"chromecast", "airplay", "sonos", "speaker"} & svcs \
                        and not general_purpose:
                    dev.device_type = "media"
                    changed = True
                elif general_purpose:
                    dev.device_type = "computer"
                    changed = True
            if changed:
                enriched += 1
        return enriched


# ==================== WS-DISCOVERY (ONVIF DEVICES) ====================
class WSDiscovery:
    """
    Find ONVIF devices — cameras, NVRs, encoders — via WS-Discovery.

    Cameras generally ignore mDNS and SSDP and speak WS-Discovery on
    239.255.255.250:3702 instead, which is why the Hikvision on this network
    was the one device that answered neither. A WS-Discovery Probe is a SOAP
    message sent to that multicast group; conforming devices reply with their
    service address and a Scopes list that usually carries the model name
    outright, e.g.

        onvif://www.onvif.org/name/HIKVISION%20DS-2CD2042WD-I
        onvif://www.onvif.org/hardware/DS-2CD2042WD-I

    That is a far better answer to "what is this thing" than a MAC prefix, and
    it comes from the device describing itself rather than us inferring.

    Like the mDNS/SSDP queries this is link-local (TTL 1) and confined to the
    subnet. It is restricted to networks we are attached to.
    """

    GROUP, PORT = "239.255.255.250", 3702

    PROBE = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
        'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
        'xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
        '<e:Header>'
        '<w:MessageID>uuid:{uuid}</w:MessageID>'
        '<w:To e:mustUnderstand="true">'
        'urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>'
        '<w:Action e:mustUnderstand="true">'
        'http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>'
        '</e:Header>'
        '<e:Body><d:Probe><d:Types>{types}</d:Types></d:Probe></e:Body>'
        '</e:Envelope>'
    )

    # Probed in order. The empty type is a match-all Probe: some firmware only
    # answers a bare request and ignores a typed one, so asking for a specific
    # type alone can make a device look absent when it is simply fussy.
    PROBE_TYPES = ("dn:NetworkVideoTransmitter", "d:Device", "")

    @staticmethod
    def _probe_packet(types: str, seq: int) -> bytes:
        # MessageID must be unique per probe but need not be random — a counter
        # keeps this reproducible, which matters because Math/random-free
        # determinism makes test runs comparable.
        stamp = f"{int(time.time()):08x}-0000-4000-8000-{seq:012x}"
        return WSDiscovery.PROBE.format(uuid=stamp, types=types).encode("utf-8")

    @staticmethod
    def _parse(text: str) -> Dict[str, Any]:
        """Extract XAddrs, Types and Scopes from a ProbeMatch."""
        out = {"xaddrs": [], "types": [], "scopes": [], "name": "",
               "hardware": "", "location": ""}

        def grab(tag):
            m = re.search(rf"<[^>]*\b{tag}\b[^>]*>(.*?)</[^>]*{tag}>",
                          text, re.S | re.I)
            return m.group(1).strip() if m else ""

        out["xaddrs"] = grab("XAddrs").split()
        out["types"] = grab("Types").split()
        scopes = grab("Scopes").split()
        out["scopes"] = scopes
        for scope in scopes:
            low = scope.lower()
            value = urllib.parse.unquote(scope.rsplit("/", 1)[-1]) if "/" in scope else ""
            if "/name/" in low and not out["name"]:
                out["name"] = value
            elif "/hardware/" in low and not out["hardware"]:
                out["hardware"] = value
            elif "/location/" in low and not out["location"]:
                out["location"] = value
        return out

    @staticmethod
    def probe(interfaces: List['NetworkInterface'], duration: float = 6.0,
              on_log=None, should_stop=None) -> Dict[str, Dict[str, Any]]:
        """Send WS-Discovery probes and collect replies, keyed by source IP."""
        on_log = on_log or (lambda m: None)
        should_stop = should_stop or (lambda: False)

        local_ips = [i.ip for i in interfaces if i.is_sweepable and i.ip]
        if not local_ips:
            return {}

        socks = []
        seq = 0
        for ip in local_ips:
            for types in WSDiscovery.PROBE_TYPES:
                seq += 1
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    s.bind((ip, 0))
                    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                                 socket.inet_aton(ip))
                    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
                    s.sendto(WSDiscovery._probe_packet(types, seq),
                             (WSDiscovery.GROUP, WSDiscovery.PORT))
                    s.setblocking(False)
                    socks.append(s)
                except OSError:
                    continue

        if not socks:
            return {}
        on_log("    Sent WS-Discovery probes (TTL 1) for ONVIF devices")

        found: Dict[str, Dict[str, Any]] = {}
        deadline = time.monotonic() + duration
        try:
            import select
            while time.monotonic() < deadline and not should_stop():
                ready, _, _ = select.select(socks, [], [], 0.5)
                for s in ready:
                    try:
                        data, addr = s.recvfrom(65535)
                    except OSError:
                        continue
                    parsed = WSDiscovery._parse(data.decode("utf-8", "replace"))
                    if not any(parsed.values()):
                        continue
                    entry = found.setdefault(addr[0], parsed)
                    for key in ("name", "hardware", "location"):
                        if not entry.get(key) and parsed.get(key):
                            entry[key] = parsed[key]
        finally:
            for s in socks:
                try:
                    s.close()
                except OSError:
                    pass
        return found

    @staticmethod
    def apply(devices: List[NetworkDevice],
              discovered: Dict[str, Dict[str, Any]]) -> int:
        """Merge ONVIF results onto matching devices."""
        by_ip = {d.ip: d for d in devices}
        n = 0
        for ip, info in discovered.items():
            dev = by_ip.get(ip)
            if not dev:
                continue
            is_camera = any("NetworkVideoTransmitter" in t or "onvif" in t.lower()
                            for t in info.get("types", [])) or \
                        any("onvif" in s.lower() for s in info.get("scopes", []))
            if is_camera:
                dev.device_type = "camera"
                for svc in ("camera", "onvif"):
                    if svc not in dev.services:
                        dev.services.append(svc)
            else:
                # Windows answers WS-Discovery too, via WSDAPI on port 5357.
                # Labelling those "onvif" would wrongly imply a camera, so the
                # generic responders are tagged for what they actually are.
                if "wsd" not in dev.services:
                    dev.services.append("wsd")
            label = info.get("name") or info.get("hardware")
            if label and not dev.hostname:
                dev.hostname = label
            if info.get("hardware"):
                dev.model = info["hardware"]
            elif info.get("name"):
                dev.model = info["name"]
            if info.get("xaddrs"):
                dev.management_url = info["xaddrs"][0]
            dev.tags.add("announces-wsd")
            n += 1
        return n


# ==================== TARGETED SERVICE IDENTIFICATION ====================
class ServiceProbe:
    """
    Identify devices by the TCP ports they hold open.

    Some hardware answers neither mDNS, SSDP nor WS-Discovery — the Hikvision
    on this network is exactly that case. For those, the ports it holds open
    are the remaining evidence of what it is and what it exposes.

    This is a TCP connect scan, the most intrusive thing in this file, so:

      - it is opt-in and never runs by default,
      - it only targets addresses inside networks we are attached to;
        naming anything outside them requires --i-have-permission,
      - it connects and closes without sending anything, unless banner
        reading is switched on — read_banner documents exactly what goes on
        the wire in that case, because it is the one place this class
        transmits, and
      - it never attempts authentication and offers no credential anywhere.

    The intent is inventory, not access.

    DEPTH. Five tiers, from a ten-port sanity check to all 65535. The tier
    decides only which ports are tried; the mechanics are identical at every
    level. The loudest tier is gated behind an explicit acknowledgement,
    because "what does this device run" and "I am going to knock on all
    65535 of its doors" are different asks with different consequences.

    CONCURRENCY. Connects are issued from one flat pool over (address, port)
    pairs rather than a loop per host. The previous implementation walked
    ports sequentially within each host — tolerable at 16 ports, impossible
    past that, since one silently-dropping host at 1000 ports would have
    taken 25 minutes on its own. Flattening also keeps the pool busy when
    most targets are dead, which is the normal case across a swept range.

    The socket cap is the throttle for this phase. RATE_LIMIT_DELAY is
    deliberately NOT applied here: at 0.01s per probe it would put a floor of
    eleven minutes on a single exhaustive host, which would make the tier
    useless rather than polite. Pace this with PROBE_MAX_SOCKETS instead.
    """

    # port -> (label, what its presence tends to mean)
    #
    # This table is the "standard" tier AND the label source for every tier.
    # Ports outside it are still probed at the deeper levels; they simply
    # report as "tcp/<port>" with no interpretation attached, which is
    # honest — an open port we cannot name is a fact, not a diagnosis.
    PORTS = {
        21:    ("ftp", "file transfer, often unauthenticated on embedded gear"),
        22:    ("ssh", "remote shell"),
        23:    ("telnet", "unencrypted remote shell — should not be open"),
        80:    ("http", "web interface"),
        443:   ("https", "web interface"),
        445:   ("smb", "windows file sharing"),
        554:   ("rtsp", "video stream"),
        1900:  ("upnp", "upnp service"),
        3389:  ("rdp", "remote desktop"),
        5000:  ("upnp-alt", "web or upnp service"),
        8000:  ("hikvision-sdk", "Hikvision/embedded SDK service port"),
        8080:  ("http-alt", "web interface"),
        8443:  ("https-alt", "web interface"),
        8554:  ("rtsp-alt", "video stream"),
        9000:  ("http-alt", "web or management service"),
        37777: ("dahua-sdk", "Dahua SDK service port"),
    }

    # Labels for ports that only appear at the deeper tiers. Kept separate
    # from PORTS so the "standard" tier stays exactly what it always was.
    EXTRA_LABELS = {
        25:    ("smtp", "mail submission"),
        53:    ("dns", "name server"),
        111:   ("rpcbind", "sun rpc portmapper"),
        135:   ("msrpc", "windows rpc endpoint mapper"),
        139:   ("netbios", "legacy windows file sharing"),
        161:   ("snmp", "management agent, often left on 'public'"),
        389:   ("ldap", "directory service"),
        502:   ("modbus", "industrial control — should never face a LAN client"),
        515:   ("lpd", "line printer daemon"),
        548:   ("afp", "apple file sharing"),
        631:   ("ipp", "printer"),
        873:   ("rsync", "file sync, frequently unauthenticated"),
        1883:  ("mqtt", "iot message broker"),
        2049:  ("nfs", "file share"),
        2323:  ("telnet-alt", "unencrypted remote shell on an alternate port"),
        3306:  ("mysql", "database"),
        3702:  ("ws-discovery", "onvif / windows device discovery"),
        4840:  ("opc-ua", "industrial control"),
        5060:  ("sip", "voip signalling"),
        5432:  ("postgres", "database"),
        5555:  ("adb", "android debug bridge — remote shell, no auth by default"),
        5900:  ("vnc", "remote desktop"),
        5985:  ("winrm", "windows remote management"),
        6379:  ("redis", "database, unauthenticated by default"),
        7547:  ("tr-069", "ISP remote management of your router"),
        8009:  ("chromecast", "cast receiver"),
        8291:  ("mikrotik", "RouterOS Winbox management"),
        8883:  ("mqtt-tls", "iot message broker"),
        9100:  ("jetdirect", "raw print queue"),
        9200:  ("elasticsearch", "search index, unauthenticated by default"),
        11211: ("memcached", "cache, unauthenticated by default"),
        27017: ("mongodb", "database"),
        32400: ("plex", "media server"),
        34567: ("dvr-sdk", "Xiongmai/generic DVR service port"),
        49152: ("upnp-dyn", "dynamic upnp / camera control"),
        62078: ("iphone-sync", "apple device pairing service"),
    }

    DEPTHS = ("quick", "standard", "deep", "full", "exhaustive")

    # The handful that answer "what is this thing" fastest.
    QUICK_PORTS = (22, 80, 443, 445, 554, 3389, 8000, 8080, 8443, 37777)

    # Well-known services plus the embedded / NVR / NAS / printer / media
    # ports consumer hardware actually listens on. Chosen for what turns up
    # on a home or small-office LAN, not for what a server farm runs.
    DEEP_PORTS = (
        7, 20, 21, 22, 23, 25, 37, 42, 49, 53, 67, 69, 79, 80, 81, 82, 83, 88,
        102, 106, 110, 111, 113, 119, 123, 135, 137, 138, 139, 143, 161, 162,
        179, 199, 264, 389, 427, 443, 444, 445, 465, 500, 502, 503, 512, 513,
        514, 515, 520, 523, 540, 548, 554, 587, 593, 623, 626, 631, 636, 646,
        771, 789, 873, 902, 990, 993, 995, 1000, 1024, 1025, 1026, 1027, 1080,
        1099, 1110, 1234, 1352, 1433, 1434, 1521, 1554, 1720, 1723, 1741,
        1755, 1801, 1883, 1900, 1911, 1962, 2000, 2001, 2049, 2082, 2083,
        2086, 2087, 2095, 2096, 2121, 2181, 2222, 2323, 2375, 2376, 2404,
        2455, 2601, 2604, 2638, 2869, 3000, 3001, 3128, 3260, 3268, 3283,
        3306, 3310, 3388, 3389, 3460, 3478, 3479, 3541, 3689, 3690, 3702,
        3749, 4000, 4022, 4040, 4063, 4064, 4443, 4444, 4500, 4567, 4664,
        4712, 4840, 4911, 5000, 5001, 5002, 5004, 5005, 5006, 5007, 5008,
        5009, 5010, 5050, 5060, 5061, 5222, 5269, 5280, 5353, 5357, 5432,
        5555, 5560, 5601, 5632, 5672, 5800, 5900, 5901, 5902, 5984, 5985,
        5986, 6000, 6001, 6379, 6443, 6666, 6667, 6881, 7000, 7001, 7070,
        7071, 7100, 7443, 7547, 7657, 7777, 8000, 8001, 8002, 8006, 8008,
        8009, 8010, 8020, 8022, 8025, 8030, 8060, 8080, 8081, 8082, 8083,
        8085, 8086, 8087, 8088, 8089, 8090, 8091, 8096, 8098, 8099, 8112,
        8123, 8126, 8139, 8181, 8200, 8222, 8243, 8280, 8291, 8332, 8333,
        8384, 8388, 8400, 8443, 8500, 8554, 8600, 8649, 8686, 8800, 8834,
        8880, 8883, 8888, 8889, 8899, 8983, 9000, 9001, 9002, 9009, 9010,
        9042, 9060, 9080, 9090, 9091, 9100, 9101, 9102, 9110, 9200, 9295,
        9300, 9443, 9481, 9535, 9595, 9600, 9700, 9876, 9898, 9917, 9943,
        9944, 9999, 10000, 10001, 10243, 10554, 11211, 12345, 16992, 16993,
        17000, 18080, 19999, 20000, 20005, 22000, 23023, 25105, 25565,
        27015, 27017, 28017, 32400, 32768, 32771, 34567, 37777, 41795,
        44158, 44818, 47808, 49152, 49153, 49154, 49155, 49156, 49157,
        50000, 50100, 51106, 52869, 55443, 62078, 64738,
    )

    # HTTP does not greet a client; it waits to be asked. These are the ports
    # where a banner read is allowed to send one minimal HEAD request.
    HTTP_PORTS = frozenset({
        80, 81, 82, 83, 443, 444, 591, 631, 2082, 2083, 2086, 2087, 4443,
        4444, 5000, 5001, 7001, 8000, 8001, 8006, 8008, 8010, 8080, 8081,
        8082, 8083, 8088, 8090, 8096, 8123, 8181, 8443, 8843, 8880, 8888,
        9000, 9080, 9090, 9443, 10000,
    })

    # Ports that expect a TLS handshake before anything else. Sending a
    # cleartext request to one of these does not just fail — the server
    # answers with a binary TLS alert record, which decodes into control
    # characters and looks like a banner while meaning nothing. Going through
    # the handshake instead is both correct and more informative.
    TLS_PORTS = frozenset({
        443, 444, 465, 636, 990, 993, 995, 2083, 2087, 2096, 4443, 5061,
        5986, 6443, 7443, 8443, 8843, 8883, 9443, 10000,
    })

    @classmethod
    def label_for(cls, port: int) -> str:
        """Service label for a port, or 'tcp/<port>' when we cannot name it."""
        entry = cls.PORTS.get(port) or cls.EXTRA_LABELS.get(port)
        return entry[0] if entry else f"tcp/{port}"

    @classmethod
    def ports_for(cls, depth: Optional[str] = None) -> List[int]:
        """
        The port list for a depth tier.

        Tiers are cumulative: each contains everything the one below it does,
        so raising the depth can only ever find more, never a different set.
        """
        depth = (depth or Config.PROBE_DEPTH or "standard").lower()
        standard = set(cls.PORTS)
        if depth == "quick":
            return sorted(cls.QUICK_PORTS)
        if depth == "deep":
            return sorted(standard | set(cls.DEEP_PORTS))
        if depth == "full":
            # Every privileged port, plus the common high ports from 'deep'.
            # Not nmap's top-1000 — this is a set we can describe exactly
            # rather than a list we would be approximating from memory.
            return sorted(set(range(1, 1025)) | standard | set(cls.DEEP_PORTS))
        if depth == "exhaustive":
            return list(range(1, 65536))
        return sorted(standard)

    # ---------- target selection ----------

    @staticmethod
    def parse_target(spec: str, limit: Optional[int] = None) -> List[str]:
        """
        Expand one target spec into addresses.

        Accepts, in rough order of how often they get typed:

            192.168.2.31                 one address
            192.168.2.0/24               a network
            192.168.2.10-40              a short range (last octet)
            192.168.2.10-192.168.2.40    an explicit range

        Raises ValueError with a usable message rather than returning an
        empty list, so a typo is reported instead of quietly probing nothing.
        Refuses to expand past `limit` addresses for the same reason
        sweep_targets refuses oversized networks: a fat-fingered prefix
        should stop the run, not start a very long one.
        """
        spec = (spec or "").strip()
        if not spec:
            raise ValueError("empty target")
        limit = limit or Config.MAX_SWEEP_HOSTS

        if "/" in spec:
            net = ipaddress.ip_network(spec, strict=False)
            hosts = [str(h) for h in net.hosts()] or [str(net.network_address)]
            if len(hosts) > limit:
                raise ValueError(f"{len(hosts)} addresses exceeds the "
                                 f"{limit}-address cap")
            return hosts

        if "-" in spec:
            head, _, tail = spec.partition("-")
            start = ipaddress.IPv4Address(head.strip())
            tail = tail.strip()
            if "." in tail:
                end = ipaddress.IPv4Address(tail)
            else:
                prefix = str(start).rsplit(".", 1)[0]
                end = ipaddress.IPv4Address(f"{prefix}.{int(tail)}")
            lo, hi = sorted((int(start), int(end)))
            if hi - lo + 1 > limit:
                raise ValueError(f"{hi - lo + 1} addresses exceeds the "
                                 f"{limit}-address cap")
            return [str(ipaddress.IPv4Address(i)) for i in range(lo, hi + 1)]

        return [str(ipaddress.IPv4Address(spec))]

    @classmethod
    def expand_targets(cls, specs: List[str], on_log=None) -> List[str]:
        """Expand many specs, reporting and skipping the ones that fail."""
        on_log = on_log or (lambda m: None)
        seen: Set[str] = set()
        out: List[str] = []
        for spec in specs or []:
            try:
                addrs = cls.parse_target(spec)
            except (ValueError, ipaddress.AddressValueError) as exc:
                on_log(f"    ! Ignoring target {spec!r}: {exc}")
                continue
            for addr in addrs:
                if addr not in seen:
                    seen.add(addr)
                    out.append(addr)
        return out

    @staticmethod
    def baseline_networks(baseline: Optional[Dict[str, Any]]) -> Set[str]:
        """
        Networks seen in a previous scan.

        Uses the subnet each device was recorded on. Older baselines predate
        that field and store only addresses; for those we fall back to a /24,
        which is a guess and is labelled as one wherever it is surfaced.
        """
        nets: Set[str] = set()
        for entry in (baseline or {}).get("lan_devices", []):
            subnet = entry.get("subnet")
            if subnet:
                try:
                    nets.add(str(ipaddress.ip_network(subnet, strict=False)))
                    continue
                except ValueError:
                    pass
            ip = entry.get("ip")
            if not ip:
                continue
            try:
                nets.add(str(ipaddress.ip_network(f"{ip}/24", strict=False)))
            except ValueError:
                continue
        return nets

    @classmethod
    def resolve_nets(cls, specs: List[str],
                     interfaces: Optional[List['NetworkInterface']] = None,
                     sweep_targets: Optional[List['SweepTarget']] = None,
                     baseline: Optional[Dict[str, Any]] = None,
                     on_log=None) -> List[str]:
        """
        Turn --probe-net values into concrete CIDRs.

        Besides literal CIDRs it accepts the names an operator actually
        thinks in, which is the point of the feature — you should not have to
        look up your own prefix to say "just this LAN":

            attached  networks this host holds an address on
            routed    networks reachable through one of our gateways
            known     networks seen in a previous scan (from the baseline)
            new       enumerated now but absent from the baseline
            all       every network this scan enumerated

        An empty spec list means no restriction, which the caller reads as
        "every enumerated network".
        """
        on_log = on_log or (lambda m: None)
        interfaces = interfaces or []
        sweep_targets = sweep_targets or []

        # is_sweepable, not merely "has a network": it excludes link-local
        # (APIPA), loopback and single-host overlay prefixes, and honours the
        # virtual/VPN opt-ins. Without it, 'attached' would resolve to things
        # like 169.254.0.0/16 and every Hyper-V and WSL host network.
        attached = {i.network for i in interfaces if i.network and i.is_sweepable}
        routed = {t.cidr for t in sweep_targets if t.origin == "routed"}
        enumerated = {t.cidr for t in sweep_targets if t.cidr} | attached
        known = cls.baseline_networks(baseline)

        out: List[str] = []
        seen: Set[str] = set()

        def add(cidr: str):
            if cidr and cidr not in seen:
                seen.add(cidr)
                out.append(cidr)

        for spec in specs or []:
            name = (spec or "").strip().lower()
            if name == "attached":
                for c in sorted(attached):
                    add(c)
            elif name == "routed":
                for c in sorted(routed):
                    add(c)
            elif name == "known":
                for c in sorted(known):
                    add(c)
            elif name == "new":
                for c in sorted(enumerated - known):
                    add(c)
            elif name == "all":
                for c in sorted(enumerated):
                    add(c)
            else:
                try:
                    add(str(ipaddress.ip_network(spec, strict=False)))
                except ValueError:
                    on_log(f"    ! Ignoring network {spec!r}: not a CIDR or a "
                           f"known name (attached/routed/known/new/all)")
        return out

    # ---------- the wire ----------

    @staticmethod
    def _connect(ip: str, port: int, timeout: float) -> Optional[socket.socket]:
        """One TCP connect. Returns the connected socket, or None."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((ip, port)) == 0:
                return s
        except OSError:
            pass
        try:
            s.close()
        except OSError:
            pass
        return None

    @classmethod
    def read_banner(cls, sock: socket.socket, ip: str, port: int,
                    timeout: float) -> str:
        """
        Read whatever the service says for itself. THIS IS THE ONE PLACE THIS
        CLASS TRANSMITS, so it is spelled out rather than left implicit.

        Two cases, and the difference is the whole ethical distinction:

          - Most services greet first. SSH sends its version string, FTP and
            SMTP send a numeric welcome, RTSP and IMAP announce themselves.
            Reading those sends NOTHING — we listen to bytes that were
            already on their way.

          - HTTP does not greet; it waits to be asked. On the HTTP_PORTS
            list, and only there, we send one 'HEAD / HTTP/1.0' — the same
            request a link checker or an uptime monitor makes, asking for
            headers and no body. That is still a transmission, which is why
            banner reading is off by default.

        Nothing else is ever sent. No credential is offered, no path beyond
        '/' is requested, and nothing is retried.
        """
        # TLS ports never speak cleartext. Asking them to saves nothing and
        # gets a binary alert record back, so go through the handshake and
        # make the same request inside it.
        if port in cls.TLS_PORTS:
            return cls._tls_banner(sock, ip, timeout)

        sock.settimeout(timeout)
        data = b""
        try:
            data = sock.recv(512)
        except (socket.timeout, OSError):
            data = b""

        if not data and port in cls.HTTP_PORTS:
            try:
                sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
                data = sock.recv(1024)
            except (socket.timeout, OSError):
                data = b""

        return cls._summarise_banner(data.decode("utf-8", "replace")) if data else ""

    @classmethod
    def _tls_banner(cls, sock: socket.socket, ip: str, timeout: float) -> str:
        """
        Complete a TLS handshake and read the response headers.

        Certificates are not verified — we are identifying a device on our own
        network, not establishing trust with it, and embedded gear ships
        self-signed certificates as a rule. Nothing is sent but the same
        'HEAD /' the cleartext path uses; it simply travels inside the tunnel.
        """
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock.settimeout(timeout)
            tls = ctx.wrap_socket(sock)
        except (ssl.SSLError, OSError, ValueError):
            return ""

        data = b""
        try:
            tls.settimeout(timeout)
            tls.sendall(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
            data = tls.recv(1024)
        except (ssl.SSLError, socket.timeout, OSError):
            data = b""
        finally:
            try:
                tls.close()
            except OSError:
                pass

        return cls._summarise_banner(data.decode("utf-8", "replace")) if data else ""

    @staticmethod
    def _summarise_banner(text: str) -> str:
        """
        Reduce a banner to its single most identifying line.

        For HTTP the status line ('HTTP/1.0 200 OK') says nothing about the
        device while the Server header often names it outright, so headers
        that identify are preferred over whatever happened to arrive first.

        Anything that accepts a connection can answer with binary — a TLS
        alert, a length-prefixed protocol frame, or plain noise. Those decode
        into control characters that mean nothing and would corrupt a
        terminal, so the text is reduced to printable characters first and
        discarded entirely if too little survives to be worth reporting.
        """
        cleaned = "".join(
            ch if (ch.isprintable() or ch in "\r\n\t") else " " for ch in text
        )
        lines = [ln.strip() for ln in cleaned.splitlines() if ln.strip()]
        if not lines:
            return ""

        best = lines[0]
        for key in ("server:", "www-authenticate:", "x-powered-by:"):
            match = next((ln for ln in lines if ln.lower().startswith(key)), None)
            if match:
                best = match
                break

        # Four printable non-space characters is the floor for calling
        # something a banner rather than noise that happened to survive.
        if sum(1 for ch in best if not ch.isspace()) < 4:
            return ""
        return best[:200]

    @classmethod
    def scan_targets(cls, ips: List[str], ports: Optional[List[int]] = None,
                     timeout: Optional[float] = None,
                     max_sockets: Optional[int] = None,
                     banners: Optional[bool] = None,
                     banner_timeout: Optional[float] = None,
                     on_log=None, on_progress=None,
                     should_stop=None) -> Dict[str, Dict[str, Any]]:
        """
        Probe every (address, port) pair.

        Returns {ip: {"open": [ports], "banners": {port: text}}} for every
        address asked about, including the ones with nothing open — an
        address that answered nothing is a result, not an absence.
        """
        ips = list(ips or [])
        ports = list(ports if ports is not None else cls.ports_for())
        timeout = Config.PROBE_CONNECT_TIMEOUT if timeout is None else timeout
        banners = Config.PROBE_BANNERS if banners is None else banners
        banner_timeout = (Config.PROBE_BANNER_TIMEOUT if banner_timeout is None
                          else banner_timeout)
        max_sockets = max(1, int(Config.PROBE_MAX_SOCKETS if max_sockets is None
                                 else max_sockets))
        on_log = on_log or (lambda m: None)
        on_progress = on_progress or (lambda stage, done, total: None)
        should_stop = should_stop or (lambda: False)

        results: Dict[str, Dict[str, Any]] = {
            ip: {"open": [], "banners": {}} for ip in ips
        }
        if not ips or not ports:
            return results

        total = len(ips) * len(ports)
        done = 0
        on_progress("probe", 0, total)

        def work(pair):
            ip, port = pair
            sock = cls._connect(ip, port, timeout)
            if sock is None:
                return None
            banner = ""
            try:
                if banners:
                    banner = cls.read_banner(sock, ip, port, banner_timeout)
            except Exception:
                banner = ""
            finally:
                try:
                    sock.close()
                except OSError:
                    pass
            return ip, port, banner

        # Chunked so an exhaustive run does not materialise millions of
        # futures up front. The pool size is unchanged; only the queue ahead
        # of it is bounded — which is also what keeps a stop request from
        # waiting on the entire remaining workload.
        chunk = max(max_sockets * 4, 256)
        pairs = ((ip, port) for ip in ips for port in ports)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_sockets) as pool:
            while not should_stop():
                batch = list(itertools.islice(pairs, chunk))
                if not batch:
                    break
                for res in pool.map(work, batch):
                    done += 1
                    if res:
                        ip, port, banner = res
                        results[ip]["open"].append(port)
                        if banner:
                            results[ip]["banners"][port] = banner
                on_progress("probe", done, total)

        for res in results.values():
            res["open"].sort()
        return results

    @classmethod
    def scan_host(cls, ip: str, timeout: float = 1.0,
                  ports: Optional[List[int]] = None) -> List[int]:
        """
        Return the subset of ports accepting connections on one host.

        Kept for callers that want a single host and nothing else; it now
        delegates to the concurrent path rather than walking ports one at a
        time.
        """
        return cls.scan_targets([ip], ports=ports, timeout=timeout,
                                banners=False)[ip]["open"]

    # ---------- device selection ----------

    @classmethod
    def select_devices(cls, devices: List[NetworkDevice],
                       select: Optional[str] = None,
                       nets: Optional[List[str]] = None,
                       allow_foreign: bool = False,
                       baseline: Optional[Dict[str, Any]] = None
                       ) -> List[NetworkDevice]:
        """
        Decide which discovered devices a probe is allowed to touch.

        Three independent filters, applied in this order because they narrow
        from "may we" to "should we":

          1. ownership — off our networks is refused unless explicitly allowed
          2. nets      — restrict to particular networks, if any were named
          3. select    — silent / unidentified / new / all

        'silent' means it announced nothing at all over mDNS, SSDP or
        WS-Discovery. A device_type guessed from a MAC prefix is not an
        identification, which is why 'unidentified' exists as a separate,
        slightly wider setting: it also picks up devices still typed
        unknown/generic despite having said something.
        """
        select = (select or Config.PROBE_SELECT or "silent").lower()

        parsed_nets = []
        for cidr in (nets or []):
            try:
                parsed_nets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                continue

        prev = (baseline or {}).get("lan_devices", []) or []
        known_macs = {d.get("mac") for d in prev if d.get("mac")}
        known_ips = {d.get("ip") for d in prev if d.get("ip")}

        out = []
        for dev in devices:
            if not dev.ip:
                continue
            if not allow_foreign and getattr(dev, "ownership", "ours") != "ours":
                continue

            if parsed_nets:
                try:
                    addr = ipaddress.ip_address(dev.ip)
                except ValueError:
                    continue
                if not any(addr in net for net in parsed_nets):
                    continue

            if select == "silent":
                if dev.services:
                    continue
            elif select == "unidentified":
                if dev.services and dev.device_type not in ("unknown", "generic", ""):
                    continue
            elif select == "new":
                if dev.mac and dev.mac in known_macs:
                    continue
                if not dev.mac and dev.ip in known_ips:
                    continue
            # 'all' falls through with no further filtering

            out.append(dev)
        return out

    # ---------- applying what we found ----------

    @classmethod
    def apply_results(cls, devices: List[NetworkDevice],
                      results: Dict[str, Dict[str, Any]]) -> int:
        """Merge probe results onto devices. Returns the number touched."""
        by_ip = {d.ip: d for d in devices}
        touched = 0
        for ip, res in results.items():
            dev = by_ip.get(ip)
            if not dev:
                continue
            ports = res.get("open") or []
            if not ports:
                continue

            dev.ports_open = sorted(set((dev.ports_open or []) + ports))
            for port in ports:
                label = cls.label_for(port)
                if label not in dev.services:
                    dev.services.append(label)

            banners = res.get("banners") or {}
            if banners:
                dev.tags.add("banner")
                dev.banners.update(banners)
                best = cls._best_banner(banners)
                if best and not dev.model:
                    dev.model = best[:120]

            cls._classify_from_ports(dev, set(ports), banners)
            touched += 1
        return touched

    @staticmethod
    def _best_banner(banners: Dict[int, str]) -> str:
        """Pick the banner that names a product over one that names a protocol."""
        for _port, text in sorted(banners.items()):
            if text and not text.lower().startswith("http/"):
                return text
        return next(iter(banners.values()), "")

    @classmethod
    def _classify_from_ports(cls, dev: NetworkDevice, ports: Set[int],
                             banners: Optional[Dict[int, str]] = None):
        """
        Infer a device type from open ports and banner text.

        Only fills a type that is still unset. A device that told us what it
        is over mDNS or WS-Discovery has already given better evidence than
        a port number, and a conflict between the two is worth noticing in
        the output rather than silently resolving here.
        """
        if dev.device_type not in ("unknown", "generic", ""):
            return

        blob = " ".join((banners or {}).values()).lower()
        for needle, kind in (
            ("hikvision", "camera"), ("dahua", "camera"), ("axis", "camera"),
            ("reolink", "camera"), ("dvrdvs", "camera"), ("rtsp", "camera"),
            ("synology", "nas"), ("qnap", "nas"),
            ("jetdirect", "printer"), ("printer", "printer"), ("cups", "printer"),
            ("mikrotik", "network"), ("routeros", "network"),
            ("openwrt", "network"), ("dd-wrt", "network"),
            ("dropbear", "iot"), ("busybox", "iot"),
        ):
            if needle in blob:
                dev.device_type = kind
                return

        if {554, 8554, 8000, 37777, 34567, 10554} & ports:
            dev.device_type = "camera"
        elif {9100, 631, 515} & ports:
            dev.device_type = "printer"
        elif {2049, 548} & ports or ({445} & ports and {5000, 5001} & ports):
            dev.device_type = "nas"
        elif {3389, 5985, 135} & ports:
            dev.device_type = "computer"
        elif {22} & ports:
            dev.device_type = "computer"

    @classmethod
    def identify(cls, devices: List[NetworkDevice], only_unidentified: bool = True,
                 on_log=None, should_stop=None, timeout: Optional[float] = None,
                 depth: Optional[str] = None, select: Optional[str] = None,
                 nets: Optional[List[str]] = None, allow_foreign: bool = False,
                 baseline: Optional[Dict[str, Any]] = None,
                 banners: Optional[bool] = None, on_progress=None,
                 max_sockets: Optional[int] = None) -> int:
        """
        Probe discovered devices for open ports.

        `only_unidentified` is kept so existing callers keep their behaviour:
        with no explicit `select` it still means "silent devices only".
        """
        on_log = on_log or (lambda m: None)

        if select is None:
            select = Config.PROBE_SELECT if only_unidentified else "all"
        depth = depth or Config.PROBE_DEPTH
        use_banners = Config.PROBE_BANNERS if banners is None else banners

        targets = cls.select_devices(devices, select=select, nets=nets,
                                     allow_foreign=allow_foreign,
                                     baseline=baseline)
        if not targets:
            on_log(f"    No devices matched select='{select}'"
                   + (f" within {', '.join(nets)}" if nets else ""))
            return 0

        ports = cls.ports_for(depth)
        detail = f"depth={depth}, {len(ports)} port(s), select={select}"
        if use_banners:
            detail += ", banners"
        if nets:
            detail += f", nets={', '.join(nets)}"
        connects = len(targets) * len(ports)
        on_log(f"    Probing {len(targets)} device(s) [{detail}]")
        # State the work up front and the rate afterwards. A deep probe of a
        # LAN can legitimately finish in seconds — closed ports answer with an
        # immediate RST, so only firewalled ones cost the full timeout — and
        # without a connect count there is no way to tell that apart from a
        # phase that quietly did nothing.
        on_log(f"    {connects:,} connects queued "
               f"({Config.PROBE_MAX_SOCKETS} at a time)")
        if depth in ("full", "exhaustive"):
            on_log(f"    ! {depth} probing is loud and slow")

        started = time.monotonic()
        results = cls.scan_targets(
            [d.ip for d in targets], ports=ports, timeout=timeout,
            max_sockets=max_sockets, banners=use_banners, on_log=on_log,
            on_progress=on_progress, should_stop=should_stop,
        )
        elapsed = max(0.001, time.monotonic() - started)
        found = cls.apply_results(targets, results)
        open_total = sum(len(r["open"]) for r in results.values())
        on_log(f"    {connects:,} connects in {elapsed:.1f}s "
               f"({connects / elapsed:,.0f}/s) — {open_total} open port(s) "
               f"on {found} device(s)")
        return found

    @staticmethod
    def findings(devices: List[NetworkDevice]) -> List['Finding']:
        """Flag exposures that are worth acting on."""
        out = []
        telnet = [d for d in devices if 23 in (d.ports_open or [])]
        if telnet:
            out.append(Finding(
                severity="critical", category="exposure",
                title=f"{len(telnet)} device(s) have telnet open",
                detail=("Telnet carries credentials in clear text and is a standard "
                        "entry point for embedded-device malware. It should be "
                        "disabled."),
                evidence=[f"{d.ip}  {d.hostname or 'no hostname'}  {d.vendor}"
                          for d in telnet],
            ))
        ftp = [d for d in devices if 21 in (d.ports_open or [])]
        if ftp:
            out.append(Finding(
                severity="warning", category="exposure",
                title=f"{len(ftp)} device(s) have FTP open",
                detail="FTP is unencrypted and frequently left unauthenticated on "
                       "embedded devices.",
                evidence=[f"{d.ip}  {d.hostname or 'no hostname'}  {d.vendor}"
                          for d in ftp],
            ))
        return out


# ==================== CHANNEL CONGESTION ====================
class ChannelAnalyzer:
    """
    Work out which Wi-Fi channels are actually busy, and which are free.

    Every visible BSSID is a competitor for airtime on its channel. Signal
    strength matters because a loud neighbour forces your radio to defer far
    more than a faint one, and modern APs bond channels — an 802.11ac/ax radio
    on channel 157 occupies an 80 MHz block covering 149-161, so "nobody else
    is on my exact channel number" is not the same as "my channel is clear".

    DFS channels (52-144) are treated as a last resort: they are usually quiet
    precisely because radios must vacate them when they detect radar, which
    produces intermittent dropouts that are hard to diagnose later.
    """

    # 80 MHz blocks in the 5 GHz band. A radio on any member contends with all.
    BLOCKS_5G = [
        (36, 40, 44, 48),        # UNII-1, non-DFS
        (52, 56, 60, 64),        # UNII-2A, DFS
        (100, 104, 108, 112),    # UNII-2C, DFS
        (116, 120, 124, 128),    # DFS
        (132, 136, 140, 144),    # DFS
        (149, 153, 157, 161),    # UNII-3, non-DFS
    ]
    DFS_CHANNELS = set(range(52, 145))

    @staticmethod
    def block_for(channel: int) -> Tuple[int, ...]:
        for block in ChannelAnalyzer.BLOCKS_5G:
            if channel in block:
                return block
        return (channel,)

    MIN_SAMPLE = 8  # below this, a snapshot is too thin to advise from

    @staticmethod
    def merge_observations(current: List['WifiNetwork'],
                           history: Optional[List[Dict[str, Any]]] = None
                           ) -> List['WifiNetwork']:
        """
        Combine this scan's BSSIDs with those remembered from previous scans.

        `netsh wlan show networks` returns the adapter's scan cache, not a fresh
        survey. An idle or disconnected radio may report a handful of BSSIDs on
        one run and twenty on the next. Recommending a channel from a single
        thin snapshot produced exactly the wrong answer in testing — the block
        holding a neighbour's mesh backhaul looked empty simply because that
        run had not seen it.

        Merging by BSSID and keeping the strongest signal ever observed gives a
        stable picture of the radio environment rather than one instant of it.
        """
        by_bssid = {n.bssid: n for n in current}
        for rec in history or []:
            bssid = rec.get("bssid")
            if not bssid or bssid in by_bssid:
                continue
            channel = rec.get("channel") or 0
            if not channel:
                continue
            by_bssid[bssid] = WifiNetwork(
                ssid=rec.get("ssid", ""),
                bssid=bssid,
                signal_percent=rec.get("signal_percent", 0),
                band=rec.get("band", ""),
                channel=channel,
                ownership=rec.get("ownership", "foreign"),
            )
        return list(by_bssid.values())

    @staticmethod
    def analyze(wifi: List['WifiNetwork']) -> Dict[str, Any]:
        """
        Score each 5 GHz block and each 2.4 GHz channel by contention.

        Score is the sum of signal percentages of competing BSSIDs, so one
        strong neighbour outweighs several distant ones — which is how airtime
        actually behaves.
        """
        ours_blocks = set()
        blocks: Dict[Tuple[int, ...], Dict[str, Any]] = {}
        for block in ChannelAnalyzer.BLOCKS_5G:
            blocks[block] = {"score": 0, "bssids": [], "ours": 0, "foreign": 0}

        band24: Dict[int, Dict[str, Any]] = defaultdict(
            lambda: {"score": 0, "bssids": [], "ours": 0, "foreign": 0})

        for n in wifi:
            if not n.channel:
                continue
            is_5g = n.channel > 14
            if is_5g:
                block = ChannelAnalyzer.block_for(n.channel)
                if block not in blocks:
                    continue
                target = blocks[block]
                if n.ownership == "ours":
                    ours_blocks.add(block)
            else:
                # 2.4 GHz: a 20 MHz channel bleeds into +/-4 either side.
                for ch in range(max(1, n.channel - 4), min(14, n.channel + 4) + 1):
                    entry = band24[ch]
                    entry["score"] += n.signal_percent if n.ownership != "ours" else 0
                    if n.channel == ch:
                        entry["bssids"].append(n)
                        entry["ours" if n.ownership == "ours" else "foreign"] += 1
                continue

            target["bssids"].append(n)
            target["ours" if n.ownership == "ours" else "foreign"] += 1
            # Only foreign radios count as contention; our own radios are
            # traffic we control and can schedule around.
            if n.ownership != "ours":
                target["score"] += n.signal_percent

        ranked = sorted(
            blocks.items(),
            key=lambda kv: (kv[1]["score"], 1 if set(kv[0]) & ChannelAnalyzer.DFS_CHANNELS else 0),
        )
        non_dfs = [(b, v) for b, v in ranked
                   if not (set(b) & ChannelAnalyzer.DFS_CHANNELS)]

        sample = sum(1 for n in wifi if n.channel)
        return {
            "blocks_5g": {"-".join(map(str, b)): v for b, v in blocks.items()},
            "band_24": {str(k): v for k, v in sorted(band24.items())},
            "ours_blocks": ["-".join(map(str, b)) for b in sorted(ours_blocks)],
            "best_non_dfs": "-".join(map(str, non_dfs[0][0])) if non_dfs else "",
            "ranked_non_dfs": [("-".join(map(str, b)), v["score"]) for b, v in non_dfs],
            "sample_size": sample,
            "sample_thin": sample < ChannelAnalyzer.MIN_SAMPLE,
        }

    @staticmethod
    def findings(wifi: List['WifiNetwork'],
                 history: Optional[List[Dict[str, Any]]] = None) -> List['Finding']:
        """Raise a finding when one of our radios shares a block with a loud neighbour."""
        out = []
        wifi = ChannelAnalyzer.merge_observations(wifi, history)
        report = ChannelAnalyzer.analyze(wifi)
        if report["sample_thin"]:
            out.append(Finding(
                severity="info", category="interference",
                title=f"Only {report['sample_size']} BSSID(s) seen — channel advice withheld",
                detail=("The wireless adapter's scan cache was nearly empty on this run, "
                        "so the radio environment is not represented well enough to "
                        "recommend a channel. Run another scan, ideally with the Wi-Fi "
                        "adapter enabled and not associated, to build up the picture."),
                evidence=[],
            ))
            return out
        for block_key in report["ours_blocks"]:
            info = report["blocks_5g"].get(block_key, {})
            foreign = [n for n in info.get("bssids", []) if n.ownership != "ours"]
            if not foreign:
                continue
            loudest = max(foreign, key=lambda n: n.signal_percent)
            if loudest.signal_percent < 40:
                continue  # faint enough not to matter
            ours = [n for n in info.get("bssids", []) if n.ownership == "ours"]
            best = report["best_non_dfs"]
            better = best and best != block_key
            out.append(Finding(
                severity="info",
                category="interference",
                title=(f"Your 5 GHz radio on channels {block_key} shares the band "
                       f"with {len(foreign)} other BSSID(s)"),
                detail=(
                    "802.11ac/ax radios bond channels into 80 MHz blocks, so every "
                    "BSSID listed here competes for the same airtime as yours even "
                    "when the channel numbers differ. Hidden mesh backhaul links are "
                    "the worst kind of neighbour on a block: they carry all of a "
                    "satellite's client traffic, so they are busy continuously rather "
                    "than in bursts."
                    + (f" Least contended non-DFS block right now: {best}." if better
                       else " No quieter non-DFS block is currently available.")
                ),
                evidence=(
                    [f"ours: {n.bssid} {n.display_name} ch{n.channel} "
                     f"{n.signal_percent}%" for n in ours]
                    + [f"theirs: {n.bssid} {n.display_name} ch{n.channel} "
                       f"{n.signal_percent}%"
                       + (" [hidden backhaul]" if n.is_hidden else "")
                       for n in sorted(foreign, key=lambda x: -x.signal_percent)]
                ),
            ))
        return out


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


def _ip_sort_key(ip: str):
    """Sort IPv4 addresses numerically rather than as strings, so .9 precedes .10."""
    try:
        return (0,) + tuple(int(o) for o in ip.split('.'))
    except (ValueError, AttributeError):
        return (1, ip)


# ==================== SECURE DASHBOARD ====================
class SecureDashboard:
    """
    GENERATE ENHANCED HTML DASHBOARD WITH SECURITY NOTICES
    
    Creates an interactive HTML dashboard that displays:
    - Network statistics
    - Device lists by subnet
    - WiFi networks
    - Security reminders
    - Ethical usage guidelines
    """
    
    @staticmethod
    def generate_dashboard(lan_devices: List[NetworkDevice], wifi_devices: List[NetworkDevice], 
                          scan_duration: float, topology: Dict[str, Any]) -> str:
        """
        Generate enhanced HTML dashboard with security features.
        
        Args:
            lan_devices: List of LAN devices
            wifi_devices: List of WiFi networks
            scan_duration: How long the scan took
            topology: Network topology information
            
        Returns:
            HTML string for the dashboard
        """
        # Color scheme for dark theme
        colors = {
            'bg': '#0f172a', 'card': '#1e293b', 'text': '#f8fafc',
            'secondary': '#94a3b8', 'border': '#334155', 'primary': '#3b82f6',
            'success': '#10b981', 'warning': '#f59e0b', 'danger': '#ef4444',
            'info': '#06b6d4', 'purple': '#8b5cf6'
        }
        
        # ===== GROUP DEVICES BY SUBNET =====
        subnets = defaultdict(list)
        for device in lan_devices:
            if device.subnet:
                subnets[device.subnet].append(device)
        
        # ===== GENERATE SUBNET HTML SECTIONS =====
        # Every subnet and every device is rendered. The previous version cut
        # this to the first 3 subnets and 12 devices each, with no indication
        # anything had been withheld, so the page under-reported the network
        # while presenting itself as a complete inventory.
        def _sort_key(item):
            _sub, devs = item
            ours = any(getattr(d, 'ownership', 'ours') == 'ours' for d in devs)
            return (0 if ours else 1, _sub)

        subnet_html = ""
        for subnet, devices in sorted(subnets.items(), key=_sort_key):
            device_count = len(devices)
            gateway_count = sum(1 for d in devices if d.is_gateway)
            wireless_count = sum(1 for d in devices if 'wireless' in d.tags)
            owned = any(getattr(d, 'ownership', 'ours') == 'ours' for d in devices)
            badge = ('<span class="badge ours">our network</span>' if owned
                     else '<span class="badge nearby">nearby &mdash; not ours</span>')

            subnet_html += f'''
            <div class="subnet-section">
                <h3>🌐 Subnet: {html.escape(subnet)} {badge}</h3>
                <p>Devices: {device_count} | Gateways: {gateway_count} | Wireless: {wireless_count}</p>
                <div class="device-grid">
            '''

            for device in sorted(devices, key=lambda d: _ip_sort_key(d.ip)):
                device_class = "wireless" if 'wireless' in device.tags else "wired"
                if device.is_gateway:
                    device_class = "gateway"

                state = getattr(device, 'neighbor_state', '') or ''
                via = getattr(device, 'discovered_via', '') or ''
                meta = " · ".join(x for x in (via, state.lower()) if x)
                vendor = device.vendor if device.vendor and device.vendor != 'Unknown' else 'Unknown vendor'

                # Open ports, when a probe found any. Ports that carry real
                # exposure are marked so the eye lands on them first — an open
                # telnet is the single most actionable thing on this page.
                ports_html = ""
                if device.ports_open:
                    chips = ""
                    for port in device.ports_open:
                        label = ServiceProbe.label_for(port)
                        risky = port in (21, 23, 2323, 445, 3389, 5900, 6379,
                                         11211, 9200, 27017)
                        banner = (device.banners or {}).get(port, "")
                        title = f"{port}/tcp {label}"
                        if banner:
                            title += f" — {banner}"
                        chips += (f'<span class="port{" risky" if risky else ""}" '
                                  f'title="{html.escape(title)}">{port}'
                                  f'<em>{html.escape(label)}</em></span>')
                    ports_html = f'<div class="ports">{chips}</div>'

                # A banner is the device describing itself, which beats every
                # inference on this card — so it gets its own line rather than
                # being buried in a tooltip.
                banner_html = ""
                if device.model:
                    banner_html = (f'<div class="banner mono">'
                                   f'{html.escape(device.model)}</div>')

                subnet_html += f'''
                    <div class="device-card {device_class}">
                        <div class="device-ip">{html.escape(device.ip)}</div>
                        <div>{html.escape(device.hostname or 'No hostname')}</div>
                        <div class="device-type">{html.escape(device.device_type.replace('_', ' ').title())}</div>
                        <div>{html.escape(vendor)}</div>
                        <div class="mono">{html.escape(device.mac or '')}</div>
                        <div class="meta">{html.escape(meta)}</div>
                        {banner_html}
                        {ports_html}
                    </div>
                '''

            subnet_html += '''
                </div>
            </div>
            '''

        # ===== GENERATE WiFi HTML =====
        # Wireless is split by ownership and grouped by physical radio, and
        # every measurement the adapter reported is shown. The old version
        # listed the first 8 BSSIDs with nothing but name, MAC and a band it
        # had guessed from the SSID string.
        wifi_networks = (topology or {}).get('wifi') or []
        by_bssid = {n.bssid: n for n in wifi_networks}

        def _render_wifi(items, empty_msg):
            if not items:
                return f'<p class="muted">{empty_msg}</p>'
            radios = defaultdict(list)
            for w in items:
                net = by_bssid.get(w.mac)
                key = net.physical_radio if net else (w.mac or w.hostname)
                radios[key].append((w, net))
            out = ""
            for key, entries in sorted(radios.items(),
                                       key=lambda kv: -max((n.signal_percent if n else 0)
                                                           for _w, n in kv[1])):
                ssids = sorted({w.hostname for w, _n in entries})
                out += (f'<div class="radio-group"><div class="radio-head">'
                        f'📻 radio <span class="mono">{html.escape(key)}</span> — '
                        f'{len(entries)} BSSID(s): {html.escape(", ".join(ssids))}</div>'
                        f'<div class="device-grid">')
                for w, net in sorted(entries, key=lambda e: -(e[1].signal_percent if e[1] else 0)):
                    if net:
                        bar = max(0, min(100, net.signal_percent))
                        extra = (f'<div class="sig"><span style="width:{bar}%"></span></div>'
                                 f'<div class="meta">{net.signal_percent}% · {html.escape(net.band_label)}'
                                 f' · ch{net.channel} · {html.escape(net.radio_type or "?")}</div>'
                                 f'<div class="meta">{html.escape(net.authentication or "unknown auth")}'
                                 f' / {html.escape(net.encryption or "?")}</div>')
                        flags = []
                        if net.is_virtual_bssid:
                            flags.append("virtual BSSID")
                        if net.is_hidden:
                            flags.append("hidden")
                        if net.is_open:
                            flags.append("OPEN")
                        if net.connected_stations:
                            flags.append(f"{net.connected_stations} station(s)")
                        if flags:
                            extra += f'<div class="meta flags">{html.escape(" · ".join(flags))}</div>'
                    else:
                        extra = ""
                    out += f'''
                    <div class="device-card wireless">
                        <div><strong>{html.escape(w.hostname or '[Hidden]')}</strong></div>
                        <div class="mono">{html.escape(w.mac)}</div>
                        <div>{html.escape(w.vendor if w.vendor != 'Unknown' else 'Unknown vendor')}</div>
                        {extra}
                    </div>'''
                out += '</div></div>'
            return out

        # ===== FINDINGS =====
        findings = (topology or {}).get('findings') or []
        if findings:
            sev_style = {"critical": ("danger", "🔴"), "warning": ("warning", "🟠"),
                         "info": ("info", "🔵")}
            cards = ""
            for f in findings:
                cls, icon = sev_style.get(f.severity, ("info", "•"))
                ev = "".join(
                    f'<li class="mono">{html.escape(str(e))}</li>' for e in f.evidence
                )
                cards += f'''
                <div class="finding {cls}">
                    <div class="finding-head">{icon} <strong>{html.escape(f.title)}</strong>
                        <span class="badge {cls}">{html.escape(f.severity)}</span></div>
                    <p class="muted">{html.escape(f.detail)}</p>
                    {f'<ul class="evidence">{ev}</ul>' if ev else ''}
                </div>'''
            counts = Counter(f.severity for f in findings)
            solicited = Config.PASSIVE_DISCOVERY and Config.DISCOVERY_SOLICIT
            method = (
                "Derived from beacon frames the adapter had already received, this "
                "host's own neighbour table, and link-local mDNS/SSDP queries "
                "(TTL 1 — they cannot leave this subnet, and are the same traffic "
                "every phone on the network emits continuously)."
                if solicited else
                "Derived from beacon frames the adapter had already received and from "
                "this host's own neighbour table. Nothing was transmitted."
            )
            findings_html = f'''
        <h2>🛡️ Findings</h2>
        <p class="muted">{method}</p>
        <p class="muted">{counts.get('critical', 0)} critical ·
           {counts.get('warning', 0)} warning · {counts.get('info', 0)} informational</p>
        {cards}'''
        else:
            findings_html = ('<h2>🛡️ Findings</h2>'
                             '<p class="muted">Nothing flagged.</p>')

        # ===== SCOPE TRANSPARENCY =====
        # Shows what was enumerated versus what was actually probed, so the
        # basis for every claim on this page is visible rather than implied.
        interfaces = (topology or {}).get('interfaces') or []
        swept = {t.cidr for t in ((topology or {}).get('sweep_targets') or [])}
        if interfaces:
            rows = ""
            for i in interfaces:
                mark = ('<span class="badge ours">swept</span>' if i.network in swept
                        else '<span class="badge nearby">observed only</span>')
                rows += (f'<tr><td>{html.escape(i.alias)}</td>'
                         f'<td class="mono">{html.escape(i.ip)}/{i.prefix_length}</td>'
                         f'<td>{html.escape(i.kind)}</td>'
                         f'<td class="mono">{html.escape(i.network or "&mdash;")}</td>'
                         f'<td class="mono">{html.escape(i.gateway or "&mdash;")}</td>'
                         f'<td>{mark}</td></tr>')
            extra_swept = sorted(swept - {i.network for i in interfaces})
            for cidr in extra_swept:
                rows += (f'<tr><td colspan="3"><em>declared / routed</em></td>'
                         f'<td class="mono">{html.escape(cidr)}</td><td>&mdash;</td>'
                         f'<td><span class="badge ours">swept</span></td></tr>')
            iface_html = (
                '<table class="iface-table"><thead><tr>'
                '<th>Interface</th><th>Address</th><th>Kind</th><th>Network</th>'
                '<th>Gateway</th><th>Scope</th></tr></thead>'
                f'<tbody>{rows}</tbody></table>'
            )
        else:
            iface_html = '<p class="muted">Interface enumeration unavailable.</p>'

        def _own(w):
            net = by_bssid.get(w.mac)
            return net.ownership if net else getattr(w, 'ownership', 'foreign')

        ours_wifi = [w for w in wifi_devices if _own(w) == 'ours']
        near_wifi = [w for w in wifi_devices if _own(w) != 'ours']
        wifi_html = _render_wifi(ours_wifi, "No wireless networks attributable to this network.")
        nearby_wifi_html = _render_wifi(near_wifi, "No other wireless networks in range.")
        
        # ===== SECURITY NOTICE =====
        security_notice = f'''
        <div class="security-notice">
            <h3>🔒 SECURITY IMPORTANT</h3>
            <p>This file contains sensitive network information including:</p>
            <ul>
                <li>IP addresses and network topology</li>
                <li>MAC addresses and device vendors</li>
                <li>WiFi network information</li>
                <li>Network infrastructure details</li>
            </ul>
            <p><strong>Please secure this file:</strong></p>
            <ul>
                <li>Encrypt with tools like 7-Zip or VeraCrypt</li>
                <li>Store in secure location only</li>
                <li>Delete when no longer needed</li>
                <li>Share only with authorized personnel</li>
            </ul>
        </div>
        '''
        
        # ===== COMPLETE HTML DASHBOARD =====
        return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Network Intelligence Dashboard</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: {colors['bg']}; color: {colors['text']}; }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        .header {{ text-align: center; margin-bottom: 40px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 40px; }}
        .stat-card {{ background: {colors['card']}; padding: 20px; border-radius: 10px; text-align: center; border: 1px solid {colors['border']}; }}
        .stat-number {{ font-size: 2.5rem; font-weight: bold; color: {colors['primary']}; }}
        .subnet-section {{ background: {colors['card']}; padding: 20px; border-radius: 10px; margin-bottom: 30px; border: 1px solid {colors['border']}; }}
        .device-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 15px; margin-top: 15px; }}
        .device-card {{ background: {colors['border']}; padding: 15px; border-radius: 8px; }}
        .device-ip {{ font-family: monospace; color: {colors['primary']}; font-weight: bold; }}
        .device-type {{ color: {colors['success']}; }}
        .wireless {{ border-left: 4px solid {colors['purple']}; }}
        .wired {{ border-left: 4px solid {colors['primary']}; }}
        .gateway {{ border-left: 4px solid {colors['warning']}; }}
        h2 {{ color: {colors['primary']}; border-bottom: 2px solid {colors['border']}; padding-bottom: 10px; }}
        h3 {{ color: {colors['info']}; margin-top: 0; }}
        .topology-diagram {{ background: {colors['card']}; padding: 20px; border-radius: 10px; margin-top: 30px; border: 1px solid {colors['border']}; }}
        .download-btn {{ display: inline-block; background: linear-gradient(90deg, {colors['primary']}, {colors['purple']}); 
                       color: white; padding: 15px 30px; border-radius: 8px; text-decoration: none; font-weight: bold;
                       margin: 10px; transition: transform 0.3s; }}
        .download-btn:hover {{ transform: translateY(-3px); }}
        .footer {{ text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid {colors['border']}; 
                  color: {colors['secondary']}; }}
        .security-notice {{ 
            background: linear-gradient(135deg, {colors['danger']}20, {colors['warning']}20);
            border: 2px solid {colors['danger']};
            border-radius: 10px;
            padding: 20px;
            margin: 30px 0;
        }}
        .security-notice h3 {{ color: {colors['danger']}; }}
        .security-notice ul {{ margin: 10px 0 10px 20px; }}
        .ethical-guidelines {{
            background: {colors['card']};
            border: 1px solid {colors['info']};
            border-radius: 10px;
            padding: 20px;
            margin: 20px 0;
        }}
        .badge {{ font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.06em;
                 padding: 3px 8px; border-radius: 999px; vertical-align: middle;
                 margin-left: 8px; font-weight: 700; }}
        .badge.ours {{ background: {colors['success']}22; color: {colors['success']};
                      border: 1px solid {colors['success']}; }}
        .badge.nearby {{ background: {colors['secondary']}22; color: {colors['secondary']};
                        border: 1px solid {colors['secondary']}; }}
        .muted {{ color: {colors['secondary']}; font-size: 0.9rem; max-width: 70ch; }}
        .mono {{ font-family: ui-monospace, Consolas, monospace; font-size: 0.78rem;
                color: {colors['secondary']}; }}
        .meta {{ font-size: 0.75rem; color: {colors['secondary']}; margin-top: 2px; }}
        .meta.flags {{ color: {colors['warning']}; }}
        .radio-group {{ border: 1px solid {colors['border']}; border-radius: 10px;
                       padding: 14px; margin-bottom: 16px; background: {colors['card']}; }}
        .radio-head {{ color: {colors['info']}; font-size: 0.85rem; margin-bottom: 10px; }}
        .sig {{ height: 4px; background: {colors['border']}; border-radius: 2px;
               margin: 6px 0 2px; overflow: hidden; }}
        .sig span {{ display: block; height: 100%; background: {colors['purple']}; }}
        .iface-table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
        .iface-table th, .iface-table td {{ text-align: left; padding: 7px 10px;
                                           border-bottom: 1px solid {colors['border']}; }}
        .iface-table th {{ color: {colors['secondary']}; font-weight: 600; }}
        .finding {{ border: 1px solid {colors['border']}; border-left-width: 4px;
                   border-radius: 8px; padding: 14px 16px; margin-bottom: 12px;
                   background: {colors['card']}; }}
        .finding.danger {{ border-left-color: {colors['danger']}; }}
        .finding.warning {{ border-left-color: {colors['warning']}; }}
        .finding.info {{ border-left-color: {colors['info']}; }}
        .finding-head {{ display: flex; align-items: center; gap: 8px;
                        margin-bottom: 6px; flex-wrap: wrap; }}
        .badge.danger {{ background: {colors['danger']}22; color: {colors['danger']};
                        border: 1px solid {colors['danger']}; }}
        .badge.warning {{ background: {colors['warning']}22; color: {colors['warning']};
                         border: 1px solid {colors['warning']}; }}
        .badge.info {{ background: {colors['info']}22; color: {colors['info']};
                      border: 1px solid {colors['info']}; }}
        ul.evidence {{ margin: 8px 0 0 18px; padding: 0; }}
        ul.evidence li {{ margin: 2px 0; }}
        .banner {{ margin-top: 6px; padding: 4px 6px; border-radius: 4px;
                  background: {colors['bg']}; color: {colors['success']};
                  font-size: 0.72rem; word-break: break-word; }}
        .ports {{ display: flex; flex-wrap: wrap; gap: 4px; margin-top: 8px; }}
        .port {{ display: inline-flex; align-items: baseline; gap: 4px;
                padding: 2px 6px; border-radius: 4px; font-size: 0.7rem;
                font-family: ui-monospace, Consolas, monospace;
                background: {colors['bg']}; color: {colors['info']};
                border: 1px solid {colors['info']}55; cursor: help; }}
        .port em {{ font-style: normal; opacity: 0.65; font-size: 0.66rem; }}
        .port.risky {{ color: {colors['danger']};
                      border-color: {colors['danger']};
                      background: {colors['danger']}18; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Secure Network Intelligence Dashboard</h1>
            <p>Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Duration: {scan_duration:.1f} seconds</p>
        </div>
        
        {security_notice}
        
        <div class="ethical-guidelines">
            <h3>📋 Ethical Usage Guidelines</h3>
            <p>This tool should only be used on networks you own or have explicit permission to scan.</p>
            <p><strong>Remember:</strong> Unauthorized network scanning may violate laws and policies.</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">{sum(1 for d in lan_devices if getattr(d, 'ownership', 'ours') == 'ours')}</div>
                <div>Devices on our networks</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{len(subnets)}</div>
                <div>Subnets</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{len(ours_wifi)}</div>
                <div>Our BSSIDs</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{len(near_wifi)}</div>
                <div>Nearby BSSIDs</div>
            </div>
        </div>
        
        <div style="text-align: center; margin-bottom: 30px;">
            <a href="secure_network_diagram.drawio.xml" download class="download-btn">
                ⬇️ Download Hierarchical Diagram
            </a>
            <a href="secure_network_dashboard.html" download class="download-btn">
                📊 Download Dashboard
            </a>
        </div>
        
        {findings_html}

        <h2>🧭 Scan Scope</h2>
        <p class="muted">Networks are read from this host's live adapter and routing
        tables. Nothing here is inferred from address arithmetic, and no range is probed
        unless it appears in the swept column below.</p>
        <div class="topology-diagram">
        {iface_html}
        </div>

        <h2>📡 Network Topology Analysis</h2>
        <div class="topology-diagram">
            <p><strong>Detected Gateways:</strong> {', '.join(topology.get('gateways', ['None detected']))}</p>
            <p><strong>Network Structure:</strong> {len(subnets)} subnets with hierarchical routing</p>
            <p><strong>Wireless Infrastructure:</strong> {len(wifi_devices)} WiFi networks detected</p>
            <p><strong>Hierarchical Diagram:</strong> Open <code>secure_network_diagram.drawio.xml</code> with 
               <a href="https://app.diagrams.net/" target="_blank" style="color: {colors['warning']};">draw.io</a> for interactive editing</p>
        </div>
        
        <h2>🖥️ Devices by Subnet</h2>
        {subnet_html if subnet_html else '<p>No subnet data available</p>'}
        
        <h2>📶 Our Wireless</h2>
        <p class="muted">Access points attributable to this network &mdash; matched by
        association, or by sharing hardware with a device on one of our subnets.</p>
        {wifi_html}

        <h2>📡 Nearby Wireless <span class="badge nearby">not ours</span></h2>
        <p class="muted">Observed passively from beacon frames already collected by the
        wireless adapter. These networks were not scanned, probed, or contacted in any
        way, and nothing here is connected to our infrastructure.</p>
        {nearby_wifi_html}
        
        <div class="topology-diagram">
            <h3>🚀 Next Steps</h3>
            <p>1. Open the hierarchical diagram in <a href="https://app.diagrams.net/" target="_blank" style="color: {colors['warning']};">draw.io</a></p>
            <p>2. Analyze your network structure across multiple subnets</p>
            <p>3. Identify potential security issues (unknown devices, open access points)</p>
            <p>4. <strong>SECURE YOUR FILES:</strong> Encrypt output files before storage or sharing</p>
        </div>
        
        <div class="footer">
            <p>Secure Network Intelligence Mapper • {datetime.now().strftime('%Y-%m-%d')}</p>
            <p>All processing done locally • No data sent to external servers</p>
            <p>🔒 Files contain sensitive information - Secure them appropriately</p>
        </div>
    </div>
</body>
</html>'''

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


# ==================== MAIN APPLICATION ====================
def main_enhanced(args):
    """
    ENHANCED MAIN APPLICATION WITH SECURITY FEATURES
    
    This is the primary scanning workflow that:
    1. Performs LAN scanning
    2. Performs WiFi scanning
    3. Analyzes network topology
    4. Generates diagrams and dashboards
    5. Creates security-conscious output files
    """
    try:
        print("\n" + "="*80)
        print("🔒 SECURE NETWORK INTELLIGENCE MAPPER PRO")
        print("="*80)
        print("Features: Secure scanning • Input validation • Rate limiting")
        print("-"*80)
        
        # Show ethical guidelines if enabled
        if Config.SHOW_ETHICAL_GUIDELINES:
            LegalDisclaimer.show_ethical_guidelines()
        
        start_time = datetime.now()
        
        # Initialize secure scanner
        scanner = SecureNetworkScanner()
        
        # ===== STEP 1: SCAN NETWORK =====
        print("\n[1/3] Secure network scanning...")
        lan_devices = []
        if args.mode in ["all", "lan"]:
            lan_devices = scanner.scan_lan_enhanced()
        
        # ===== STEP 2: SCAN WiFi =====
        print("\n[2/3] Passive wireless survey...")
        wifi_networks: List[WifiNetwork] = []
        wifi_devices: List[NetworkDevice] = []
        if args.mode in ["all", "wifi"]:
            # Hand the classifier every MAC we can justify calling ours, so a
            # device of ours that also broadcasts its own SSID is recognised
            # rather than reported as a stranger.
            wifi_networks = SecureWiFiScanner.scan_wifi(
                our_macs=scanner.our_known_macs(lan_devices)
            )
            wifi_devices = [n.to_device() for n in wifi_networks]
            radios = SecureWiFiScanner.group_by_radio(wifi_networks)
            ours_n = sum(1 for n in wifi_networks if n.ownership == "ours")
            print(f"    {len(wifi_networks)} BSSIDs across {len(radios)} physical radios "
                  f"({ours_n} ours, {len(wifi_networks) - ours_n} nearby)")

        # ===== STEP 3: ANALYZE TOPOLOGY =====
        print("\n[3/3] Analyzing network topology...")
        topology = scanner.infer_network_topology(lan_devices)
        topology['wifi'] = wifi_networks
        topology['interfaces'] = scanner.interfaces
        topology['sweep_targets'] = scanner.sweep_targets

        # ===== STEP 3a: ANNOUNCEMENT LISTENING =====
        if Config.PASSIVE_DISCOVERY and args.mode in ("all", "lan"):
            print("\n📻 Listening for device announcements...")
            announced = PassiveDiscovery.collect(
                scanner.interfaces,
                duration=Config.DISCOVERY_DURATION,
                active=Config.DISCOVERY_SOLICIT,
                on_log=print,
            )
            enriched = PassiveDiscovery.apply(lan_devices, announced)
            print(f"    {len(announced)} host(s) announced, {enriched} device(s) enriched")

            # Announcements can reveal hosts the neighbour table missed.
            known = {d.ip for d in lan_devices}
            attached_nets = [i.network for i in scanner.interfaces if i.network]
            for ip, info in announced.items():
                if ip in known or ip in scanner._own_addresses:
                    continue
                dev = NetworkDevice(ip=ip, network_type="lan")
                dev.hostname = sorted(info["names"])[0] if info["names"] else ""
                dev.services = sorted(info["services"])
                dev.discovered_via = "announcement"
                dev.ownership = scanner._classify_ownership(ip, attached_nets)
                lan_devices.append(dev)
                print(f"    + {ip} found via announcement only")

            # ONVIF / WS-Discovery: cameras and NVRs answer here and nowhere else.
            onvif = WSDiscovery.probe(scanner.interfaces, duration=6.0, on_log=print)
            if onvif:
                WSDiscovery.apply(lan_devices, onvif)
                known = {d.ip for d in lan_devices}
                for ip, info in onvif.items():
                    if ip in known or ip in scanner._own_addresses:
                        continue
                    dev = NetworkDevice(ip=ip, network_type="lan")
                    dev.hostname = info.get("name") or info.get("hardware") or ""
                    dev.discovered_via = "ws-discovery"
                    dev.ownership = scanner._classify_ownership(ip, attached_nets)
                    lan_devices.append(dev)
                print(f"    {len(onvif)} WS-Discovery responder(s)")

        # ===== STEP 3b: SERVICE PROBING =====
        # Its own phase, deliberately outside the announcement-listening block
        # above: probing used to be nested inside it, so --no-discovery
        # silently disabled port probing too. They are separate decisions.
        #
        # The baseline is loaded before this rather than after, because
        # select='new' and the 'known'/'new' network names are answered from
        # it. Nothing else about the ordering changed.
        baseline = load_baseline(args)

        if not Config.IDENTIFY_SILENT and args.mode in ("all", "lan"):
            # Say so rather than skipping in silence. A depth setting with no
            # probe behind it is the single easiest thing to misread as "the
            # deep scan ran and found nothing".
            print(f"\n🔌 Service probing: OFF (depth would be "
                  f"{Config.PROBE_DEPTH}). Enable with --identify-silent.")

        if Config.IDENTIFY_SILENT and args.mode in ("all", "lan"):
            print("\n🔌 Probing for open service ports...")
            nets = ServiceProbe.resolve_nets(
                Config.PROBE_NETS,
                interfaces=scanner.interfaces,
                sweep_targets=scanner.sweep_targets,
                baseline=baseline,
                on_log=print,
            )
            if Config.PROBE_NETS and not nets:
                print("    ! No networks matched --probe-net; nothing probed.")
            else:
                found = ServiceProbe.identify(
                    lan_devices,
                    on_log=print,
                    nets=nets or None,
                    baseline=baseline,
                    allow_foreign=getattr(args, "i_have_permission", False),
                )
                print(f"    {found} device(s) answered on at least one port")

        # ===== STEP 3c: PASSIVE THREAT ANALYSIS =====
        findings = ThreatAnalyzer.analyze(lan_devices, wifi_networks,
                                          scanner.interfaces, baseline)
        findings += ChannelAnalyzer.findings(
            wifi_networks, (baseline or {}).get("wifi_networks"))
        findings += ServiceProbe.findings(lan_devices)
        if Config.USE_WATCHLIST:
            findings += VendorWatchlist.check(lan_devices)
            findings.sort(key=lambda f: ({"critical": 0, "warning": 1,
                                          "info": 2}.get(f.severity, 3), f.category))
        topology['findings'] = findings
        if findings:
            crit = sum(1 for f in findings if f.severity == "critical")
            warn = sum(1 for f in findings if f.severity == "warning")
            print(f"\n🛡️  {len(findings)} finding(s): {crit} critical, {warn} warning")
            for f in findings:
                if f.severity in ("critical", "warning"):
                    print(f"    [{f.severity.upper()}] {f.title}")

        scan_duration = (datetime.now() - start_time).total_seconds()
        
        # ===== STEP 4: GENERATE SECURE DIAGRAM =====
        print("\n🎨 Generating secure diagram...")
        diagram_xml = EnhancedDiagramGenerator.generate_hierarchical_diagram(
            lan_devices, wifi_devices, topology
        )
        
        with open("secure_network_diagram.drawio.xml", "w", encoding="utf-8") as f:
            f.write(diagram_xml)
        print("   ✓ Saved: secure_network_diagram.drawio.xml")
        
        # ===== STEP 5: GENERATE SECURE DASHBOARD =====
        print("📊 Creating secure dashboard...")
        dashboard_html = SecureDashboard.generate_dashboard(
            lan_devices, wifi_devices, scan_duration, topology
        )
        
        with open("secure_network_dashboard.html", "w", encoding="utf-8") as f:
            f.write(dashboard_html)
        print("   ✓ Saved: secure_network_dashboard.html")

        # Record this scan so the next one can report what changed.
        save_baseline(args, lan_devices, wifi_networks)
        
        # ===== STEP 6: CREATE SECURE LAUNCHER (Windows batch file) =====
        with open("launch_secure.bat", "w", encoding="utf-8-sig") as f:
            f.write('''@echo off
chcp 65001 > nul
echo.
echo ===============================================
echo   SECURE NETWORK MAPPER LAUNCHER
echo ===============================================
echo.
echo Opening Secure Dashboard...
start "" "secure_network_dashboard.html"
echo.
echo ⚠️  SECURITY NOTICE:
echo   These files contain sensitive network information!
echo   Encrypt them before storage or sharing.
echo.
echo Files generated:
echo   - secure_network_diagram.drawio.xml - Hierarchical diagram
echo   - secure_network_dashboard.html - Secure dashboard
echo   - launch_secure.bat - This launcher
echo.
echo Open the .XML file with draw.io for interactive editing.
echo.
echo 🔒 SECURE YOUR FILES!
pause''')
        print("   ✓ Saved: launch_secure.bat")
        
        # ===== STEP 7: DISPLAY RESULTS SUMMARY =====
        print("\n" + "="*80)
        print("✅ SECURE SCAN COMPLETE!")
        print("="*80)
        
        # Group devices by subnet for summary
        subnets = defaultdict(list)
        for device in lan_devices:
            if device.subnet:
                subnets[device.subnet].append(device)
        
        print(f"\n📊 SECURE RESULTS:")
        print(f"  • Scan Time: {scan_duration:.1f} seconds")
        print(f"  • Total Devices: {len(lan_devices)}")
        print(f"  • Subnets Detected: {len(subnets)}")
        
        # Show subnet breakdown
        for subnet, devices in subnets.items():
            wireless = sum(1 for d in devices if 'wireless' in d.tags)
            gateways = sum(1 for d in devices if d.is_gateway)
            print(f"  • {subnet}: {len(devices)} devices ({wireless} wireless, {gateways} gateways)")
        
        print(f"  • WiFi Networks: {len(wifi_devices)}")
        
        if topology.get('gateways'):
            print(f"  • Gateways: {', '.join(topology['gateways'])}")
        
        print(f"\n📁 FILES CREATED (⚠️ Contains sensitive info):")
        print(f"  • secure_network_diagram.drawio.xml - Secure hierarchical diagram")
        print(f"  • secure_network_dashboard.html - Secure dashboard with warnings")
        print(f"  • launch_secure.bat - Launcher with security notice")
        
        print(f"\n🔒 SECURITY REMINDER:")
        print(f"  ⚠️  These files contain sensitive network information")
        print(f"  🔐 Encrypt files before storage or sharing")
        print(f"  🗑️  Delete when no longer needed")
        print(f"  👥 Share only with authorized personnel")
        
        print(f"\n🚀 QUICK START:")
        print(f"  1. Run 'launch_secure.bat'")
        print(f"  2. Open the secure diagram in draw.io")
        print(f"  3. 🔐 ENCRYPT YOUR FILES!")
        
        # Auto-open dashboard if configured
        if Config.AUTO_OPEN and not args.no_open:
            print(f"\n🔄 Opening secure dashboard...")
            dashboard_path = os.path.abspath("secure_network_dashboard.html")
            file_url = "file:///" + dashboard_path.replace('\\', '/')
            webbrowser.open(file_url)
            
    except Exception as e:
        print(f"\n❌ Error in secure scan: {e}")
        import traceback
        traceback.print_exc()

def main_original(args):
    """
    ORIGINAL MAIN FUNCTION WITH SECURITY IMPROVEMENTS
    
    Simplified version of the main workflow with basic scanning
    and compatibility-focused output.
    """
    try:
        print("\n" + "="*80)
        print("🔒 ORIGINAL NETWORK INTELLIGENCE MAPPER (Secure)")
        print("="*80)
        
        # Show ethical guidelines if enabled
        if Config.SHOW_ETHICAL_GUIDELINES:
            LegalDisclaimer.show_ethical_guidelines()
        
        start_time = datetime.now()
        
        # Use the secure scanner
        scanner = SecureNetworkScanner()
        print("\n[1/2] Secure LAN scanning...")
        lan_devices = scanner.scan_lan_enhanced()
        
        print("\n[2/2] Secure WiFi scanning...")
        wifi_networks = SecureWiFiScanner.scan_wifi(
            our_macs=scanner.our_known_macs(lan_devices)
        )
        wifi_devices = [n.to_device() for n in wifi_networks]

        scan_duration = (datetime.now() - start_time).total_seconds()

        # Build a real topology rather than handing the renderers an empty one.
        # Passing {'gateways': [], 'subnets': {}, ...} meant this mode produced a
        # diagram with no gateway, no subnet grouping and no wireless section.
        topology = scanner.infer_network_topology(lan_devices)
        topology['wifi'] = wifi_networks
        topology['interfaces'] = scanner.interfaces
        topology['sweep_targets'] = scanner.sweep_targets

        # Generate outputs using original format
        print("\n🎨 Generating secure outputs...")

        # Generate diagram
        print("[1/3] Creating secure network diagram...")
        diagram_xml = EnhancedDiagramGenerator.generate_hierarchical_diagram(
            lan_devices, wifi_devices, topology
        )
        with open("network_diagram.drawio.xml", "w", encoding="utf-8") as f:
            f.write(diagram_xml)
        print("   ✓ Saved: network_diagram.drawio.xml")

        # Generate the dashboard the launcher below actually opens.
        # This step was numbered "[3/3]" in the output but never implemented, so
        # open_dashboard.bat has always pointed at a file that did not exist.
        print("[2/3] Creating dashboard...")
        dashboard_html = SecureDashboard.generate_dashboard(
            lan_devices, wifi_devices, scan_duration, topology
        )
        with open("network_dashboard.html", "w", encoding="utf-8") as f:
            f.write(dashboard_html)
        print("   ✓ Saved: network_dashboard.html")

        # Create secure launcher
        print("[3/3] Creating secure launcher...")
        with open("open_dashboard.bat", "w", encoding="utf-8-sig") as f:
            f.write('''@echo off
chcp 65001 > nul
echo.
echo ===============================================
echo   SECURE NETWORK MAPPER
echo ===============================================
echo.
echo ⚠️  SECURITY NOTICE: Files contain sensitive info!
echo.
echo Opening Network Dashboard...
start "" "network_dashboard.html"
echo.
echo Files generated:
echo   - network_dashboard.html - Interactive dashboard
echo   - network_diagram.drawio.xml - Network diagram
echo   - open_dashboard.bat - This launcher
echo.
echo 🔒 Encrypt files before storage or sharing!
echo.
pause''')
        print("   ✓ Saved: open_dashboard.bat")
        
        print("\n" + "="*80)
        print("✅ SECURE SCAN COMPLETE!")
        print("="*80)
        print(f"\n📊 RESULTS:")
        print(f"  • Scan Time: {scan_duration:.1f} seconds")
        print(f"  • LAN Devices: {len(lan_devices)}")
        print(f"  • WiFi Networks: {len(wifi_devices)}")
        
        print(f"\n🔒 SECURITY REMINDER:")
        print(f"  ⚠️  Output files contain sensitive network information")
        print(f"  🔐 Encrypt files before storage or sharing")
        
        print(f"\n🚀 QUICK START:")
        print(f"  1. Run 'open_dashboard.bat'")
        print(f"  2. 🔐 Encrypt output files")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


PROBE_RESULTS_FILE = "probe_results.json"


def main_probe_only(args):
    """
    STANDALONE TARGETED PROBE

    Skips enumeration, sweeping and announcement listening entirely and goes
    straight at the addresses named on the command line. This is the mode for
    "what is 192.168.2.31 actually running" — re-checking one device should
    not cost a full LAN scan first.

    Interfaces are still enumerated, for exactly one reason: to decide whether
    the named targets fall inside a network this host is attached to. Probing
    addresses that do not is a materially different act, and it needs
    --i-have-permission the same way --scope wide does.

    No dashboard or diagram is written. A topology picture of three addresses
    is not worth generating; the console report and probe_results.json are.
    """
    try:
        print("\n" + "=" * 80)
        print("🔌 TARGETED SERVICE PROBE")
        print("=" * 80)

        start_time = datetime.now()

        targets = ServiceProbe.expand_targets(args.probe_only, on_log=print)
        if not targets:
            print("\n❌ No usable targets. Nothing to do.")
            return

        # Which of these are on a network we are attached to?
        interfaces = LocalNetworkEnumerator.enumerate()
        attached_nets = [i.network for i in interfaces if i.network]
        own_addresses = {i.ip for i in interfaces if i.ip}

        ours, foreign = [], []
        for ip in targets:
            if ip in own_addresses:
                continue  # probing ourselves proves nothing
            (ours if SecureNetworkScanner._classify_ownership(ip, attached_nets) == "ours"
             else foreign).append(ip)

        if foreign and not args.i_have_permission:
            print(f"\n  {len(foreign)} of {len(targets)} target(s) are not on any "
                  f"network this host is attached to:")
            for ip in sorted(foreign, key=_ip_sort_key)[:10]:
                print(f"    {ip}")
            if len(foreign) > 10:
                print(f"    ... and {len(foreign) - 10} more")
            print("\n  Re-run with --i-have-permission if you have authority over "
                  "them.")
            print("  To probe only the targets on your own networks, name those "
                  "instead.\n")
            sys.exit(2)

        probe_list = ours + (foreign if args.i_have_permission else [])
        if not probe_list:
            print("\n❌ Every target was this host's own address. Nothing to do.")
            return

        depth = Config.PROBE_DEPTH
        ports = ServiceProbe.ports_for(depth)
        print(f"\n  Targets:  {len(probe_list)} address(es)"
              + (f"  ({len(foreign)} off-network, permitted)" if foreign else ""))
        print(f"  Depth:    {depth} — {len(ports)} port(s) each")
        print(f"  Banners:  {'yes' if Config.PROBE_BANNERS else 'no'}")
        print(f"  Sockets:  {Config.PROBE_MAX_SOCKETS} concurrent")
        print(f"  Total:    {len(probe_list) * len(ports):,} connects\n")

        last_pct = [-1]

        def on_progress(stage, done, total):
            if not total:
                return
            pct = int(done * 100 / total)
            if pct != last_pct[0] and pct % 5 == 0:
                last_pct[0] = pct
                print(f"    {pct:3d}%  ({done:,}/{total:,})")

        results = ServiceProbe.scan_targets(probe_list, ports=ports,
                                            on_log=print, on_progress=on_progress)

        # Build devices so the same enrichment, findings and watchlist code
        # applies here as in a full scan.
        neighbours = {}
        try:
            scanner = SecureNetworkScanner()
            for dev in scanner.scan_neighbors(interfaces):
                neighbours[dev.ip] = dev
        except Exception:
            pass

        devices = []
        for ip in probe_list:
            known = neighbours.get(ip)
            dev = NetworkDevice(ip=ip, network_type="lan",
                                mac=known.mac if known else "")
            dev.discovered_via = "probe"
            dev.ownership = SecureNetworkScanner._classify_ownership(ip, attached_nets)
            if known:
                dev.subnet = known.subnet
                dev.interface = known.interface
                dev.neighbor_state = known.neighbor_state
            if Config.SHOW_VENDOR_INFO and dev.mac:
                dev.vendor = VendorDatabase.lookup(dev.mac)
            if Config.RESOLVE_HOSTNAMES:
                try:
                    dev.hostname = socket.gethostbyaddr(ip)[0]
                except Exception:
                    pass
            devices.append(dev)

        answered = ServiceProbe.apply_results(devices, results)
        duration = (datetime.now() - start_time).total_seconds()

        # ===== REPORT =====
        print("\n" + "=" * 80)
        print(f"✅ PROBE COMPLETE — {duration:.1f}s")
        print("=" * 80)
        print(f"\n  {answered} of {len(probe_list)} target(s) answered on at "
              f"least one port\n")

        for dev in sorted(devices, key=lambda d: _ip_sort_key(d.ip)):
            if not dev.ports_open:
                continue
            head = f"  {dev.ip}"
            if dev.hostname:
                head += f"  {dev.hostname}"
            if dev.vendor and dev.vendor != "Unknown":
                head += f"  [{dev.vendor}]"
            if dev.device_type not in ("unknown", ""):
                head += f"  → {dev.device_type}"
            print(head)
            res = results.get(dev.ip, {})
            for port in dev.ports_open:
                label = ServiceProbe.label_for(port)
                meaning = (ServiceProbe.PORTS.get(port)
                           or ServiceProbe.EXTRA_LABELS.get(port) or ("", ""))[1]
                line = f"      {port:>5}/tcp  {label:<16}"
                banner = (res.get("banners") or {}).get(port)
                if banner:
                    line += f"  {banner[:70]}"
                elif meaning:
                    line += f"  {meaning}"
                print(line)
            print()

        silent = [d.ip for d in devices if not d.ports_open]
        if silent:
            print(f"  {len(silent)} target(s) answered nothing: "
                  f"{', '.join(sorted(silent, key=_ip_sort_key)[:8])}"
                  + (" ..." if len(silent) > 8 else ""))
            print()

        # ===== FINDINGS =====
        findings = ServiceProbe.findings(devices)
        if Config.USE_WATCHLIST:
            findings += VendorWatchlist.check(devices)
        if findings:
            order = {"critical": 0, "warning": 1, "info": 2}
            findings.sort(key=lambda f: (order.get(f.severity, 3), f.category))
            print("🛡️  FINDINGS")
            for f in findings:
                print(f"\n  [{f.severity.upper()}] {f.title}")
                print(f"    {f.detail}")
                for line in f.evidence:
                    print(f"      {line}")
            print()

        # ===== ARTIFACT =====
        payload = {
            "captured": start_time.isoformat(timespec="seconds"),
            "duration_seconds": round(duration, 2),
            "depth": depth,
            "ports_per_host": len(ports),
            "banners": Config.PROBE_BANNERS,
            "targets": probe_list,
            "devices": [
                {
                    "ip": d.ip, "mac": d.mac, "hostname": d.hostname,
                    "vendor": d.vendor, "device_type": d.device_type,
                    "ownership": d.ownership, "model": d.model,
                    "ports_open": d.ports_open,
                    "services": d.services,
                    "banners": {str(p): t for p, t
                                in (results.get(d.ip, {}).get("banners") or {}).items()},
                }
                for d in sorted(devices, key=lambda d: _ip_sort_key(d.ip))
            ],
            "findings": [f.to_dict() for f in findings],
        }
        try:
            Path(PROBE_RESULTS_FILE).write_text(
                json.dumps(payload, indent=2), encoding="utf-8")
            print(f"📁 Saved: {PROBE_RESULTS_FILE}")
        except OSError as exc:
            print(f"  ! Could not write {PROBE_RESULTS_FILE}: {exc}")

        print("\n🔒 This file lists open ports on your devices. Secure it.\n")

    except KeyboardInterrupt:
        print("\n\n  Interrupted.")
    except Exception as e:
        print(f"\n❌ Error in targeted probe: {e}")
        import traceback
        traceback.print_exc()


def parse_arguments():
    """
    PARSE COMMAND LINE ARGUMENTS
    
    Provides flexible command-line interface with options for:
    - Scan mode selection
    - Security warning control
    - Rate limiting adjustment
    - Legal information display
    """
    parser = argparse.ArgumentParser(
        description='Secure Network Intelligence Mapper Pro',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s --enhanced          # Run enhanced scan with security
  %(prog)s --original          # Run original scan with security
  %(prog)s --no-warning        # Skip legal warning
  %(prog)s --mode lan          # Scan only LAN devices
  %(prog)s --mode wifi         # Scan only WiFi networks
  %(prog)s --legal-info        # Display legal information

Service probing:
  # deeper probe as a phase of a normal scan
  %(prog)s --enhanced --identify-silent --probe-depth deep

  # restrict it to one network, or to networks by name
  %(prog)s --enhanced --identify-silent --probe-net 192.168.2.0/24
  %(prog)s --enhanced --identify-silent --probe-net attached --probe-net new

  # probe everything found, not just the silent devices, and read banners
  %(prog)s --enhanced --identify-silent --probe-select all --probe-banners

  # standalone: no enumeration, no sweep, straight at the targets
  %(prog)s --probe-only 192.168.2.31 --probe-depth full --probe-banners
  %(prog)s --probe-only 192.168.2.10-40 --probe-depth deep
  %(prog)s --probe-only 192.168.2.0/24 --probe-depth quick
        '''
    )
    
    parser.add_argument('--enhanced', action='store_true', 
                       help='Run enhanced scan with security improvements')
    parser.add_argument('--original', action='store_true',
                       help='Run original scan with security improvements')
    parser.add_argument('--mode', choices=['all', 'lan', 'wifi'], default='all',
                       help='Scan mode: all (default), lan, or wifi')
    parser.add_argument('--warning', action='store_true', default=True,
                       help='Show legal warning (default: True)')
    parser.add_argument('--no-warning', action='store_true',
                       help='Skip legal warning')
    parser.add_argument('--legal-info', action='store_true',
                       help='Display legal information and exit')
    parser.add_argument('--no-open', action='store_true',
                       help='Do not auto-open dashboard')
    parser.add_argument('--rate-limit', type=float, default=0.01,
                       help='Rate limit delay between probes (default: 0.01)')

    scope = parser.add_argument_group('scope: which networks are eligible to sweep')
    scope.add_argument('--scope', choices=['attached', 'routed', 'wide'],
                       default='attached',
                       help='attached: only networks this host holds an address on '
                            '(default). routed: also networks reachable via a router. '
                            'wide: also adjacent ranges that are almost certainly '
                            "someone else's — requires --i-have-permission.")
    scope.add_argument('--extra-subnet', action='append', default=[], metavar='CIDR',
                       help='Additional CIDR you own but have no interface on. '
                            'Repeatable.')
    scope.add_argument('--include-virtual', action='store_true',
                       help='Also sweep Hyper-V / WSL / VMware host networks')
    scope.add_argument('--include-vpn', action='store_true',
                       help='Also sweep VPN / overlay networks (Tailscale, etc.)')
    scope.add_argument('--max-sweep-hosts', type=int, default=Config.MAX_SWEEP_HOSTS,
                       help=f'Refuse to sweep a network larger than this '
                            f'(default: {Config.MAX_SWEEP_HOSTS})')
    scope.add_argument('--i-have-permission', action='store_true',
                       help='Required acknowledgement for --scope wide, which probes '
                            'addresses outside your own networks. Only use this where '
                            'you have authority over the ranges concerned.')

    parser.add_argument('--oui-file', metavar='PATH',
                       help='IEEE oui.csv (or AABBCC<sep>Vendor text) to replace the '
                            'small built-in vendor table')
    parser.add_argument('--baseline', metavar='PATH',
                       help=f'Baseline file for change detection '
                            f'(default: {BASELINE_FILE})')
    parser.add_argument('--no-baseline', action='store_true',
                       help='Do not read or write the change-detection baseline')
    parser.add_argument('--reset', action='store_true',
                       help='Forget every previous scan: delete the baseline and '
                            'the saved probe results, then continue. The next scan '
                            'treats every device as newly seen. Note this only '
                            'affects change detection — a scan never hides a device '
                            'because a previous scan already found it.')

    disc = parser.add_argument_group('announcement listening')
    disc.add_argument('--no-discovery', action='store_true',
                      help='Skip mDNS/SSDP announcement listening')
    disc.add_argument('--discovery-time', type=float,
                      default=Config.DISCOVERY_DURATION, metavar='SECONDS',
                      help=f'How long to listen (default: {Config.DISCOVERY_DURATION})')
    disc.add_argument('--listen-only', action='store_true',
                      help='Never transmit: join the multicast groups and wait for '
                           'unsolicited announcements. Note that a host firewall '
                           'usually drops these, so this often finds nothing.')
    disc.add_argument('--identify-silent', action='store_true',
                      help='Probe devices that answered no announcement protocol for '
                           'open management ports. Only touches your own devices; '
                           'connects and closes without sending data or credentials.')
    disc.add_argument('--no-watchlist', action='store_true',
                      help='Do not apply the vendor/service watchlist')
    disc.add_argument('--write-watchlist', action='store_true',
                      help='Write the default watchlist rules to a JSON file and exit')

    probe = parser.add_argument_group(
        'service probing (TCP connect — the most intrusive thing here)')
    probe.add_argument('--probe-only', action='append', default=[], metavar='SPEC',
                       help='Standalone targeted probe: skip enumeration, sweeping '
                            'and announcement listening, and probe these addresses '
                            'directly. Accepts 192.168.2.31, 192.168.2.0/24, '
                            '192.168.2.10-40, or 192.168.2.10-192.168.2.40. '
                            'Repeatable. Targets outside your own networks require '
                            '--i-have-permission.')
    probe.add_argument('--probe-depth', choices=list(ServiceProbe.DEPTHS),
                       default=Config.PROBE_DEPTH,
                       help='How many ports to try per host: quick (10), standard '
                            '(16, the default), deep (315), full (1270), exhaustive '
                            '(all 65535). Tiers are cumulative. "exhaustive" needs '
                            '--i-have-permission — it takes minutes per host and is '
                            'unmistakable in a firewall log.')
    probe.add_argument('--probe-banners', action='store_true',
                       help='Read what each open service says for itself (SSH version, '
                            'HTTP Server header, RTSP greeting). Most services greet '
                            'first and this sends nothing; on HTTP ports only, it '
                            'sends one "HEAD / HTTP/1.0". No credentials, ever.')
    probe.add_argument('--probe-select',
                       choices=['silent', 'unidentified', 'new', 'all'],
                       default=Config.PROBE_SELECT,
                       help='Which discovered devices to probe: silent (announced '
                            'nothing at all — the default), unidentified (also those '
                            'still typed unknown/generic), new (absent from the '
                            'baseline), all.')
    probe.add_argument('--probe-net', action='append', default=[],
                       metavar='CIDR|NAME',
                       help='Restrict probing to these networks. Accepts a CIDR or '
                            'one of: attached, routed, known (seen in a previous '
                            'scan), new (enumerated now but not in the baseline), '
                            'all. Repeatable. Default: every enumerated network.')
    probe.add_argument('--probe-timeout', type=float,
                       default=Config.PROBE_CONNECT_TIMEOUT, metavar='SECONDS',
                       help=f'TCP handshake timeout per port '
                            f'(default: {Config.PROBE_CONNECT_TIMEOUT})')
    probe.add_argument('--probe-sockets', type=int,
                       default=Config.PROBE_MAX_SOCKETS, metavar='N',
                       help=f'Concurrent connects in flight across all hosts. This is '
                            f'the throttle for this phase — the global rate limit is '
                            f'not applied to it (default: {Config.PROBE_MAX_SOCKETS})')

    return parser.parse_args()

def display_legal_info():
    """
    DISPLAY COMPREHENSIVE LEGAL INFORMATION
    
    Shows detailed legal and ethical guidelines before
    users proceed with network scanning.
    """
    legal_text = '''
    ⚠️  LEGAL AND ETHICAL INFORMATION
    
    NETWORK INTELLIGENCE MAPPER PRO - SECURE VERSION
    
    PURPOSE:
    This tool is designed for legitimate network administration, troubleshooting,
    and visualization purposes ONLY.
    
    LEGAL REQUIREMENTS:
    1. Only scan networks you own or have explicit written permission to scan
    2. Unauthorized network scanning may violate:
       - Computer Fraud and Abuse Act (CFAA)
       - State computer crime laws
       - Network Terms of Service
       - Privacy laws
    
    INTENDED USERS:
    - Network administrators
    - IT professionals with network access rights
    - Security professionals with authorization
    - Educational institutions in lab environments
    
    ETHICAL GUIDELINES:
    1. Always obtain permission before scanning
    2. Respect network usage policies
    3. Secure generated files (they contain sensitive information)
    4. Delete scans when no longer needed
    5. Be transparent about scanning activities
    
    SECURITY FEATURES IN THIS VERSION:
    - Input validation to prevent command injection
    - Rate limiting to prevent network flooding
    - Security warnings in output files
    - Ethical usage reminders
    - Skip multicast/broadcast addresses by default
    
    DISCLAIMER:
    The developers assume no liability for misuse of this tool.
    Users are solely responsible for complying with applicable laws.
    
    By using this tool, you acknowledge understanding and acceptance
    of these terms.
    '''
    
    print(legal_text)
    sys.exit(0)

# ==================== MAIN ENTRY POINT ====================
if __name__ == "__main__":
    """
    MAIN ENTRY POINT FOR THE APPLICATION
    
    Handles command-line arguments, displays legal information if requested,
    shows ethical guidelines, and launches the appropriate scanning mode.
    
    WORKFLOW:
    1. Parse command line arguments
    2. Display legal info if requested
    3. Configure settings based on arguments
    4. Show legal warning (if required)
    5. Run selected scanning mode
    """
    # The banners and status lines throughout this script use emoji. On Windows
    # the console defaults to cp1252, which cannot encode them, so running the
    # script directly aborted on its very first print with a UnicodeEncodeError
    # — and then again inside the exception handler, which also prints emoji.
    # It only appeared to work under the web wrapper because that sets
    # PYTHONIOENCODING=utf-8 for the child process.
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass  # already wrapped, or not a real stream

    # Parse command line arguments
    args = parse_arguments()
    
    # Handle legal info request
    if args.legal_info:
        display_legal_info()
    
    # Configure based on arguments
    if args.no_warning:
        Config.LEGAL_WARNING_REQUIRED = False
    if args.rate_limit:
        Config.RATE_LIMIT_DELAY = args.rate_limit

    if args.write_watchlist:
        path = VendorWatchlist.write_default()
        print(f"  Wrote default watchlist rules to {path}")
        sys.exit(0)

    # --reset clears remembered state, then the run continues normally.
    # Deliberately not a mode of its own: "start clean and scan" is one
    # intention, and making it two commands invites doing only the first.
    if args.reset:
        removed = []
        for path in (Path(args.baseline or BASELINE_FILE), Path(PROBE_RESULTS_FILE)):
            try:
                if path.exists():
                    path.unlink()
                    removed.append(str(path))
            except OSError as exc:
                print(f"  ! Could not remove {path}: {exc}")
        if removed:
            print(f"  Reset: removed {', '.join(removed)}")
        else:
            print("  Reset: nothing to remove, already clean")
        print("  Every device will be reported as newly seen this run.")

    Config.SCAN_MODE = args.mode
    Config.SCAN_SCOPE = args.scope
    Config.PASSIVE_DISCOVERY = not args.no_discovery
    Config.DISCOVERY_DURATION = max(1.0, args.discovery_time)
    Config.DISCOVERY_SOLICIT = not args.listen_only
    Config.USE_WATCHLIST = not args.no_watchlist
    Config.IDENTIFY_SILENT = args.identify_silent
    Config.EXTRA_SUBNETS = list(args.extra_subnet or [])
    Config.SCAN_VIRTUAL_ADAPTERS = args.include_virtual
    Config.SCAN_VPN_ADAPTERS = args.include_vpn
    Config.MAX_SWEEP_HOSTS = args.max_sweep_hosts

    Config.PROBE_DEPTH = args.probe_depth
    Config.PROBE_BANNERS = args.probe_banners
    Config.PROBE_SELECT = args.probe_select
    Config.PROBE_NETS = list(args.probe_net or [])
    Config.PROBE_TARGETS = list(args.probe_only or [])
    Config.PROBE_CONNECT_TIMEOUT = max(0.05, args.probe_timeout)
    Config.PROBE_MAX_SOCKETS = max(1, min(1024, args.probe_sockets))

    # Naming any probe option is a statement of intent, so honour it rather
    # than making the operator also remember --identify-silent. The flag stays
    # meaningful as the way to turn probing on at default depth.
    if args.probe_depth != 'standard' or args.probe_banners or args.probe_net \
            or args.probe_select != 'silent':
        Config.IDENTIFY_SILENT = True

    # --scope wide probes addresses that are not on any network this host is
    # attached to. That is a materially different act from mapping your own
    # LAN, so it needs an explicit acknowledgement rather than a quiet default.
    if args.scope == 'wide' and not args.i_have_permission:
        print("\n  --scope wide probes ranges outside your own networks.")
        print("  Re-run with --i-have-permission if you have authority over them.")
        print("  To map only your own networks, use --scope attached (the default).\n")
        sys.exit(2)

    # An exhaustive probe is 65535 connects per host — minutes each, and the
    # single most conspicuous thing this tool can do. Same gate, same reason.
    if args.probe_depth == 'exhaustive' and not args.i_have_permission:
        print("\n  --probe-depth exhaustive opens 65535 connections per host.")
        print("  It takes minutes per address and is unmistakable in any firewall log.")
        print("  Re-run with --i-have-permission if you have authority over the targets.")
        print("  For nearly the same coverage far faster, use --probe-depth full.\n")
        sys.exit(2)

    if args.oui_file:
        loaded = VendorDatabase.load_oui_file(args.oui_file)
        print(f"  Vendor database: {loaded} OUI prefixes loaded from {args.oui_file}")
    else:
        loaded = VendorDatabase.autoload()
        if loaded:
            print(f"  Vendor database: {loaded} OUI prefixes auto-loaded")
    
    # Show legal warning if required
    if Config.LEGAL_WARNING_REQUIRED and args.warning and not args.no_warning:
        if not LegalDisclaimer.display_warning(skip=False):
            print("\n❌ Consent not given. Exiting...")
            sys.exit(0)
    
    # Determine which mode to run.
    #
    # --probe-only is checked first and deliberately does not fall through to
    # the interactive menu: naming targets is already an unambiguous statement
    # of what you want done, and there is nothing to choose between.
    if args.probe_only:
        main_probe_only(args)
    elif args.enhanced:
        main_enhanced(args)
    elif args.original:
        main_original(args)
    else:
        # Interactive mode selection
        print("\nChoose scanning mode:")
        print("1. Enhanced Scan (Security features, hierarchical mapping)")
        print("2. Original Scan (Compatibility mode with security)")
        print("3. Exit")
        
        choice = input("\nEnter choice (1, 2, or 3): ").strip()
        
        if choice == "1":
            main_enhanced(args)
        elif choice == "2":
            main_original(args)
        else:
            print("Exiting...")
            sys.exit(0)