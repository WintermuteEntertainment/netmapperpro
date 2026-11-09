"""Neighbour table, ping sweep and device type inference."""

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
from .safety import RateLimiter, SecurityValidator
from .vendors import VendorDatabase
from .models import NetworkDevice
from .netenum import LocalNetworkEnumerator


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

    def fill_missing_macs(self, devices: List[NetworkDevice]) -> List[NetworkDevice]:
        """
        Give MAC-less devices their hardware address from a fresh read of the
        neighbour table. Returns the devices that were filled in.

        A host found by the ping sweep (or by an mDNS/WS-Discovery reply) has
        no MAC, because the table was read before we talked to it. Talking to
        it puts it in the table, so a second read after the sweep finds it.
        Without this the host had no vendor, could not anchor its own Wi-Fi
        network as "ours", and broke the MAC-keyed baseline comparison.
        """
        missing = {d.ip: d for d in devices if not d.mac}
        if not missing:
            return []
        filled = []
        for row in self.scan_neighbors(self.interfaces):
            dev = missing.get(row.ip)
            if dev is None:
                continue
            dev.mac = row.mac
            dev.neighbor_state = dev.neighbor_state or row.neighbor_state
            dev.interface = dev.interface or row.interface
            filled.append(dev)
        return filled

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

                if ping_devices:
                    filled = self.fill_missing_macs(ping_devices)
                    self.on_log(f"      Hardware address filled in for {len(filled)} of "
                                f"{len(ping_devices)} from the neighbour table after the sweep")

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
