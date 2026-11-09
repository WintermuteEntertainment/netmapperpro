"""Which networks this host is on, and which of them may be swept."""

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


# Imported last on purpose: scanner.py imports this module, and the enumerator
# only needs SecureNetworkScanner.run_cmd inside function bodies, at call time.
from .scanner import SecureNetworkScanner  # noqa: E402
