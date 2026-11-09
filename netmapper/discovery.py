"""Devices identifying themselves: mDNS, SSDP and WS-Discovery."""

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

from .models import NetworkDevice


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
