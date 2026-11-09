"""TCP connect service probing."""

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
from .models import Finding, NetworkDevice


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
