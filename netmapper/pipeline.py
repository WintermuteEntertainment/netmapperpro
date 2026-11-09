"""
The scan itself, shared by the command line and the web app.

Before this module existed, the steps of a scan were written out twice: once in
cli.main_enhanced() and again in the web app's run_scan(). The two copies had
already drifted apart. Both front ends now call run_scan() here and differ only
in what they do with the result: the CLI writes files and prints a summary, the
web app streams progress and archives each scan in its own folder.

run_scan() never prints. Everything it has to say goes through on_log.
"""

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .config import Config
from .models import NetworkDevice, WifiNetwork, Finding
from .netenum import LocalNetworkEnumerator, NetworkInterface, SweepTarget
from .scanner import SecureNetworkScanner
from .wifi import SecureWiFiScanner
from .discovery import PassiveDiscovery, WSDiscovery
from .probe import ServiceProbe
from .channels import ChannelAnalyzer
from .watchlist import VendorWatchlist
from .threats import ThreatAnalyzer

SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2}


class ScanCancelled(Exception):
    """Raised when should_stop() turns true. Carries what was found so far."""

    def __init__(self, partial: "ScanResult"):
        super().__init__("scan stopped")
        self.partial = partial


@dataclass
class ScanResult:
    lan_devices: List[NetworkDevice] = field(default_factory=list)
    wifi_networks: List[WifiNetwork] = field(default_factory=list)
    interfaces: List[NetworkInterface] = field(default_factory=list)
    sweep_targets: List[SweepTarget] = field(default_factory=list)
    topology: Dict[str, Any] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    duration: float = 0.0

    @property
    def wifi_devices(self) -> List[NetworkDevice]:
        """Wi-Fi networks as diagram/dashboard nodes."""
        return [n.to_device() for n in self.wifi_networks]


def _add_unlisted(devices, found, own_addresses, attached, via, describe):
    """
    Add hosts that answered a discovery protocol but were not in the neighbour
    table or the sweep. Returns the IPs added.
    """
    known = {d.ip for d in devices}
    added = []
    for ip, info in found.items():
        if ip in known or ip in own_addresses:
            continue
        dev = NetworkDevice(ip=ip, network_type="lan")
        describe(dev, info)
        dev.discovered_via = via
        dev.ownership = SecureNetworkScanner._classify_ownership(ip, attached)
        devices.append(dev)
        known.add(ip)
        added.append(ip)
    return added


def _describe_announced(dev, info):
    dev.hostname = sorted(info["names"])[0] if info["names"] else ""
    dev.services = sorted(info["services"])


def _describe_onvif(dev, info):
    dev.hostname = info.get("name") or info.get("hardware") or ""


def run_scan(*,
             baseline: Optional[Dict[str, Any]] = None,
             wifi_history: Optional[List[Dict[str, Any]]] = None,
             watchlist_rules: Optional[List[Dict[str, Any]]] = None,
             allow_foreign: bool = False,
             discovery: Optional[bool] = None,
             probing: Optional[bool] = None,
             analysis: bool = True,
             on_log: Optional[Callable[[str], None]] = None,
             on_progress: Optional[Callable[[str, int, int], None]] = None,
             should_stop: Optional[Callable[[], bool]] = None,
             wait_if_paused: Optional[Callable[[], None]] = None) -> ScanResult:
    """
    Run one scan using the current Config and return everything it found.

    baseline        previous scan, for change detection and probe selection
    wifi_history    BSSIDs from earlier scans for channel advice; defaults to
                    the baseline's Wi-Fi list
    watchlist_rules rules to apply; None loads the default watchlist file
    allow_foreign   let the probe touch addresses outside our own networks
    discovery       mDNS/SSDP/WS-Discovery; None follows Config
    probing         TCP service probe; None follows Config
    analysis        findings (baseline diff, channels, watchlist)
    """
    log = on_log or (lambda m: None)
    progress = on_progress or (lambda stage, done, total: None)
    stopping = should_stop or (lambda: False)
    if discovery is None:
        discovery = Config.PASSIVE_DISCOVERY
    if probing is None:
        probing = Config.IDENTIFY_SILENT

    mode = Config.SCAN_MODE
    lan_wanted = mode in ("all", "lan")
    started = time.monotonic()
    result = ScanResult()

    def checkpoint():
        if stopping():
            result.duration = time.monotonic() - started
            raise ScanCancelled(result)

    scanner = SecureNetworkScanner(on_progress=on_progress, on_log=log,
                                   should_stop=should_stop,
                                   wait_if_paused=wait_if_paused)

    # 1. Networks and devices
    log("[1/3] Network scan...")
    if lan_wanted:
        result.lan_devices = scanner.scan_lan_enhanced()
    else:
        scanner.interfaces = LocalNetworkEnumerator.enumerate()
    result.interfaces = scanner.interfaces
    result.sweep_targets = scanner.sweep_targets
    checkpoint()

    # 2. Wi-Fi
    if mode in ("all", "wifi"):
        progress("wifi", 0, 1)
        log("[2/3] Passive wireless survey...")
        # Every MAC we can justify calling ours, so a device of ours that also
        # broadcasts its own SSID is recognised rather than called a stranger.
        result.wifi_networks = SecureWiFiScanner.scan_wifi(
            our_macs=scanner.our_known_macs(result.lan_devices))
        radios = SecureWiFiScanner.group_by_radio(result.wifi_networks)
        ours_n = sum(1 for n in result.wifi_networks if n.ownership == "ours")
        log(f"    {len(result.wifi_networks)} BSSIDs across {len(radios)} physical "
            f"radios ({ours_n} ours, {len(result.wifi_networks) - ours_n} nearby)")
        progress("wifi", 1, 1)
    checkpoint()

    # 3. Devices identifying themselves
    attached = [i.network for i in result.interfaces if i.network]
    if discovery and lan_wanted:
        progress("announce", 0, 1)
        log("Listening for device announcements...")
        announced = PassiveDiscovery.collect(
            result.interfaces, duration=Config.DISCOVERY_DURATION,
            active=Config.DISCOVERY_SOLICIT, on_log=log, should_stop=should_stop)
        enriched = PassiveDiscovery.apply(result.lan_devices, announced)
        log(f"    {len(announced)} host(s) announced, {enriched} device(s) enriched")
        for ip in _add_unlisted(result.lan_devices, announced, scanner._own_addresses,
                                attached, "announcement", _describe_announced):
            log(f"    + {ip} found via announcement only")

        # ONVIF cameras and recorders answer WS-Discovery and nothing else.
        onvif = WSDiscovery.probe(result.interfaces, duration=6.0,
                                  on_log=log, should_stop=should_stop)
        if onvif:
            WSDiscovery.apply(result.lan_devices, onvif)
            _add_unlisted(result.lan_devices, onvif, scanner._own_addresses,
                          attached, "ws-discovery", _describe_onvif)
            log(f"    {len(onvif)} WS-Discovery responder(s)")
        progress("announce", 1, 1)
    checkpoint()

    # 4. Service probe. A separate decision from discovery: it used to be
    # nested inside the block above, so turning discovery off silently turned
    # probing off too.
    if lan_wanted and not probing:
        # Say so rather than skipping in silence: a depth setting with no probe
        # behind it reads exactly like a deep scan that found nothing.
        log(f"Service probing: OFF (depth would be {Config.PROBE_DEPTH}).")
    if lan_wanted and probing:
        progress("probe", 0, 1)
        log("Probing for open service ports...")
        nets = ServiceProbe.resolve_nets(
            Config.PROBE_NETS, interfaces=result.interfaces,
            sweep_targets=result.sweep_targets, baseline=baseline, on_log=log)
        if Config.PROBE_NETS and not nets:
            log("    ! No networks matched the probe network filter; nothing probed.")
        else:
            answered = ServiceProbe.identify(
                result.lan_devices, on_log=log, should_stop=should_stop,
                nets=nets or None, baseline=baseline, on_progress=on_progress,
                allow_foreign=allow_foreign)
            log(f"    {answered} device(s) answered on at least one port")
        progress("probe", 1, 1)
    checkpoint()

    # 5. Topology, built last so devices found by discovery are included.
    progress("topology", 0, 1)
    log("[3/3] Analyzing network topology...")
    topology = scanner.infer_network_topology(result.lan_devices)
    topology["wifi"] = result.wifi_networks
    topology["interfaces"] = result.interfaces
    topology["sweep_targets"] = result.sweep_targets

    # 6. Findings. Costs nothing on the wire: it reasons over beacons already
    # received, our own neighbour table and the previous scan.
    findings: List[Finding] = []
    if analysis:
        findings = ThreatAnalyzer.analyze(result.lan_devices, result.wifi_networks,
                                          result.interfaces, baseline)
        history = wifi_history if wifi_history is not None \
            else (baseline or {}).get("wifi_networks")
        findings += ChannelAnalyzer.findings(result.wifi_networks, history)
        findings += ServiceProbe.findings(result.lan_devices)
        if Config.USE_WATCHLIST:
            findings += VendorWatchlist.check(result.lan_devices, watchlist_rules)
        findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 3), f.category))
        crit = sum(1 for f in findings if f.severity == "critical")
        warn = sum(1 for f in findings if f.severity == "warning")
        log(f"{len(findings)} finding(s): {crit} critical, {warn} warning")
        for f in findings:
            if f.severity in ("critical", "warning"):
                log(f"    [{f.severity.upper()}] {f.title}")
    topology["findings"] = findings
    progress("topology", 1, 1)

    result.topology = topology
    result.findings = findings
    result.duration = time.monotonic() - started
    return result
