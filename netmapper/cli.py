"""Command line: scan modes, argument parsing and the entry point."""

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
from .safety import LegalDisclaimer
from .vendors import VendorDatabase
from .models import NetworkDevice, WifiNetwork, _ip_sort_key
from .netenum import LocalNetworkEnumerator
from .scanner import SecureNetworkScanner
from .wifi import SecureWiFiScanner
from .diagram import EnhancedDiagramGenerator
from .discovery import PassiveDiscovery, WSDiscovery
from .probe import ServiceProbe
from .channels import ChannelAnalyzer
from .watchlist import VendorWatchlist
from .threats import ThreatAnalyzer
from .dashboard import SecureDashboard
from .baseline import BASELINE_FILE, load_baseline, save_baseline
from .pipeline import run_scan


# ==================== MAIN APPLICATION ====================
LAUNCHER_ENHANCED = '''@echo off
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
pause'''

LAUNCHER_ORIGINAL = '''@echo off
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
pause'''


def _fail(what, exc):
    """
    Report a failed run and exit with code 1, so scripts and schedulers can
    tell it failed. The full traceback is shown only with --debug.
    """
    print(f"\n❌ {what}: {exc}")
    if Config.SHOW_TRACEBACK:
        import traceback
        traceback.print_exc()
    else:
        print("   Run again with --debug to see the full error.")
    sys.exit(1)


def _write_outputs(result, diagram_path, dashboard_path, launcher_path, launcher_text):
    """Write the diagram, dashboard and Windows launcher for one scan."""
    print("\n🎨 Generating secure diagram...")
    diagram_xml = EnhancedDiagramGenerator.generate_hierarchical_diagram(
        result.lan_devices, result.wifi_devices, result.topology
    )
    with open(diagram_path, "w", encoding="utf-8") as f:
        f.write(diagram_xml)
    print(f"   ✓ Saved: {diagram_path}")

    print("📊 Creating secure dashboard...")
    dashboard_html = SecureDashboard.generate_dashboard(
        result.lan_devices, result.wifi_devices, result.duration, result.topology
    )
    with open(dashboard_path, "w", encoding="utf-8") as f:
        f.write(dashboard_html)
    print(f"   ✓ Saved: {dashboard_path}")

    # utf-8-sig so cmd.exe shows the emoji after `chcp 65001`.
    with open(launcher_path, "w", encoding="utf-8-sig") as f:
        f.write(launcher_text)
    print(f"   ✓ Saved: {launcher_path}")


def main_enhanced(args):
    """
    The normal scan: everything the scanner can do, written to the current
    folder as a diagram, a dashboard, a launcher and the baseline.
    """
    try:
        print("\n" + "="*80)
        print("🔒 SECURE NETWORK INTELLIGENCE MAPPER PRO")
        print("="*80)
        print("Features: Secure scanning • Input validation • Rate limiting")
        print("-"*80)

        if Config.SHOW_ETHICAL_GUIDELINES:
            LegalDisclaimer.show_ethical_guidelines()

        # Loaded before the scan because probe selection ('new') reads it.
        baseline = load_baseline(args)
        result = run_scan(
            baseline=baseline,
            allow_foreign=getattr(args, "i_have_permission", False),
            on_log=print,
        )

        _write_outputs(result, "secure_network_diagram.drawio.xml",
                       "secure_network_dashboard.html", "launch_secure.bat",
                       LAUNCHER_ENHANCED)

        # Record this scan so the next one can report what changed.
        save_baseline(args, result.lan_devices, result.wifi_networks)

        print("\n" + "="*80)
        print("✅ SECURE SCAN COMPLETE!")
        print("="*80)

        subnets = defaultdict(list)
        for device in result.lan_devices:
            if device.subnet:
                subnets[device.subnet].append(device)

        print(f"\n📊 SECURE RESULTS:")
        print(f"  • Scan Time: {result.duration:.1f} seconds")
        print(f"  • Total Devices: {len(result.lan_devices)}")
        print(f"  • Subnets Detected: {len(subnets)}")
        for subnet, devices in subnets.items():
            wireless = sum(1 for d in devices if 'wireless' in d.tags)
            gateways = sum(1 for d in devices if d.is_gateway)
            print(f"  • {subnet}: {len(devices)} devices ({wireless} wireless, {gateways} gateways)")
        print(f"  • WiFi Networks: {len(result.wifi_networks)}")
        if result.topology.get('gateways'):
            print(f"  • Gateways: {', '.join(result.topology['gateways'])}")

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

        if Config.AUTO_OPEN and not args.no_open:
            print(f"\n🔄 Opening secure dashboard...")
            dashboard_path = os.path.abspath("secure_network_dashboard.html")
            file_url = "file:///" + dashboard_path.replace('\\', '/')
            webbrowser.open(file_url)

    except Exception as e:
        _fail("Error in secure scan", e)


def main_original(args):
    """
    The reduced scan kept for compatibility: devices and Wi-Fi only, with no
    discovery, probing, findings or baseline, under the older file names.
    """
    try:
        print("\n" + "="*80)
        print("🔒 ORIGINAL NETWORK INTELLIGENCE MAPPER (Secure)")
        print("="*80)

        if Config.SHOW_ETHICAL_GUIDELINES:
            LegalDisclaimer.show_ethical_guidelines()

        result = run_scan(discovery=False, probing=False, analysis=False,
                          on_log=print)

        _write_outputs(result, "network_diagram.drawio.xml",
                       "network_dashboard.html", "open_dashboard.bat",
                       LAUNCHER_ORIGINAL)

        print("\n" + "="*80)
        print("✅ SECURE SCAN COMPLETE!")
        print("="*80)
        print(f"\n📊 RESULTS:")
        print(f"  • Scan Time: {result.duration:.1f} seconds")
        print(f"  • LAN Devices: {len(result.lan_devices)}")
        print(f"  • WiFi Networks: {len(result.wifi_networks)}")

        print(f"\n🔒 SECURITY REMINDER:")
        print(f"  ⚠️  Output files contain sensitive network information")
        print(f"  🔐 Encrypt files before storage or sharing")

        print(f"\n🚀 QUICK START:")
        print(f"  1. Run 'open_dashboard.bat'")
        print(f"  2. 🔐 Encrypt output files")

    except Exception as e:
        _fail("Error", e)


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
        _fail("Error in targeted probe", e)


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
    parser.add_argument('--debug', action='store_true',
                       help='If the scan fails, show the full Python traceback '
                            'instead of a one-line error')

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
def main():
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

    Config.SHOW_TRACEBACK = args.debug
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


if __name__ == "__main__":
    main()
