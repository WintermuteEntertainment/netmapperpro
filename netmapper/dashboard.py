"""HTML dashboard output."""

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
from .models import NetworkDevice, _ip_sort_key
from .probe import ServiceProbe


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
