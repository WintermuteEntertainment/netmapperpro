"""draw.io diagram output."""

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
from .models import NetworkDevice
from .probe import ServiceProbe


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
