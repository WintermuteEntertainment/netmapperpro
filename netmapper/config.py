"""Scanner settings."""

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

    # ===== ERRORS =====
    # A failed scan always says so and exits with code 1. This decides how much
    # it says: False prints one line, True (--debug) adds the full traceback.
    SHOW_TRACEBACK = False

    @classmethod
    def reset(cls):
        """
        Put every setting back to the value it had when the module loaded.

        Settings are class attributes, so in a long-running process (the web
        app) one scan's choices would otherwise carry into the next.
        """
        for name, value in _DEFAULTS.items():
            setattr(cls, name, list(value) if isinstance(value, list) else value)


# Snapshot of the shipped defaults, taken once at import for Config.reset().
_DEFAULTS = {name: (list(value) if isinstance(value, list) else value)
             for name, value in vars(Config).items() if name.isupper()}
