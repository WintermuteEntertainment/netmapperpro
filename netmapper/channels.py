"""Wi-Fi channel crowding."""

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

from .models import Finding, WifiNetwork


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
