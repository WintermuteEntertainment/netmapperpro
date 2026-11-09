"""Input validation, ping pacing and the legal disclaimer."""

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


# ==================== SECURITY ENHANCEMENTS ====================
class SecurityValidator:
    """
    INPUT VALIDATION AND SECURITY CHECKS
    
    This class provides methods to validate and sanitize all inputs
    to prevent security vulnerabilities like command injection.
    
    CRITICAL SECURITY:
    - All user inputs pass through these validators
    - Shell commands are sanitized before execution
    - Network addresses are validated before use
    """
    
    @staticmethod
    def validate_ip_address(ip: str) -> bool:
        """
        Validate IP address format and range.
        
        Args:
            ip: IP address string to validate
            
        Returns:
            True if valid, False otherwise
            
        SECURITY: Prevents using malformed or dangerous IP addresses
        """
        try:
            # Check if it's a valid IP using Python's ipaddress module
            ip_obj = ipaddress.ip_address(ip)
            
            # Skip problematic addresses if configured (privacy feature)
            if Config.SKIP_MULTICAST_IPS:
                if ip_obj.is_multicast or ip_obj.is_link_local:
                    return False
                    
            # Skip loopback addresses (127.0.0.1, etc.)
            if ip_obj.is_loopback:
                return False
                
            return True
        except ValueError:
            return False  # Not a valid IP address
    
    @staticmethod
    def validate_mac_address(mac: str) -> bool:
        """
        Validate MAC address format using regex.
        
        Args:
            mac: MAC address string
            
        Returns:
            True if valid format, False otherwise
        """
        # Standard MAC address patterns: 00:11:22:33:44:55 or 00-11-22-33-44-55
        mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
        return bool(mac_pattern.match(mac))
    
    @staticmethod
    def sanitize_command_input(input_str: str) -> str:
        """
        Sanitize input for shell commands to prevent injection attacks.
        
        Args:
            input_str: Raw input string
            
        Returns:
            Sanitized string with dangerous characters removed
            
        SECURITY CRITICAL: This prevents command injection vulnerabilities
        """
        if not Config.VALIDATE_COMMAND_INPUTS:
            return input_str  # Only if validation is disabled (not recommended)
            
        # Remove potentially dangerous shell characters
        dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '{', '}', '[', ']', '<', '>', '!', '\n', '\r']
        for char in dangerous_chars:
            input_str = input_str.replace(char, '')
        return input_str.strip()


class RateLimiter:
    """
    RATE LIMITER TO PREVENT NETWORK FLOODING
    
    This class ensures that scans don't overwhelm the network
    by adding delays between probes.
    
    IMPORTANT FOR:
    - Avoiding network congestion
    - Preventing detection by intrusion detection systems
    - Being respectful to network resources
    """
    def __init__(self):
        self.next_slot = 0.0  # monotonic timestamp of the next free probe slot
        self.lock = threading.Lock()  # Thread-safe operations

    def wait_if_needed(self):
        """
        Pace probe launches to at most one per RATE_LIMIT_DELAY seconds.

        The lock is held only long enough to CLAIM a time slot; the sleep
        happens outside it. Holding the lock across the sleep (the previous
        behaviour) serialised the whole thread pool, so 50 workers performed
        exactly like 1. Now each worker reserves a distinct slot and then
        waits for its own, which paces the aggregate probe rate without
        destroying parallelism.
        """
        if not Config.RATE_LIMIT_SCANS or Config.RATE_LIMIT_DELAY <= 0:
            return  # Rate limiting disabled

        interval = Config.RATE_LIMIT_DELAY
        with self.lock:
            now = time.monotonic()
            slot = max(now, self.next_slot)
            self.next_slot = slot + interval

        delay = slot - time.monotonic()
        if delay > 0:
            time.sleep(delay)


class LegalDisclaimer:
    """
    LEGAL AND ETHICAL GUIDELINES DISPLAY
    
    This class ensures users understand the legal implications
    of network scanning and promotes ethical usage.
    """
    
    @staticmethod
    def display_warning(skip=False):
        """
        Display legal warning if enabled.
        
        Args:
            skip: If True, skip the warning (not recommended)
            
        Returns:
            True if user consents, False otherwise
        """
        if skip and not Config.LEGAL_WARNING_REQUIRED:
            return True
        
        warning_text = """
        ⚠️  LEGAL NOTICE: Network Scanning Tool
        
        This tool scans networks for mapping and visualization purposes.
        
        IMPORTANT: Only scan networks you own or have explicit permission to scan.
        Unauthorized scanning may be illegal in your jurisdiction.
        
        By using this tool, you acknowledge that:
        1. You have permission to scan the target network
        2. You understand local laws regarding network scanning
        3. You accept responsibility for proper use
        
        Continue? (yes/no): """
        
        print(warning_text)
        response = input().strip().lower()
        return response in ['yes', 'y', '']
    
    @staticmethod
    def show_ethical_guidelines():
        """
        Display ethical usage tips.
        
        These guidelines help users understand responsible
        network scanning practices.
        """
        if not Config.SHOW_ETHICAL_GUIDELINES:
            return
            
        guidelines = """
        📋 ETHICAL USAGE GUIDELINES:
        
        1. Scan only networks you own or have explicit permission to scan
        2. Respect network policies and terms of service
        3. Use during off-hours for production networks
        4. Be transparent about scanning activities
        5. Secure generated files (they contain sensitive info)
        6. Delete scans when no longer needed
        
        """
        print(guidelines)
