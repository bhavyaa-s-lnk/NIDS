import urllib.request
import json
import os
import socket
import threading
from dataclasses import dataclass
from typing import Optional


@dataclass
class MACInfo:
    """Represents MAC address information"""
    mac_address: str
    vendor: str
    device_type: str  # Router, Phone, TV, PC, IoT, Unknown
    nickname: str
    last_3_bytes: str

    def to_dict(self):
        return {
            'mac': self.mac_address,
            'vendor': self.vendor,
            'device_type': self.device_type,
            'nickname': self.nickname,
            'last_bytes': self.last_3_bytes
        }


class MACLookup:
    """OOP MAC address lookup with vendor, type detection and DNS resolution"""

    def __init__(self, cache_file="mac_cache.json"):
        self.cache_file = cache_file
        self.cache = self.load_cache()
        self.dns_cache = {}
        self.device_type_patterns = self._init_device_patterns()

    def load_cache(self):
        """Load cached MAC lookups from file"""
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def save_cache(self):
        """Save MAC lookups to file"""
        with open(self.cache_file, 'w') as f:
            json.dump(self.cache, f, indent=2)

    def _init_device_patterns(self) -> dict:
        """Initialize device type detection patterns"""
        return {
            'Router': ['sagecom', 'tp-link', 'd-link', 'netgear', 'asus', 'cisco', 'ubiquiti', 'mikrotik'],
            'Phone': ['apple', 'samsung', 'motorola', 'nokia', 'oppo', 'vivo', 'xiaomi', 'huawei', 'oneplus', 'sony',
                      'htc'],
            'TV': ['lg electronics', 'samsung', 'sony', 'philips', 'sharp', 'panasonic', 'roku'],
            'PC': ['intel', 'amd', 'dell', 'hp', 'lenovo', 'asus', 'msi'],
            'IoT': ['amazon', 'google', 'philips', 'nest', 'echo', 'smartthings', 'wyze'],
            'Printer': ['hp', 'canon', 'epson', 'xerox', 'brother', 'ricoh'],
            'Gaming': ['nvidia', 'playstation', 'xbox', 'nintendo'],
        }

    def _is_valid_mac(self, mac: str) -> bool:
        """Validate MAC address format"""
        if not mac or mac == "":
            return False
        parts = mac.split(':')
        if len(parts) != 6:
            return False
        for part in parts:
            if len(part) != 2:
                return False
            try:
                int(part, 16)
            except:
                return False
        return True

    def reverse_dns_lookup(self, ip_address: str) -> Optional[str]:
        """Perform reverse DNS lookup to get hostname"""
        if ip_address in self.dns_cache:
            return self.dns_cache[ip_address]

        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            self.dns_cache[ip_address] = hostname
            return hostname
        except:
            self.dns_cache[ip_address] = None
            return None

    def lookup_vendor(self, mac_address: str) -> str:
        """Look up MAC vendor from online API"""
        if not mac_address or mac_address == "" or mac_address == "00:00:00:00:00:00":
            return "Unknown"

        mac = mac_address.upper().strip()

        if not self._is_valid_mac(mac):
            return "Invalid"

        # Check cache first
        if mac in self.cache:
            return self.cache[mac]

        try:
            url = f"https://api.macvendors.com/{mac}"
            with urllib.request.urlopen(url, timeout=3) as response:
                vendor = response.read().decode('utf-8').strip()

            if vendor and len(vendor) > 2:
                self.cache[mac] = vendor
                self.save_cache()
                return vendor
        except:
            pass

        # Default to Unknown
        self.cache[mac] = "Unknown"
        self.save_cache()
        return "Unknown"

    def detect_device_type(self, vendor: str) -> str:
        """Detect device type based on vendor name"""
        vendor_lower = vendor.lower()

        for device_type, keywords in self.device_type_patterns.items():
            for keyword in keywords:
                if keyword in vendor_lower:
                    return device_type

        return "Unknown"

    def get_nickname(self, vendor: str, device_type: str) -> str:
        """Get friendly nickname with emoji based on vendor and type"""
        vendor_lower = vendor.lower()

        emojis = {
            'Router': '🌐',
            'Phone': '📱',
            'TV': '📺',
            'PC': '💻',
            'IoT': '🏠',
            'Printer': '🖨️',
            'Gaming': '🎮',
            'Unknown': '❓'
        }

        emoji = emojis.get(device_type, '❓')

        # Vendor-specific nicknames
        vendor_names = {
            'apple': '🍎 Apple',
            'samsung': 'Samsung',
            'motorola': 'Motorola',
            'lg electronics': 'LG',
            'sony': 'Sony',
            'google': 'Google',
            'tp-link': 'TP-Link',
            'netgear': 'Netgear',
            'asus': 'ASUS',
            'dell': 'Dell',
            'hp': 'HP',
            'canon': 'Canon',
            'epson': 'Epson',
            'amazon': 'Amazon',
            'philips': 'Philips',
            'intel': 'Intel',
            'nvidia': 'NVIDIA',
            'sagecom': 'Sagecom',
        }

        for key, name in vendor_names.items():
            if key in vendor_lower:
                return f"{emoji} {name} ({device_type})"

        return f"{emoji} {vendor} ({device_type})"

    def get_last_3_bytes(self, mac: str) -> str:
        """Get last 3 bytes of MAC for device identification"""
        if not mac or len(mac) < 17:
            return "N/A"
        return mac[-8:]  # Last 8 chars (3 bytes in XX:XX:XX format)

    def lookup(self, mac_address: str, ip_address: Optional[str] = None) -> MACInfo:
        """
        Complete lookup: vendor, type detection, hostname resolution
        Returns MACInfo object with all details
        """
        mac = mac_address.upper().strip() if mac_address else ""

        # Get vendor
        vendor = self.lookup_vendor(mac)

        # Detect device type
        device_type = self.detect_device_type(vendor)

        # Get nickname
        nickname = self.get_nickname(vendor, device_type)

        # Get last 3 bytes
        last_bytes = self.get_last_3_bytes(mac)

        # Try hostname resolution if IP provided
        if ip_address:
            hostname = self.reverse_dns_lookup(ip_address)
            if hostname and hostname != "":
                nickname = f"🌐 {hostname}"

        return MACInfo(
            mac_address=mac,
            vendor=vendor,
            device_type=device_type,
            nickname=nickname,
            last_3_bytes=last_bytes
        )

    def lookup_batch(self, mac_list: list, ip_list: list = None) -> list:
        """Lookup multiple MAC addresses at once"""
        results = []
        for i, mac in enumerate(mac_list):
            ip = ip_list[i] if ip_list and i < len(ip_list) else None
            results.append(self.lookup(mac, ip))
        return results