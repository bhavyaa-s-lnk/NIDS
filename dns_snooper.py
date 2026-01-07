from scapy.all import DNS, DNSQR, IP, UDP
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional
import time


@dataclass
class DNSQuery:
    """Represents a DNS query"""
    ip: str
    hostname: str
    query_type: str  # A, AAAA, PTR, etc
    timestamp: float

    def to_dict(self):
        return {
            'ip': self.ip,
            'hostname': self.hostname,
            'type': self.query_type,
            'time': self.timestamp
        }


@dataclass
class DeviceProfile:
    """Device profile built from DNS queries"""
    ip: str
    mac: str = None
    device_name: str = "Unknown"
    device_type: str = "Unknown"
    queries: List[str] = field(default_factory=list)
    first_seen: float = 0
    last_seen: float = 0

    def to_dict(self):
        return {
            'ip': self.ip,
            'mac': self.mac,
            'device_name': self.device_name,
            'device_type': self.device_type,
            'total_queries': len(self.queries),
            'queries_sample': self.queries[-10:],  # Last 10 queries
            'first_seen': self.first_seen,
            'last_seen': self.last_seen
        }


class DNSSnooper:
    """Snoop DNS queries to fingerprint devices and extract hostnames"""

    def __init__(self):
        self.dns_queries: Dict[str, List[DNSQuery]] = defaultdict(list)
        self.device_profiles: Dict[str, DeviceProfile] = {}
        self.hostname_to_device: Dict[str, str] = {}
        self.device_fingerprints = self._init_fingerprints()

    def _init_fingerprints(self) -> dict:
        """Initialize device fingerprints based on DNS patterns"""
        return {
            'Apple': ['api.apple.com', 'icloud.com', 'mzstatic.com', 'push.apple.com'],
            'Google Pixel': ['google.com', 'android.com', 'gstatic.com'],
            'Samsung': ['samsung.com', 'samsungapps.com'],
            'Amazon Alexa': ['amazon.com', 'alexa.com', 'alexa-device-setup.com'],
            'Chromecast': ['google.com', 'gstatic.com', 'youtube.com'],
            'Roku': ['roku.com', 'rokudev.com'],
            'Smart TV': ['samsung.com', 'lg.com', 'sony.com', 'netflix.com'],
            'Windows PC': ['microsoft.com', 'windows.com', 'xbox.com'],
            'MacOS': ['apple.com', 'icloud.com', 'macdownload.apple.com'],
            'Linux': ['ubuntu.com', 'debian.org', 'github.com'],
            'Android Phone': ['google.com', 'android.com', 'gms.googleapis.com'],
            'IoT Device': ['amazon.com', 'google.com', 'home-automation.com'],
            'Router': ['router-login.com', 'routerlogin.net', 'myrouter.local'],
        }

    def process_dns_packet(self, packet) -> Optional[DNSQuery]:
        """Extract DNS query from packet"""
        try:
            if DNS not in packet or IP not in packet:
                return None

            dns_layer = packet[DNS]
            ip_layer = packet[IP]

            # Only process queries (not responses)
            if dns_layer.qr != 0:  # qr=0 is query, qr=1 is response
                return None

            src_ip = ip_layer.src

            # Extract query name
            if dns_layer.qdcount > 0:
                query_name = dns_layer.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                query_type = self._get_query_type(dns_layer.qd.qtype)

                dns_query = DNSQuery(
                    ip=src_ip,
                    hostname=query_name,
                    query_type=query_type,
                    timestamp=time.time()
                )

                # Store query
                self.dns_queries[src_ip].append(dns_query)

                # Update device profile
                self._update_device_profile(src_ip, query_name)

                return dns_query

        except Exception as e:
            pass

        return None

    def _get_query_type(self, qtype: int) -> str:
        """Convert DNS query type number to string"""
        types = {
            1: 'A',
            2: 'NS',
            5: 'CNAME',
            12: 'PTR',
            16: 'TXT',
            28: 'AAAA',
            33: 'SRV',
        }
        return types.get(qtype, f'Type{qtype}')

    def _update_device_profile(self, ip: str, hostname: str):
        """Update device profile with DNS query"""
        if ip not in self.device_profiles:
            self.device_profiles[ip] = DeviceProfile(
                ip=ip,
                first_seen=time.time(),
                last_seen=time.time()
            )

        profile = self.device_profiles[ip]
        profile.queries.append(hostname)
        profile.last_seen = time.time()

        # Fingerprint device based on queries
        device_type = self._fingerprint_device(profile.queries)
        if device_type != "Unknown":
            profile.device_type = device_type
            profile.device_name = f"🔍 {device_type}"

        # Try to extract hostname from queries
        hostname_candidate = self._extract_hostname(hostname)
        if hostname_candidate and len(hostname_candidate) < 50:
            if hostname_candidate not in profile.device_name:
                # Check if it looks like a real device name
                if self._is_device_hostname(hostname_candidate):
                    profile.device_name = f"📱 {hostname_candidate}"
                    self.hostname_to_device[hostname_candidate] = ip

    def _fingerprint_device(self, queries: List[str]) -> str:
        """Fingerprint device type based on DNS queries"""
        query_str = ' '.join(queries).lower()

        for device_type, patterns in self.device_fingerprints.items():
            matches = sum(1 for pattern in patterns if pattern.lower() in query_str)
            if matches >= 2:  # At least 2 pattern matches
                return device_type

        return "Unknown"

    def _extract_hostname(self, domain: str) -> Optional[str]:
        """Try to extract device hostname from DNS query"""
        # Look for patterns like "device-name.local" or "hostname.home"
        parts = domain.split('.')

        if len(parts) >= 2:
            # Check for .local domains
            if parts[-1] == 'local':
                return parts[0]

            # Check for obvious device names
            if len(parts[0]) < 20 and not parts[0].startswith('api') and not parts[0].startswith('cdn'):
                if self._is_device_hostname(parts[0]):
                    return parts[0]

        return None

    def _is_device_hostname(self, name: str) -> bool:
        """Check if string looks like a device hostname"""
        # Avoid generic patterns
        if any(x in name.lower() for x in ['api', 'cdn', 'analytics', 'tracking', 'ads', 'beacon']):
            return False

        # Should contain alphanumeric and hyphens only
        if not all(c.isalnum() or c == '-' for c in name):
            return False

        # Between 3 and 30 chars
        if 3 <= len(name) <= 30:
            return True

        return False

    def get_device_queries(self, ip: str) -> List[DNSQuery]:
        """Get all DNS queries from an IP"""
        return self.dns_queries.get(ip, [])

    def get_device_profile(self, ip: str) -> Optional[DeviceProfile]:
        """Get device profile by IP"""
        return self.device_profiles.get(ip)

    def get_all_profiles(self) -> List[DeviceProfile]:
        """Get all device profiles"""
        return list(self.device_profiles.values())

    def get_top_domains(self, ip: str, limit: int = 10) -> List[str]:
        """Get most queried domains for an IP"""
        queries = self.dns_queries.get(ip, [])
        if not queries:
            return []

        domain_count = defaultdict(int)
        for query in queries:
            domain_count[query.hostname] += 1

        return sorted(domain_count.items(), key=lambda x: x[1], reverse=True)[:limit]

    def get_unique_domains(self, ip: str) -> int:
        """Get count of unique domains queried by device"""
        queries = self.dns_queries.get(ip, [])
        return len(set(q.hostname for q in queries))

    def export_profiles(self, filename: str = "dns_profiles.json"):
        """Export device profiles"""
        import json
        data = {
            'timestamp': time.time(),
            'total_devices': len(self.device_profiles),
            'devices': [p.to_dict() for p in self.device_profiles.values()]
        }
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"📤 DNS profiles exported to {filename}")

    def print_summary(self):
        """Print DNS snooping summary"""
        print("\n" + "=" * 60)
        print("         📊 DNS SNOOPING SUMMARY")
        print("=" * 60)

        for profile in sorted(self.device_profiles.values(),
                              key=lambda x: len(x.queries), reverse=True)[:10]:
            print(f"\n🔍 {profile.device_name}")
            print(f"   IP: {profile.ip}")
            print(f"   Type: {profile.device_type}")
            print(f"   Queries: {len(profile.queries)}")
            print(f"   Unique domains: {len(set(profile.queries))}")

            # Top domains
            top_domains = defaultdict(int)
            for q in profile.queries:
                top_domains[q] += 1

            print(f"   Top queries:")
            for domain, count in sorted(top_domains.items(), key=lambda x: x[1], reverse=True)[:3]:
                print(f"     - {domain} ({count}x)")

        print("\n" + "=" * 60)