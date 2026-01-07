import time
from dataclasses import dataclass, asdict
from typing import Dict, List
from mac_lookup import MACLookup


@dataclass
class Device:
    """Represents a network device"""
    ip: str
    mac: str
    device_name: str
    vendor: str
    device_type: str
    last_3_bytes: str
    first_seen: float
    last_seen: float
    packet_count: int = 0
    is_flagged: bool = False
    flag_reason: str = None

    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        return {
            'ip': self.ip,
            'mac': self.mac,
            'device_name': self.device_name,
            'vendor': self.vendor,
            'device_type': self.device_type,
            'last_bytes': self.last_3_bytes,
            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
            'packet_count': self.packet_count,
            'is_flagged': self.is_flagged,
            'flag_reason': self.flag_reason
        }


class DeviceManager:
    """Manages all devices on the network"""

    def __init__(self):
        self.devices: Dict[str, Device] = {}  # IP -> Device
        self.mac_lookup = MACLookup()

    def add_or_update_device(self, ip: str, mac: str) -> Device:
        """Add new device or update existing one"""
        current_time = time.time()

        if ip in self.devices:
            # Update existing device
            device = self.devices[ip]
            device.last_seen = current_time
            device.packet_count += 1
            return device
        else:
            # Create new device with MAC lookup
            mac_info = self.mac_lookup.lookup(mac, ip)

            device = Device(
                ip=ip,
                mac=mac,
                device_name=mac_info.nickname,
                vendor=mac_info.vendor,
                device_type=mac_info.device_type,
                last_3_bytes=mac_info.last_3_bytes,
                first_seen=current_time,
                last_seen=current_time,
                packet_count=1
            )

            self.devices[ip] = device
            print(f"🆕 New device: {ip} | {mac_info.nickname} | Type: {mac_info.device_type}")
            return device

    def get_device(self, ip: str) -> Device:
        """Get device by IP"""
        return self.devices.get(ip)

    def get_all_devices(self) -> List[Device]:
        """Get all devices sorted by packet count (descending)"""
        return sorted(
            self.devices.values(),
            key=lambda d: d.packet_count,
            reverse=True
        )

    def get_top_talkers(self, count: int = 5) -> List[Device]:
        """Get top N most active devices"""
        return self.get_all_devices()[:count]

    def get_devices_as_dict(self) -> Dict[str, dict]:
        """Get all devices as dictionaries (for JSON)"""
        return {
            ip: device.to_dict()
            for ip, device in self.devices.items()
        }

    def get_top_ips(self, count: int = 5) -> Dict[str, int]:
        """Get top IPs with packet counts"""
        top = self.get_top_talkers(count)
        return {
            device.ip: device.packet_count
            for device in top
        }

    def flag_device(self, ip: str, reason: str):
        """Flag a device as suspicious"""
        if ip in self.devices:
            device = self.devices[ip]
            device.is_flagged = True
            device.flag_reason = reason
            print(f"🚩 Device flagged: {ip} - {reason}")

    def unflag_device(self, ip: str):
        """Remove flag from device"""
        if ip in self.devices:
            device = self.devices[ip]
            device.is_flagged = False
            device.flag_reason = None

    def get_flagged_devices(self) -> List[Device]:
        """Get all flagged/suspicious devices"""
        return [d for d in self.devices.values() if d.is_flagged]

    def get_online_count(self) -> int:
        """Get count of online devices"""
        return len(self.devices)

    def get_total_packets(self) -> int:
        """Get total packets from all devices"""
        return sum(d.packet_count for d in self.devices.values())

    def export_devices(self, filename: str = "devices.json"):
        """Export all devices to JSON file"""
        import json
        data = {
            'timestamp': time.time(),
            'total_devices': len(self.devices),
            'devices': self.get_devices_as_dict()
        }
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"📤 Devices exported to {filename}")