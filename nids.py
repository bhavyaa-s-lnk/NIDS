# =========================
# NETWORK INTRUSION DETECTION SYSTEM
# =========================
from ml_detector import MLAnomalyDetector
from web_dashboard import start_dashboard, stats
from logger import AlertLogger
from rules import DetectionRules
from device_manager import DeviceManager
from dns_snooper import DNSSnooper
import signal
import time
import sys
import threading
import os
from scapy.all import sniff, IP, TCP, ICMP, Ether
from collections import defaultdict


class NIDS:
    """Network Intrusion Detection System with ML anomaly detection"""

    def __init__(self):
        self.logger = AlertLogger()
        self.logger.log("SYSTEM", "NIDS_STARTED", "IDS initialized")

        self.alert_count = 0
        self.packet_count = defaultdict(int)
        self.rules = DetectionRules()
        self.ml_detector = MLAnomalyDetector()
        self.device_manager = DeviceManager()
        self.dns_snooper = DNSSnooper()

    def dashboard(self):
        """Display CLI dashboard"""
        while True:
            os.system("cls" if os.name == "nt" else "clear")
            print("=" * 60)
            print("        🚨 PYTHON NIDS DASHBOARD")
            print("=" * 60)

            total_packets = sum(self.packet_count.values())
            print(f"Packets captured : {total_packets}")
            print(f"Unique IPs       : {self.device_manager.get_online_count()}")
            print(f"Alerts raised    : {self.alert_count}\n")

            print("Top Talkers:")
            for device in self.device_manager.get_top_talkers(5):
                flag = "🚩" if device.is_flagged else "  "
                print(f"  {flag} {device.ip:<15} | {device.device_name:<30} | {device.packet_count} packets")

            print("\nStatus: RUNNING")
            print("=" * 60)
            time.sleep(1)

    def process_packet(self, packet):
        """Process incoming packet for threats and device info"""
        if IP not in packet:
            return

        # Snoop DNS queries for device fingerprinting
        self.dns_snooper.process_dns_packet(packet)

        src_ip = packet[IP].src
        self.packet_count[src_ip] += 1

        # Extract MAC address
        src_mac = None
        if Ether in packet:
            src_mac = packet[Ether].src

        # Add or update device
        device = None
        if src_mac:
            device = self.device_manager.add_or_update_device(src_ip, src_mac)

            # Update device name from DNS fingerprinting
            dns_profile = self.dns_snooper.get_device_profile(src_ip)
            if dns_profile and dns_profile.device_type != "Unknown":
                if "Unknown" in device.device_name:
                    device.device_name = dns_profile.device_name
                    device.device_type = dns_profile.device_type

        # Update stats
        stats.packets = self.device_manager.get_total_packets()
        stats.unique_ips = self.device_manager.get_online_count()
        stats.top_ips = self.device_manager.get_top_ips(5)
        stats.ip_devices = self.device_manager.get_devices_as_dict()
        stats.alerts = self.alert_count

        # ==== THREAT DETECTION ====

        # TCP threats
        if TCP in packet:
            dst_port = packet[TCP].dport

            if self.rules.check_port_scan(src_ip, dst_port):
                self.alert(src_ip, "Port Scan Detected", "Multiple ports accessed", device)

            if packet[TCP].flags == "S":
                if self.rules.check_syn_flood(src_ip):
                    self.alert(src_ip, "SYN Flood Detected", "Excessive SYN packets", device)

        # ICMP threats
        if ICMP in packet:
            if self.rules.check_icmp_flood(src_ip):
                self.alert(src_ip, "ICMP Flood Detected", "Too many ICMP packets", device)

        # ==== ML ANOMALY DETECTION ====

        features = self.ml_detector.extract_features(src_ip, packet)
        self.ml_detector.collect(features)

        is_anomaly, score = self.ml_detector.predict(features)
        severity = self.ml_detector.get_severity(score)

        # Add score to graph
        if score is not None:
            stats.ml_scores.append(score)
            if len(stats.ml_scores) > 100:
                stats.ml_scores.pop(0)

        # Alert if anomaly detected
        if is_anomaly:
            self.alert(
                src_ip,
                "ML Anomaly Detected",
                f"Score: {score:.4f}",
                device,
                severity
            )

    def alert(self, src_ip, attack_type, description, device=None, severity="LOW"):
        """Log an alert"""
        self.alert_count += 1

        device_name = device.device_name if device else "Unknown"

        stats.alert_logs.append({
            "src": src_ip,
            "device": device_name,
            "type": attack_type,
            "desc": description,
            "severity": severity
        })

        # Flag the device
        if device and "Detected" in attack_type:
            self.device_manager.flag_device(src_ip, f"{attack_type}: {severity}")

        self.logger.log(
            src_ip,
            attack_type,
            f"{description} | SEVERITY: {severity} | DEVICE: {device_name}"
        )

    def start(self):
        """Start NIDS"""
        signal.signal(signal.SIGINT, self.shutdown)

        print("🚨 NIDS Started... Monitoring Network Traffic\n")

        # Start web dashboard
        start_dashboard()

        # Start CLI dashboard
        dashboard_thread = threading.Thread(
            target=self.dashboard,
            daemon=True
        )
        dashboard_thread.start()

        # Start packet sniffing (blocking)
        print("📡 Starting packet capture...\n")
        sniff(prn=self.process_packet, store=False)

    def shutdown(self, sig, frame):
        """Shutdown NIDS and export data"""
        print("\n🛑 NIDS stopped")
        print(f"Total packets analyzed : {self.device_manager.get_total_packets()}")
        print(f"Unique IPs detected    : {self.device_manager.get_online_count()}")
        print(f"Alerts raised          : {self.alert_count}")

        print(f"Flagged devices        : {len(self.device_manager.get_flagged_devices())}")

        # Export data
        self.device_manager.export_devices()
        self.dns_snooper.export_profiles()
        self.dns_snooper.print_summary()

        sys.exit(0)


if __name__ == "__main__":
    nids = NIDS()
    nids.start()