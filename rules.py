import time

class DetectionRules:
    def __init__(self):
        self.port_scan = {}
        self.icmp_flood = {}
        self.syn_flood = {}

        self.PORT_SCAN_THRESHOLD = 20
        self.ICMP_FLOOD_THRESHOLD = 10
        self.SYN_FLOOD_THRESHOLD = 15
        self.TIME_WINDOW = 10

    def check_port_scan(self, src_ip, dst_port):
        if src_ip not in self.port_scan:
            self.port_scan[src_ip] = set()

        self.port_scan[src_ip].add(dst_port)
        return len(self.port_scan[src_ip]) >= self.PORT_SCAN_THRESHOLD

    def check_icmp_flood(self, src_ip):
        now = time.time()

        if src_ip not in self.icmp_flood:
            self.icmp_flood[src_ip] = []

        self.icmp_flood[src_ip].append(now)

        self.icmp_flood[src_ip] = [
            t for t in self.icmp_flood[src_ip]
            if now - t <= self.TIME_WINDOW
        ]

        return len(self.icmp_flood[src_ip]) >= self.ICMP_FLOOD_THRESHOLD

    def check_syn_flood(self, src_ip):
        now = time.time()

        if src_ip not in self.syn_flood:
            self.syn_flood[src_ip] = []

        self.syn_flood[src_ip].append(now)

        self.syn_flood[src_ip] = [
            t for t in self.syn_flood[src_ip]
            if now - t <= self.TIME_WINDOW
        ]

        return len(self.syn_flood[src_ip]) >= self.SYN_FLOOD_THRESHOLD
