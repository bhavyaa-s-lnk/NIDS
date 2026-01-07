from flask import Flask, jsonify
import threading
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class DashboardStats:
    """Dashboard statistics container"""
    packets: int = 0
    unique_ips: int = 0
    alerts: int = 0
    top_ips: Dict[str, int] = field(default_factory=dict)
    alert_logs: List[dict] = field(default_factory=list)
    ml_scores: List[float] = field(default_factory=list)
    ml_threshold: float = -0.5
    ip_devices: Dict[str, dict] = field(default_factory=dict)

    def to_dict(self):
        return {
            'packets': self.packets,
            'unique_ips': self.unique_ips,
            'alerts': self.alerts,
            'top_ips': self.top_ips,
            'alert_logs': self.alert_logs,
            'ml_scores': self.ml_scores,
            'ml_threshold': self.ml_threshold,
            'ip_devices': self.ip_devices
        }


class HTMLTemplate:
    """Minimalistic Black & White NIDS Dashboard"""

    STYLE = """
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --bg-primary: #000000;
            --bg-secondary: #0a0a0a;
            --bg-tertiary: #1a1a1a;
            --text-primary: #ffffff;
            --text-secondary: #888888;
            --text-tertiary: #555555;
            --border-color: #2a2a2a;
            --accent: #ffffff;
        }

        body {
            background: var(--bg-primary);
            color: var(--text-primary);
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Helvetica Neue', sans-serif;
            min-height: 100vh;
            overflow-x: hidden;
        }

        .header {
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border-color);
            padding: 20px 40px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            backdrop-filter: blur(10px);
            position: sticky;
            top: 0;
            z-index: 100;
            animation: slideDown 0.6s cubic-bezier(0.34, 1.56, 0.64, 1);
        }

        @keyframes slideDown {
            from { transform: translateY(-100%); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }

        .logo {
            font-size: 1.3rem;
            font-weight: 700;
            letter-spacing: -0.5px;
            color: var(--text-primary);
        }

        .status-indicator {
            width: 8px;
            height: 8px;
            background: var(--text-primary);
            border-radius: 50%;
            animation: pulse 2s ease-in-out infinite;
            margin-left: 8px;
            display: inline-block;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        .container {
            max-width: 1600px;
            margin: 0 auto;
            padding: 60px 40px;
        }

        h1 {
            color: var(--text-primary);
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 60px;
            letter-spacing: -1px;
            animation: fadeInUp 0.8s cubic-bezier(0.34, 1.56, 0.64, 1) 0.1s both;
        }

        @keyframes fadeInUp {
            from { transform: translateY(30px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 24px;
            margin-bottom: 80px;
        }

        .stat-card {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 32px;
            transition: all 0.4s cubic-bezier(0.34, 1.56, 0.64, 1);
            animation: fadeInUp 0.8s cubic-bezier(0.34, 1.56, 0.64, 1) forwards;
            opacity: 0;
        }

        .stat-card:nth-child(1) { animation-delay: 0.15s; }
        .stat-card:nth-child(2) { animation-delay: 0.25s; }
        .stat-card:nth-child(3) { animation-delay: 0.35s; }

        .stat-card:hover {
            background: var(--bg-tertiary);
            border-color: var(--text-primary);
            transform: translateY(-4px);
        }

        .stat-label {
            color: var(--text-secondary);
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            margin-bottom: 12px;
            font-weight: 600;
        }

        .stat-value {
            color: var(--text-primary);
            font-size: 2.8rem;
            font-weight: 700;
            letter-spacing: -1px;
            font-variant-numeric: tabular-nums;
            transition: all 0.3s ease;
        }

        .stat-card:hover .stat-value {
            transform: scale(1.05);
        }

        section {
            margin-bottom: 80px;
            animation: fadeInUp 0.8s cubic-bezier(0.34, 1.56, 0.64, 1) 0.4s both;
        }

        h2 {
            color: var(--text-primary);
            font-size: 1.1rem;
            font-weight: 700;
            margin-bottom: 20px;
            letter-spacing: -0.3px;
            text-transform: uppercase;
            font-size: 0.85rem;
            color: var(--text-secondary);
            letter-spacing: 1.2px;
        }

        .button-group {
            display: flex;
            gap: 12px;
            margin-bottom: 24px;
        }

        .btn {
            padding: 10px 20px;
            border: 1px solid var(--border-color);
            background: var(--bg-secondary);
            color: var(--text-primary);
            border-radius: 8px;
            cursor: pointer;
            font-size: 0.85rem;
            font-weight: 600;
            transition: all 0.3s cubic-bezier(0.34, 1.56, 0.64, 1);
        }

        .btn:hover {
            background: var(--bg-tertiary);
            border-color: var(--text-primary);
            transform: translateY(-2px);
        }

        .btn:active {
            transform: translateY(0);
        }

        .table-wrapper {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            overflow: hidden;
            transition: all 0.3s ease;
        }

        .table-wrapper:hover {
            border-color: var(--text-tertiary);
        }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        thead th {
            background: var(--bg-secondary);
            color: var(--text-secondary);
            padding: 16px 20px;
            text-align: left;
            font-weight: 600;
            font-size: 0.7rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            border-bottom: 1px solid var(--border-color);
        }

        tbody td {
            padding: 16px 20px;
            border-bottom: 1px solid var(--border-color);
            font-size: 0.9rem;
            transition: all 0.2s ease;
        }

        tbody tr {
            transition: all 0.3s ease;
        }

        tbody tr:hover {
            background: var(--bg-tertiary);
        }

        tbody tr:last-child td {
            border-bottom: none;
        }

        .device-name {
            color: var(--text-primary);
            font-weight: 600;
        }

        .ip-addr {
            color: var(--text-secondary);
            font-family: 'Courier New', monospace;
            font-size: 0.85rem;
        }

        .severity-HIGH { 
            color: var(--text-primary);
            font-weight: 700;
            padding: 4px 8px;
            background: var(--bg-tertiary);
            border-radius: 4px;
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .severity-MEDIUM { 
            color: var(--text-primary);
            font-weight: 700;
            padding: 4px 8px;
            background: var(--bg-tertiary);
            border-radius: 4px;
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            opacity: 0.7;
        }

        .severity-LOW { 
            color: var(--text-secondary);
            font-weight: 600;
            padding: 4px 8px;
            background: var(--bg-tertiary);
            border-radius: 4px;
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            opacity: 0.6;
        }

        .chart-wrapper {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 32px;
            transition: all 0.3s ease;
        }

        .chart-wrapper:hover {
            border-color: var(--text-tertiary);
        }

        canvas { 
            max-height: 350px;
            animation: fadeIn 1s ease 0.5s both;
        }

        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.7);
            backdrop-filter: blur(5px);
            overflow-y: auto;
            padding: 40px 20px;
            animation: fadeIn 0.3s ease;
        }

        .modal.active {
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .modal-content {
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 40px;
            width: 90%;
            max-width: 1200px;
            max-height: 85vh;
            overflow-y: auto;
            animation: slideUp 0.4s cubic-bezier(0.34, 1.56, 0.64, 1);
        }

        @keyframes slideUp {
            from { transform: translateY(40px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }

        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 20px;
        }

        .modal-header h2 {
            color: var(--text-primary);
            font-size: 1.3rem;
            margin: 0;
            font-weight: 700;
        }

        .close-btn {
            background: transparent;
            color: var(--text-secondary);
            border: none;
            width: 36px;
            height: 36px;
            cursor: pointer;
            font-size: 1.5rem;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .close-btn:hover {
            color: var(--text-primary);
            transform: rotate(90deg);
        }

        .modal-table {
            width: 100%;
            border-collapse: collapse;
        }

        .modal-table th {
            background: transparent;
            color: var(--text-secondary);
            padding: 14px 16px;
            text-align: left;
            font-weight: 600;
            font-size: 0.7rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            border-bottom: 1px solid var(--border-color);
        }

        .modal-table td {
            padding: 14px 16px;
            border-bottom: 1px solid var(--border-color);
            font-size: 0.9rem;
        }

        .modal-table tr {
            transition: all 0.2s ease;
        }

        .modal-table tr:hover { 
            background: var(--bg-secondary);
        }

        .packet-count { 
            color: var(--text-primary);
            font-weight: 700;
        }

        .empty-state {
            text-align: center;
            padding: 40px 20px;
            color: var(--text-secondary);
        }

        .empty-state p {
            font-size: 0.9rem;
        }

        @media (max-width: 1024px) {
            .stats-grid { grid-template-columns: repeat(2, 1fr); }
            .container { padding: 40px 20px; }
        }

        @media (max-width: 768px) {
            .header { padding: 16px 20px; }
            .container { padding: 30px 16px; }
            h1 { font-size: 1.8rem; margin-bottom: 40px; }
            .stats-grid { grid-template-columns: 1fr; gap: 16px; }
            .stat-card { padding: 24px; }
            .stat-value { font-size: 2rem; }
            .modal-content { padding: 24px; }
        }

        /* Scrollbar styling */
        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }

        ::-webkit-scrollbar-track {
            background: var(--bg-secondary);
        }

        ::-webkit-scrollbar-thumb {
            background: var(--border-color);
            border-radius: 4px;
        }

        ::-webkit-scrollbar-thumb:hover {
            background: var(--text-tertiary);
        }
    """

    @staticmethod
    def render(stats_obj: DashboardStats) -> str:
        return f"""
<!DOCTYPE html>
<html>
<head>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NIDS Dashboard</title>
    <style>{HTMLTemplate.STYLE}</style>
</head>
<body>
    <div class="header">
        <div class="logo">
            🛡️ NIDS
            <span class="status-indicator"></span>
        </div>
    </div>

    <div class="container">
        <h1>Network Intrusion Detection</h1>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">📊 Total Packets</div>
                <div class="stat-value" id="packets">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">🌐 Active IPs</div>
                <div class="stat-value" id="unique_ips">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">⚠️ Alerts</div>
                <div class="stat-value" id="alerts">0</div>
            </div>
        </div>

        <section>
            <h2>Network Activity</h2>
            <div class="button-group">
                <button class="btn" id="showAllBtn">All Talkers</button>
                <button class="btn" id="showAllDevicesBtn">All Devices</button>
            </div>
            <div class="table-wrapper">
                <table id="topTalkersTable">
                    <thead><tr><th>IP Address</th><th>Device</th><th>Type</th><th>Vendor</th><th>Packets</th></tr></thead>
                    <tbody></tbody>
                </table>
            </div>
        </section>

        <section>
            <h2>Recent Alerts</h2>
            <div class="table-wrapper">
                <table id="alertsTable">
                    <thead><tr><th>IP Address</th><th>Device</th><th>Threat Type</th><th>Details</th><th>Severity</th></tr></thead>
                    <tbody></tbody>
                </table>
            </div>
        </section>

        <section>
            <h2>Anomaly Detection</h2>
            <div class="chart-wrapper">
                <canvas id="mlChart" height="80"></canvas>
            </div>
        </section>
    </div>

    <div id="allTalkersModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>All Network Talkers</h2>
                <button class="close-btn" id="closeModal">✕</button>
            </div>
            <table class="modal-table">
                <thead><tr><th>IP Address</th><th>Device</th><th>Type</th><th>Vendor</th><th>MAC Address</th><th>Packets</th></tr></thead>
                <tbody id="allTalkersTableBody"></tbody>
            </table>
        </div>
    </div>

    <div id="allDevicesModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>All Connected Devices</h2>
                <button class="close-btn" id="closeDevicesModal">✕</button>
            </div>
            <table class="modal-table">
                <thead><tr><th>IP Address</th><th>Device</th><th>Type</th><th>Vendor</th><th>MAC Address</th><th>Activity</th></tr></thead>
                <tbody id="allDevicesTableBody"></tbody>
            </table>
        </div>
    </div>

    <script>{HTMLTemplate.get_javascript()}</script>
</body>
</html>
"""

    @staticmethod
    def get_javascript() -> str:
        return """
let mlChart = null;
let displayData = [];
let allScores = [];
let threshold = -0.5;
let lastDataLength = 0;

const modals = {
    talkers: document.getElementById('allTalkersModal'),
    devices: document.getElementById('allDevicesModal')
};

document.getElementById('showAllBtn').addEventListener('click', () => {
    modals.talkers.classList.add('active');
});

document.getElementById('closeModal').addEventListener('click', () => {
    modals.talkers.classList.remove('active');
});

document.getElementById('showAllDevicesBtn').addEventListener('click', () => {
    modals.devices.classList.add('active');
});

document.getElementById('closeDevicesModal').addEventListener('click', () => {
    modals.devices.classList.remove('active');
});

window.addEventListener('click', (e) => {
    if (e.target === modals.talkers) modals.talkers.classList.remove('active');
    if (e.target === modals.devices) modals.devices.classList.remove('active');
});

function initChart() {
    const ctx = document.getElementById('mlChart').getContext('2d');
    mlChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Anomaly Score',
                    data: [],
                    borderWidth: 2,
                    tension: 0.4,
                    borderColor: '#ffffff',
                    backgroundColor: 'rgba(255, 255, 255, 0.05)',
                    pointRadius: 0,
                    pointHoverRadius: 6,
                    pointBackgroundColor: '#ffffff',
                    pointBorderColor: '#000000',
                    pointBorderWidth: 2,
                    fill: true,
                    spanGaps: false
                },
                {
                    label: 'Threshold',
                    data: [],
                    borderWidth: 1.5,
                    borderDash: [5, 5],
                    borderColor: 'rgba(255, 255, 255, 0.2)',
                    backgroundColor: 'transparent',
                    pointRadius: 0,
                    fill: false,
                    spanGaps: false
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            animation: false,
            interaction: { intersect: false, mode: 'index' },
            plugins: {
                legend: {
                    display: true,
                    position: 'top',
                    labels: { 
                        color: '#888888', 
                        font: { size: 11, weight: '600' }, 
                        padding: 16, 
                        usePointStyle: true,
                        pointStyle: 'circle'
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(10, 10, 10, 0.95)',
                    titleColor: '#ffffff',
                    bodyColor: '#cccccc',
                    borderColor: '#2a2a2a',
                    borderWidth: 1,
                    padding: 12,
                    titleFont: { size: 12, weight: '600' },
                    bodyFont: { size: 11 },
                    displayColors: true,
                    usePointStyle: true
                }
            },
            scales: {
                y: {
                    ticks: { color: '#555555', font: { size: 10 } },
                    grid: { color: 'rgba(255, 255, 255, 0.05)', drawBorder: false },
                    border: { display: false }
                },
                x: {
                    ticks: { color: '#555555', font: { size: 10 } },
                    grid: { color: 'rgba(255, 255, 255, 0.05)', drawBorder: false },
                    border: { display: false }
                }
            }
        }
    });
    animateHeartbeat();
}

function animateHeartbeat() {
    const windowSize = 60;

    if (allScores.length > lastDataLength) {
        lastDataLength = allScores.length;
        if (displayData.length > 0) {
            const lastDisplayed = displayData[displayData.length - 1];
            const newValue = allScores[allScores.length - 1];
            for (let i = 1; i <= 5; i++) {
                const progress = i / 5;
                const interpolated = lastDisplayed + (newValue - lastDisplayed) * progress;
                displayData.push(interpolated);
            }
        } else {
            displayData.push(allScores[allScores.length - 1]);
        }
    }

    const startIndex = Math.max(0, displayData.length - windowSize);
    const windowData = displayData.slice(startIndex);

    mlChart.data.datasets[0].data = windowData;
    mlChart.data.labels = windowData.map((_, i) => startIndex + i);
    mlChart.data.datasets[1].data = windowData.map(() => threshold);
    mlChart.update('none');
    requestAnimationFrame(animateHeartbeat);
}

async function updateDashboard() {
    try {
        const [statsRes, mlRes] = await Promise.all([fetch('/api/stats'), fetch('/ml_data')]);
        const stats = await statsRes.json();
        const mlData = await mlRes.json();

        document.getElementById('packets').textContent = stats.packets.toLocaleString();
        document.getElementById('unique_ips').textContent = stats.unique_ips;
        document.getElementById('alerts').textContent = stats.alerts;

        updateTable('topTalkersTable', stats, true);
        updateTable('alertsTable', stats, false);
        updateModals(stats);

        if (mlData.scores.length > 0) {
            threshold = mlData.threshold;
            allScores = mlData.scores;
            if (displayData.length === 0) {
                displayData = mlData.scores.slice();
                lastDataLength = mlData.scores.length;
            }
        }
    } catch(e) { console.error(e); }
}

function updateTable(id, stats, isTop) {
    const tbody = document.querySelector(`#${id} tbody`);

    let rows = [];
    if (isTop) {
        rows = Object.entries(stats.top_ips).map(([ip, count]) => {
            const d = stats.ip_devices[ip] || {};
            return [
                `<span class="ip-addr">${ip}</span>`,
                `<span class="device-name">${d.device_name || '—'}</span>`,
                d.device_type || '—',
                d.vendor || '—',
                count
            ];
        });
    } else {
        rows = stats.alert_logs.slice(-5).map(a => [
            `<span class="ip-addr">${a.src}</span>`,
            `<span class="device-name">${a.device}</span>`,
            a.type,
            a.desc,
            `<span class="severity-${a.severity}">${a.severity}</span>`
        ]);
    }

    tbody.innerHTML = rows.length > 0
        ? rows.map(cells => `<tr>${cells.map(cell => `<td>${cell}</td>`).join('')}</tr>`).join('')
        : `<tr><td colspan="5" class="empty-state"><p>No data available</p></td></tr>`;
}

function updateModals(stats) {
    const mkRow = (ip, d, count) => [
        `<span class="ip-addr">${ip}</span>`,
        `<span class="device-name">${d.device_name}</span>`,
        d.device_type || '—',
        d.vendor,
        `<span style="color:#555555;font-size:0.85em">${d.last_bytes || '—'}</span>`,
        `<span class="packet-count">${count}</span>`
    ];

    const sorted = Object.entries(stats.ip_devices).sort((a, b) => 
        (stats.top_ips[b[0]] || 0) - (stats.top_ips[a[0]] || 0)
    );

    document.getElementById('allTalkersTableBody').innerHTML = sorted
        .map(([ip, d]) => `<tr>${mkRow(ip, d, stats.top_ips[ip] || 0).map(cell => `<td>${cell}</td>`).join('')}</tr>`)
        .join('');

    const byName = Object.entries(stats.ip_devices).sort((a, b) => 
        a[1].device_name.localeCompare(b[1].device_name)
    );

    document.getElementById('allDevicesTableBody').innerHTML = byName
        .map(([ip, d]) => `<tr>${mkRow(ip, d, stats.top_ips[ip] || 0).map(cell => `<td>${cell}</td>`).join('')}</tr>`)
        .join('');
}

window.addEventListener('load', () => {
    initChart();
    updateDashboard();
    setInterval(updateDashboard, 1000);
});

window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        modals.talkers.classList.remove('active');
        modals.devices.classList.remove('active');
    }
});
"""


class DashboardServer:
    def __init__(self, stats: DashboardStats):
        self.app = Flask(__name__)
        self.stats = stats
        self.setup_routes()

    def setup_routes(self):
        @self.app.route("/")
        def dashboard():
            return HTMLTemplate.render(self.stats)

        @self.app.route("/api/stats")
        def api_stats():
            return jsonify(self.stats.to_dict())

        @self.app.route("/ml_data")
        def ml_data():
            return jsonify({"scores": self.stats.ml_scores, "threshold": self.stats.ml_threshold})

    def start_background(self):
        threading.Thread(target=lambda: self.app.run(debug=False, use_reloader=False), daemon=True).start()


stats = DashboardStats()


def start_dashboard():
    DashboardServer(stats).start_background()
    print("🔍 Dashboard: http://127.0.0.1:5000")