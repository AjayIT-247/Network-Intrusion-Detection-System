
from http.server import HTTPServer, BaseHTTPRequestHandler
from scapy.all import sniff, IP, TCP, UDP
from threading import Thread, Lock
from collections import deque
from datetime import datetime
from html import escape
import time


# ==========================================
# 1. IDS CONFIGURATION
# ==========================================

PORT_THRESHOLD = 5
PACKET_THRESHOLD = 10

PACKET_TIME_WINDOW = 10
PORT_TIME_WINDOW = 60

MAX_TRAFFIC_RECORDS = 20
MAX_ALERT_RECORDS = 100

packet_count = 0
alert_count = 0

protocol_stats = {
    "TCP": 0,
    "UDP": 0,
    "OTHER": 0
}

ip_packets = {}
ip_ports = {}

packet_times = {}
port_times = {}

last_port_alert = {}

alerts = []
recent_traffic = []

capture_status = "Starting"

data_lock = Lock()


# ==========================================
# 2. ALERT SYSTEM
# ==========================================

def generate_alert(message, severity):

    global alert_count

    alert = {
        "message": message,
        "severity": severity,
        "time": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    }

    with data_lock:

        alert_count += 1
        alerts.append(alert)

        if len(alerts) > MAX_ALERT_RECORDS:
            alerts.pop(0)

    print(f"[{severity}] {message}")


# ==========================================
# 3. PACKET ANALYSIS
# ==========================================

def analyze_packet(
    source_ip,
    destination_port,
    protocol,
    traffic_type="LIVE"
):

    global packet_count

    current_time = time.time()

    # Update packet statistics

    with data_lock:

        packet_count += 1

        protocol_stats[protocol] += 1

        ip_packets[source_ip] = (
            ip_packets.get(source_ip, 0) + 1
        )

        # Store recent packet information

        traffic = {
            "source": source_ip,
            "port": (
                destination_port
                if destination_port is not None
                else "N/A"
            ),
            "protocol": protocol,
            "type": traffic_type,
            "time": datetime.now().strftime("%H:%M:%S")
        }

        recent_traffic.append(traffic)

        if len(recent_traffic) > MAX_TRAFFIC_RECORDS:
            recent_traffic.pop(0)

        # Maintain packet timestamps for each IP

        if source_ip not in packet_times:
            packet_times[source_ip] = deque()

        packet_times[source_ip].append(current_time)

        while (
            packet_times[source_ip]
            and current_time - packet_times[source_ip][0]
            > PACKET_TIME_WINDOW
        ):

            packet_times[source_ip].popleft()

        recent_packet_total = len(
            packet_times[source_ip]
        )

        # Maintain destination port history

        unique_ports = 0
        should_check_ports = destination_port is not None

        if should_check_ports:

            if source_ip not in port_times:
                port_times[source_ip] = deque()

            port_times[source_ip].append(
                (current_time, destination_port)
            )

            while (
                port_times[source_ip]
                and current_time - port_times[source_ip][0][0]
                > PORT_TIME_WINDOW
            ):

                port_times[source_ip].popleft()

            ip_ports[source_ip] = {
                port for packet_time, port
                in port_times[source_ip]
            }

            unique_ports = len(ip_ports[source_ip])

        # Check port alert cooldown

        port_alert_allowed = (
            source_ip not in last_port_alert
            or current_time - last_port_alert[source_ip]
            > PORT_TIME_WINDOW
        )

        if (
            unique_ports >= PORT_THRESHOLD
            and port_alert_allowed
        ):

            last_port_alert[source_ip] = current_time
            port_alert = True

        else:
            port_alert = False

        # Packet activity threshold

        packet_alert = (
            recent_packet_total == PACKET_THRESHOLD + 1
        )

    # Generate alerts outside the data lock

    if packet_alert:

        generate_alert(
            f"High packet activity from {source_ip}",
            "MEDIUM"
        )

    if port_alert:

        generate_alert(
            f"Possible Port Scan activity from {source_ip}",
            "HIGH"
        )


# ==========================================
# 4. LIVE PACKET CAPTURE
# ==========================================

def capture_packet(packet):

    if IP not in packet:
        return

    source_ip = packet[IP].src

    destination_port = None
    protocol = "OTHER"

    if TCP in packet:

        destination_port = packet[TCP].dport
        protocol = "TCP"

    elif UDP in packet:

        destination_port = packet[UDP].dport
        protocol = "UDP"

    analyze_packet(
        source_ip,
        destination_port,
        protocol,
        "LIVE"
    )


def start_capture():

    global capture_status

    print("Starting live packet capture...")

    try:

        with data_lock:
            capture_status = "Running"

        sniff(
            prn=capture_packet,
            store=False
        )

    except Exception as error:

        with data_lock:
            capture_status = "Error"

        print("Packet capture error:", error)


# ==========================================
# 5. DASHBOARD
# ==========================================

class Dashboard(BaseHTTPRequestHandler):

    def do_GET(self):

        # Simulated port test

        if self.path.startswith("/test/"):

            try:

                port = int(self.path.split("/")[-1])

                if 1 <= port <= 65535:

                    analyze_packet(
                        "192.168.1.10",
                        port,
                        "TCP",
                        "SIMULATED"
                    )

            except ValueError:
                pass

        # Simulated high packet activity test

        elif self.path == "/high-activity":

            for i in range(11):

                analyze_packet(
                    "192.168.1.20",
                    80,
                    "TCP",
                    "SIMULATED"
                )

        # Read dashboard data safely

        with data_lock:

            current_packets = packet_count
            current_alerts = alert_count

            current_protocols = protocol_stats.copy()

            current_history = list(alerts)
            current_traffic = list(recent_traffic)

            current_status = capture_status

        # ==================================
        # BUILD ALERT TABLE
        # ==================================

        alert_html = ""

        for alert in reversed(current_history):

            severity = escape(alert["severity"])
            message = escape(alert["message"])
            alert_time = escape(alert["time"])

            alert_html += f"""
            <tr>
                <td class="{severity.lower()}">
                    {severity}
                </td>

                <td>{message}</td>

                <td>{alert_time}</td>
            </tr>
            """

        if not alert_html:

            alert_html = """
            <tr>
                <td colspan="3">
                    No alerts detected yet
                </td>
            </tr>
            """

        # ==================================
        # BUILD NETWORK TRAFFIC TABLE
        # ==================================

        traffic_html = ""

        for traffic in reversed(current_traffic):

            source = escape(str(traffic["source"]))
            port = escape(str(traffic["port"]))
            protocol = escape(str(traffic["protocol"]))
            traffic_type = escape(str(traffic["type"]))
            traffic_time = escape(str(traffic["time"]))

            traffic_html += f"""
            <tr>
                <td>{source}</td>
                <td>{port}</td>
                <td>{protocol}</td>
                <td>{traffic_type}</td>
                <td>{traffic_time}</td>
            </tr>
            """

        if not traffic_html:

            traffic_html = """
            <tr>
                <td colspan="5">
                    No network traffic recorded yet
                </td>
            </tr>
            """

        # ==================================
        # PROTOCOL STATISTICS
        # ==================================

        total = max(current_packets, 1)

        tcp_width = (
            current_protocols["TCP"] / total
        ) * 100

        udp_width = (
            current_protocols["UDP"] / total
        ) * 100

        other_width = (
            current_protocols["OTHER"] / total
        ) * 100

        # ==================================
        # HTML DASHBOARD
        # ==================================

        html = f"""
        <!DOCTYPE html>

        <html>

        <head>

            <title>Network IDS Dashboard</title>

            <meta
                http-equiv="refresh"
                content="3"
            >

            <meta
                name="viewport"
                content="width=device-width, initial-scale=1"
            >

            <style>

                * {{
                    box-sizing: border-box;
                }}

                body {{
                    background: #101827;
                    color: white;
                    font-family: Arial, sans-serif;
                    padding: 25px;
                    margin: 0;
                }}

                h1 {{
                    color: #38bdf8;
                }}

                h2 {{
                    color: #e2e8f0;
                }}

                .card {{
                    background: #1e293b;
                    padding: 20px;
                    margin: 18px 0;
                    border-radius: 10px;
                    overflow-x: auto;
                }}

                .stats {{
                    display: grid;
                    grid-template-columns:
                        repeat(auto-fit, minmax(180px, 1fr));
                    gap: 15px;
                }}

                .stat-box {{
                    background: #334155;
                    padding: 18px;
                    border-radius: 8px;
                }}

                .stat-box h3 {{
                    color: #94a3b8;
                }}

                .stat-box p {{
                    font-size: 25px;
                    color: #38bdf8;
                    font-weight: bold;
                }}

                button {{
                    background: #0284c7;
                    color: white;
                    border: none;
                    padding: 12px;
                    margin: 5px;
                    cursor: pointer;
                    border-radius: 5px;
                }}

                button:hover {{
                    background: #0369a1;
                }}

                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 15px;
                    min-width: 550px;
                }}

                th, td {{
                    padding: 12px;
                    text-align: left;
                    border-bottom: 1px solid #475569;
                }}

                th {{
                    color: #38bdf8;
                }}

                .high {{
                    color: #f87171;
                    font-weight: bold;
                }}

                .medium {{
                    color: #facc15;
                    font-weight: bold;
                }}

                .low {{
                    color: #4ade80;
                    font-weight: bold;
                }}

                .bar-background {{
                    background: #334155;
                    width: 100%;
                    height: 14px;
                    border-radius: 10px;
                    margin: 8px 0 18px;
                    overflow: hidden;
                }}

                .bar {{
                    height: 14px;
                    border-radius: 10px;
                }}

                .tcp {{
                    background: #38bdf8;
                }}

                .udp {{
                    background: #4ade80;
                }}

                .other {{
                    background: #facc15;
                }}

                .status {{
                    color: #4ade80;
                    font-weight: bold;
                }}

                small {{
                    color: #94a3b8;
                }}

            </style>

        </head>

        <body>

            <h1>
                Network Intrusion Detection System
            </h1>

            <!-- MONITORING STATUS -->

            <div class="card">

                <h2>Monitoring Status</h2>

                <p>
                    Dashboard:
                    <span class="status">Running</span>
                </p>

                <p>
                    Live Capture:
                    <strong>{escape(current_status)}</strong>
                </p>

            </div>

            <!-- NETWORK STATISTICS -->

            <div class="card">

                <h2>Network Statistics</h2>

                <div class="stats">

                    <div class="stat-box">

                        <h3>Total Packets</h3>

                        <p>{current_packets}</p>

                    </div>

                    <div class="stat-box">

                        <h3>Security Alerts</h3>

                        <p>{current_alerts}</p>

                    </div>

                    <div class="stat-box">

                        <h3>TCP Packets</h3>

                        <p>{current_protocols["TCP"]}</p>

                    </div>

                    <div class="stat-box">

                        <h3>UDP Packets</h3>

                        <p>{current_protocols["UDP"]}</p>

                    </div>

                </div>

            </div>

            <!-- PROTOCOL CHART -->

            <div class="card">

                <h2>Protocol Distribution</h2>

                <p>
                    TCP: {current_protocols["TCP"]}
                </p>

                <div class="bar-background">

                    <div
                        class="bar tcp"
                        style="width: {tcp_width:.2f}%"
                    ></div>

                </div>

                <p>
                    UDP: {current_protocols["UDP"]}
                </p>

                <div class="bar-background">

                    <div
                        class="bar udp"
                        style="width: {udp_width:.2f}%"
                    ></div>

                </div>

                <p>
                    OTHER: {current_protocols["OTHER"]}
                </p>

                <div class="bar-background">

                    <div
                        class="bar other"
                        style="width: {other_width:.2f}%"
                    ></div>

                </div>

            </div>

            <!-- SIMULATED TESTS -->

            <div class="card">

                <h2>Simulated Detection Tests</h2>

                <p>
                    Use these buttons to test the detection rules.
                </p>

                <a href="/test/80">
                    <button>Port 80</button>
                </a>

                <a href="/test/443">
                    <button>Port 443</button>
                </a>

                <a href="/test/22">
                    <button>Port 22</button>
                </a>

                <a href="/test/21">
                    <button>Port 21</button>
                </a>

                <a href="/test/8080">
                    <button>Port 8080</button>
                </a>

                <br><br>

                <a href="/high-activity">
                    <button>Test High Activity</button>
                </a>

            </div>

            <!-- RECENT NETWORK TRAFFIC -->

            <div class="card">

                <h2>Recent Network Traffic</h2>

                <table>

                    <tr>
                        <th>Source IP</th>
                        <th>Destination Port</th>
                        <th>Protocol</th>
                        <th>Traffic Type</th>
                        <th>Time</th>
                    </tr>

                    {traffic_html}

                </table>

                <small>
                    Showing the latest 20 records.
                </small>

            </div>

            <!-- ALERT HISTORY -->

            <div class="card">

                <h2>Security Alert History</h2>

                <table>

                    <tr>
                        <th>Severity</th>
                        <th>Alert Message</th>
                        <th>Timestamp</th>
                    </tr>

                    {alert_html}

                </table>

            </div>

            <p>
                <small>
                    Educational IDS project.
                    Detection results are rule-based and may
                    include false positives.
                </small>
            </p>

        </body>

        </html>
        """

        self.send_response(200)

        self.send_header(
            "Content-type",
            "text/html; charset=utf-8"
        )

        self.end_headers()

        self.wfile.write(
            html.encode("utf-8")
        )


# ==========================================
# 6. START PROJECT
# ==========================================

if __name__ == "__main__":

    capture_thread = Thread(
        target=start_capture,
        daemon=True
    )

    capture_thread.start()

    server = HTTPServer(
        ("localhost", 8000),
        Dashboard
    )

    print("--------------------------------")
    print("NETWORK IDS STARTED")
    print("--------------------------------")
    print("Dashboard: http://localhost:8000")
    print("Live capture: Starting")
    print("Press CTRL+C to stop")
    print("--------------------------------")

    try:

        server.serve_forever()

    except KeyboardInterrupt:

        print("\nStopping Network IDS...")

        server.server_close()

        print("Network IDS stopped.")
