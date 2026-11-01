# Python-Based Network Intrusion Detection System (NIDS)

A Python-based Network Intrusion Detection System (NIDS) that monitors network traffic, analyzes packet activity, identifies suspicious patterns, and displays alerts through a browser-based dashboard.

## Project Overview

This project is designed to demonstrate the fundamentals of network monitoring and intrusion detection using Python and Scapy. It captures live IP traffic and uses rule-based detection to identify unusual packet activity and possible port scanning behavior.

## Features

- **Live Packet Monitoring:** Captures network packets using Scapy.
- **Traffic Analysis:** Tracks source IP addresses, destination ports, and protocols.
- **High Packet Activity Detection:** Generates alerts when a source IP exceeds the configured packet threshold.
- **Possible Port Scan Detection:** Identifies multiple distinct destination ports from a source IP within a configured time window.
- **Alert Management:** Displays alerts with severity levels and timestamps.
- **Protocol Statistics:** Shows TCP, UDP, and other IP traffic statistics.
- **Web Dashboard:** Displays network statistics, recent traffic, and alert history.
- **Simulated Tests:** Allows testing detection rules through dashboard controls.

## Dashboard Screenshots

### Main Dashboard

![NIDS Dashboard](Screenshot%202026-11-01%20171834.png)

### Network Traffic and Statistics

![Network Traffic](Screenshot%202026-11-01%20171854.png)

### Alerts and Monitoring

![Alert Monitoring](Screenshot%202026-11-01%20171905.png)

## Technologies Used

| Technology | Purpose |
|---|---|
| Python | Main programming language |
| Scapy | Network packet capture and analysis |
| Npcap | Packet capture support on Windows |
| HTTPServer | Local web server |
| HTML and CSS | Dashboard interface |
| Threading | Background packet monitoring |

## Installation and Setup

### Requirements

- Windows
- Python 3
- Npcap
- Scapy

### 1. Install Scapy

Open Command Prompt and run:

```bash
python -m pip install scapy
```

### 2. Install Npcap

Download and install Npcap from:

https://npcap.com/

### 3. Clone the Repository

```bash
git clone https://github.com/AjayIT-247/Network-Intrusion-Detection-System.git
```

### 4. Open the Project Folder

```bash
cd Network-Intrusion-Detection-System
```

### 5. Run the Application

Run Command Prompt as Administrator if required for packet capture, then execute:

```bash
python app.py
```

### 6. Open the Dashboard

Visit the following address in your browser:

http://localhost:8000

## Detection Rules

| Detection | Description | Severity |
|---|---|---|
| High Packet Activity | More than 10 packets from one source IP within 10 seconds | Medium |
| Possible Port Scan | 5 or more distinct destination ports from one source IP within 60 seconds | High |

## Project Limitations

- Detection is based on predefined rules.
- Unusual activity may generate false-positive alerts.
- Traffic statistics and alerts are stored in memory and reset when the application restarts.
- This project does not provide advanced deep packet inspection or machine-learning-based detection.
- Packet capture depends on the selected network interface and Windows permissions.

## Future Improvements

- Add network interface selection.
- Store alerts in a database.
- Add IP-based filtering and analysis.
- Improve detection rules.
- Add downloadable alert reports.

## Disclaimer

This project is developed for educational purposes and cybersecurity learning. Monitor only your own network or networks for which you have explicit authorization.

## Author

**Ajay**

Cybersecurity Learner | Python | Network Security

GitHub: https://github.com/AjayIT-247