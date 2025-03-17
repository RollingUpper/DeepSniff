Network Traffic Monitor

Overview

This is a Python-based network traffic monitoring tool that captures and analyzes packets using Scapy. It logs network activity into an SQLite database and provides security insights via DeepSeek.

Features

Packet Sniffing: Captures network packets in real-time.

Traffic Logging: Stores packet data in an SQLite database.

Security Analysis: Uses DeepSeek AI for potential threat detection.

Command-line UI: Interactive terminal-based interface.

Installation

Prerequisites

Ensure you have the following installed:

Python 3.x

Scapy (pip install scapy)

SQLite3 (included with Python)

Setup

Clone the repository:

git clone https://github.com/yourusername/network-monitor.git
cd network-monitor

Install dependencies:

pip install -r requirements.txt

Run the program:

python network_monitor.py

Usage

Start monitoring with:

sudo python network_monitor.py

Logs are saved in network_logs.db.

Security Notice

Ensure you do not expose API keys in the code.

Run the program with appropriate permissions.

Future Enhancements

Implement a real-time firewall rule suggestion system.

Add a web-based UI for easier monitoring.

License

This project is licensed under the MIT License.

Contributors

Your Name

