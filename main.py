import scapy.all as scapy
import datetime
import json
import os
import threading
import time
import logging
import sqlite3
import requests
import asyncio
from DeeperSeek import DeepSeek
from collections import defaultdict

# Configuration: Output log files
LOG_FILE = "traffic_log.json"
UNIQUE_IPS_LOG_FILE = "unique_ips_log.txt"
SNIFFER_OUTPUT_FILE = "sniffer_output.log"
DB_FILE = "ip_data.db"
API_URL = "http://ip-api.com/json/"
THREAT_ANALYSIS_FILE = "ip_threat_analysis.txt"

# DeepSeek credentials
DEEPSEEK_CREDS = {
    "email": "YOUR TOKEN",
    "password": "YOUR PASSWORD",
    "token": "YOUR TOKEN"
}

# Port scan detection parameters
SCAN_THRESHOLD = 10
TIME_WINDOW = datetime.timedelta(seconds=10)
sniffer_running = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
    handlers=[logging.FileHandler("network_traffic.log"), logging.StreamHandler()]
)

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ip_info (
            ip TEXT PRIMARY KEY,
            country TEXT,
            region TEXT,
            city TEXT,
            isp TEXT,
            org TEXT,
            as_info TEXT,
            ports TEXT, 
            analysis TEXT
        )
    """)
    conn.commit()
    conn.close()

async def get_security_analysis(api, ip, port):
    """Get security analysis with port context"""
    prompt = f"""Provide a security analysis of IP {ip} interacting with port {port} using this format:
    IP Address: {ip}
    Port: {port} (Service: [service name])
    Company: [company]
    Provider: [provider]
    Country: [country]
    Threat Level: [Low/Medium/High/Critical]
    Analysis: [brief summary]"""
    
    response = await api.send_message(
        prompt, deepthink=False, search=False, 
        slow_mode=False, timeout=60
    )
    return response.text.strip()


async def process_ips_with_deepseek():
    """Fetch IP info with ports and analyze with DeepSeek"""
    print("\n[!] Initializing DeepSeek API...")
    api = DeepSeek(**DEEPSEEK_CREDS, headless=True)
    await api.initialize()

    try:
        with open(UNIQUE_IPS_LOG_FILE, "r") as f:
            ip_entries = [line.strip().split("|") for line in f]
    except Exception as e:
        print(f"[!] Error reading IP:port file: {e}")
        return

    for ip, ports in ip_entries:
        print(f"Analyzing {ip} (Ports: {ports})...")
        ip_info = fetch_ip_info(ip)
        if ip_info:
            # Get most frequent port (simple heuristic)
            port_list = ports.split(",")
            main_port = max(set(port_list), key=port_list.count)
            
            analysis = await get_security_analysis(api, ip, main_port)
            store_ip_info(ip_info + (ports, analysis))
            
            with open(THREAT_ANALYSIS_FILE, "a") as f:
                f.write(f"{ip} Analysis (Ports: {ports}):\n{analysis}\n{'='*40}\n")
            
            print(f"DeepSeek analysis stored for {ip}")
        time.sleep(1)

    await api.close()

def fetch_ip_info(ip):
    """Fetch IP information from API"""
    try:
        response = requests.get(API_URL + ip)
        data = response.json()
        if data["status"] == "success":
            return (
                data["query"], data["country"], data["regionName"],
                data["city"], data["isp"], data["org"], data["as"]
            )
    except Exception as e:
        print(f"Error fetching {ip}: {e}")
    return None

def store_ip_info(ip_info):
    """Store IP info with analysis"""
    if ip_info:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO ip_info 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, ip_info)
        conn.commit()
        conn.close()
def process_ips():
    """Fetch and store information for unique IPs from the log file."""
    with open(UNIQUE_IPS_LOG_FILE, "r") as f:
        ips = {line.strip() for line in f}  # Read unique IPs

    for ip in ips:
        print(f"Checking {ip}...")
        ip_info = fetch_ip_info(ip)
        if ip_info:
            store_ip_info(ip_info)
            print(f"Stored {ip} data successfully.")
        time.sleep(1)  # To prevent rate-limiting

def packet_handler(packet):
    """Processes each captured packet and logs details."""
    try:
        # Ensure the packet has the required layers
        if not packet.haslayer(scapy.IP):
            return  # Skip non-IP packets

        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

        # Extract protocol name and ports
        src_port = None
        dst_port = None
        if packet.haslayer(scapy.TCP):
            protocol_name = "TCP"
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport
        elif packet.haslayer(scapy.UDP):
            protocol_name = "UDP"
            src_port = packet[scapy.UDP].sport
            dst_port = packet[scapy.UDP].dport
        else:
            protocol_name = "Other"

        # Log the packet details to JSON
        log_entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "src": src_ip,
            "dst": dst_ip,
            "protocol": protocol_name,
            "src_port": src_port,
            "dst_port": dst_port,
            "summary": packet.summary()
        }
        log_packet(log_entry)

        # Log the packet details to console and file using logging
        log_message = (
            f"SRC: {src_ip}:{src_port} -> DST: {dst_ip}:{dst_port} "
            f"PROTO: {protocol_name}"
        )
        logging.info(log_message)
    except AttributeError as e:
        # Handle cases where packet layers are incomplete or malformed
        print(f"[!] Skipping malformed packet: {e}")
    except Exception as e:
        print(f"[!] Error processing packet: {e}")

def log_packet(entry):
    """Logs packet data to a JSON file."""
    try:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        print(f"[!] Error writing to log file: {e}")

def check_root():
    """Ensures the script is running with root privileges."""
    if os.geteuid() != 0:
        print("[!] This script must be run as root! Try using sudo.")
        exit(1)

def start_sniffer(interface=None, count=None):
    """Starts sniffing packets on the specified interface."""
    global sniffer_running
    sniffer_running = True
    check_root()
    if count:
        print(f"[*] Sniffing on {interface} - capturing {count} packets...")
    else:
        print(f"[*] Sniffing on {interface} - capturing packets continuously...")
    print(f"[*] Sniffer output is being logged to {SNIFFER_OUTPUT_FILE}")
    scapy.sniff(iface=interface, prn=packet_handler, count=count, store=False)

def stop_sniffer():
    """Stops the continuous packet sniffer."""
    global sniffer_running
    sniffer_running = False
    print("[*] Stopping the sniffer...")

def detect_port_scan(log_file=LOG_FILE):
    """Detects potential port scans from the log file."""
    ip_port_map = {}  # Dictionary to map IPs to the ports they access

    try:
        with open(log_file, "r") as f:
            logs = [json.loads(line) for line in f.readlines()]
    except json.JSONDecodeError as e:
        print(f"[!] Error parsing JSON: {e}")
        return
    except Exception as e:
        print(f"[!] Error reading log file: {e}")
        return

    for log in logs:
        if not log or not isinstance(log, dict):  # Skip invalid logs
            continue

        src_ip = log.get("src", "N/A")
        dst_port = log.get("dst_port", "N/A")
        timestamp_str = log.get("timestamp", None)

        if timestamp_str is None:
            continue  # Skip log entries without timestamps

        try:
            timestamp = datetime.datetime.fromisoformat(timestamp_str)
        except ValueError:
            continue  # Skip malformed timestamps

        if src_ip not in ip_port_map:
            ip_port_map[src_ip] = []

        ip_port_map[src_ip].append((dst_port, timestamp))

    for ip, port_times in ip_port_map.items():
        port_times.sort(key=lambda x: x[1])  # Sort by timestamp
        for i in range(len(port_times)):
            ports_accessed = set()
            start_time = port_times[i][1]
            for j in range(i, len(port_times)):
                if port_times[j][1] - start_time <= TIME_WINDOW:
                    ports_accessed.add(port_times[j][0])
                else:
                    break
            if len(ports_accessed) >= SCAN_THRESHOLD:
                print(f"[!] Potential port scan detected from IP: {ip}")
                break

def log_unique_ips(log_file=LOG_FILE, output_file=UNIQUE_IPS_LOG_FILE):
    """Log unique IP:port combinations from packet log"""
    ip_port_map = defaultdict(set)

    try:
        with open(log_file, "r") as f:
            logs = [json.loads(line) for line in f.readlines()]
    except Exception as e:
        print(f"[!] Error reading log file: {e}")
        return

    for log in logs:
        if not log or not isinstance(log, dict):
            continue
        
        # Track both source and destination IP:port pairs
        src_ip = log.get("src", "")
        src_port = log.get("src_port", "")
        dst_ip = log.get("dst", "")
        dst_port = log.get("dst_port", "")

        if src_ip and src_port:
            ip_port_map[src_ip].add(src_port)
        if dst_ip and dst_port:
            ip_port_map[dst_ip].add(dst_port)

    try:
        with open(output_file, "w") as f:
            for ip, ports in ip_port_map.items():
                port_list = ",".join(str(p) for p in ports)
                f.write(f"{ip}|{port_list}\n")
        print(f"[+] Logged {len(ip_port_map)} IP:port combinations")
    except Exception as e:
        print(f"[!] Error writing IP:ports: {e}")


def search_ip_in_db():
    """Searches for and outputs IP information from the database."""
    search_ip = input("Enter the IP address to search for: ")

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ip_info WHERE ip = ?", (search_ip,))
    result = cursor.fetchone()
    conn.close()

    if result:
        print(f"[+] Found information for IP: {search_ip}")
        print(f"Organization: {result[5]}")
        print(f"Country: {result[1]}")
        print(f"Region: {result[2]}")
        print(f"City: {result[3]}")
        print(f"ISP: {result[4]}")
        print(f"AS: {result[6]}")
    else:
        print(f"[!] No information found for IP: {search_ip}")

def background_sniffer(interface):
    """Runs the sniffer in the background."""
    start_sniffer(interface=interface)
    while sniffer_running:
        time.sleep(1)  # Keep the thread alive

def main():
    """Main menu with DeepSeek integration"""
    init_db()
    while True:
        print("\nNetwork Monitoring Toolkit")
        print("1. Start sniffing (capture packets)")
        print("2. Detect port scans")
        print("3. Log unique IPs")
        print("4. Start background sniffing")
        print("5. Stop background sniffing")
        print("6. Search IP in database")
        print("7. Fetch basic IP info")
        print("8. Run DeepSeek threat analysis")
        print("9. Exit")
        choice = input("Choice: ")

        if choice == "1":
            interface = input("Enter network interface (e.g., eth0): ")
            count = int(input("Number of packets to capture: "))
            start_sniffer(interface=interface, count=count)
            
        elif choice == "2":
            detect_port_scan()
            
        elif choice == "3":
            log_unique_ips()
            
        elif choice == "4":
            if sniffer_running:
                print("[!] Sniffer already running!")
            else:
                interface = input("Enter network interface (e.g., eth0): ")
                sniffer_thread = threading.Thread(target=background_sniffer, args=(interface,))
                sniffer_thread.daemon = True
                sniffer_thread.start()
                print("[*] Background sniffing started")
                
        elif choice == "5":
            if sniffer_running:
                stop_sniffer()
            else:
                print("[!] No active sniffing session")
                
        elif choice == "6":
            search_ip_in_db()
            
        elif choice == "7":
            process_ips()
            print("[+] IP information updated in database")
            
        elif choice == "8":
            try:
                print("[*] Starting DeepSeek analysis...")
                asyncio.run(process_ips_with_deepseek())
                print("\n[+] Threat analysis complete!")
                print(f"Results saved to {THREAT_ANALYSIS_FILE}")
            except Exception as e:
                print(f"[!] DeepSeek error: {e}")
                
        elif choice == "9":
            print("[*] Exiting...")
            if sniffer_running:
                stop_sniffer()
            break
            
        else:
            print("[!] Invalid choice!")

# ... (keep all other functions unchanged)

if __name__ == "__main__":
    main()
