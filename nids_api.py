import requests
import json
from scapy.all import sniff, TCP, IP, UDP
from collections import defaultdict
import time
from threading import Thread
import socket
import sys # Import sys to get executable path
import traceback # Import traceback for error logging

# --- Configuration ---
# IPs for your virtual network
HOST_IP = "192.168.23.1"
VICTIM_IP = "192.168.23.131"
ATTACKER_IP = "192.168.23.132"

# URL of your NIDS Flask server's alert endpoint
ALERT_API_URL = f"http://{HOST_IP}:5001/api/ingest_alert"
ALLOWLIST_API_URL = f"http://{HOST_IP}:5001/api/allowlist"

# Try to get the local IP, but fall back to the one we set
try:
    local_ip = socket.gethostbyname(socket.gethostname())
except Exception:
    local_ip = VICTIM_IP # Fallback

print(f"--- NIDS Sensor Service ---")
print(f"Sensor IP identified as: {local_ip}")
print(f"Monitoring traffic for destination: {VICTIM_IP}")
print(f"Alerts will be sent to: {ALERT_API_URL}")

# --- Detection Parameters ---
PORT_SCAN_THRESHOLD = 10  # 10 different ports
TIME_WINDOW = 5           # within 5 seconds

# --- Global Data Structures ---
potential_scans = defaultdict(lambda: {"ports": set(), "first_seen": time.time()})
potential_udp_scans = defaultdict(lambda: {"ports": set(), "first_seen": time.time()})
ALLOWLISTED_IPS = set() # For our new allowlist feature

# --- Helper Functions ---

def fetch_allowlist():
    """
    Fetches the IP allowlist from the API server on startup.
    """
    global ALLOWLISTED_IPS
    try:
        print(f"Fetching allowlist from {ALLOWLIST_API_URL}...")
        response = requests.get(ALLOWLIST_API_URL, timeout=5)
        if response.status_code == 200:
            ips = response.json()
            ALLOWLISTED_IPS = set(ips)
            print(f"Successfully fetched {len(ALLOWLISTED_IPS)} allowlisted IPs.")
        else:
            print(f"Warning: Could not fetch allowlist. Server responded with {response.status_code}")
    except requests.exceptions.ConnectionError:
        print(f"[ERROR] Connection Error: Could not connect to API at {ALLOWLIST_API_URL}")
    except Exception as e:
        print(f"An error occurred while fetching allowlist: {e}")

def send_alert(alert_type, severity, source_ip, details):
    """
    Helper function to format and send an alert to the API.
    """
    try:
        alert_payload = {
            "alert_type": alert_type,
            "severity": severity,
            "source_ip": source_ip,
            "details": details
        }
        response = requests.post(ALERT_API_URL, json=alert_payload, timeout=3)
        if response.status_code == 201:
            print(f"Successfully sent {alert_type} alert to dashboard.")
        else:
            print(f"Failed to send {alert_type} alert. Server responded with: {response.status_code}")
    except Exception as e:
        print(f"An error occurred while sending {alert_type} alert: {e}")

# --- Scan Detection Logic ---

def check_for_port_scan(attacker_ip, port):
    """
    Checks if a packet contributes to a TCP SYN port scan and sends an alert if it does.
    """
    global potential_scans
    current_time = time.time()
    
    scan_data = potential_scans[attacker_ip]

    if current_time - scan_data["first_seen"] > TIME_WINDOW:
        scan_data["ports"] = {port}
        scan_data["first_seen"] = current_time
        return

    scan_data["ports"].add(port)

    if len(scan_data["ports"]) >= PORT_SCAN_THRESHOLD:
        print("\n" + "="*40)
        print("   !!! TCP PORT SCAN DETECTED !!!")
        print(f"   Source IP: {attacker_ip}")
        print(f"   Ports Scanned: {len(scan_data['ports'])}")
        print("="*40 + "\n")
        
        # 1. Send the alert using our helper function
        send_alert(
            alert_type="TCP Port Scan",
            severity="Medium",
            source_ip=attacker_ip,
            details={
                "scanned_port_count": len(scan_data["ports"]),
                "ports_sampled": list(scan_data["ports"])[:20]
            }
        )

        # 2. Clear this IP's record
        del potential_scans[attacker_ip]

def check_for_udp_scan(attacker_ip, port):
    """
    Checks if a packet contributes to a UDP port scan.
    """
    global potential_udp_scans
    current_time = time.time()
    
    scan_data = potential_udp_scans[attacker_ip]

    if current_time - scan_data["first_seen"] > TIME_WINDOW:
        scan_data["ports"] = {port}
        scan_data["first_seen"] = current_time
        return

    scan_data["ports"].add(port)

    if len(scan_data["ports"]) >= PORT_SCAN_THRESHOLD:
        print("\n" + "="*40)
        print("   !!! UDP PORT SCAN DETECTED !!!")
        print(f"   Source IP: {attacker_ip}")
        print(f"   Ports Scanned: {len(scan_data['ports'])}")
        print("="*40 + "\n")
        
        send_alert(
            alert_type="UDP Port Scan",
            severity="Medium",
            source_ip=attacker_ip,
            details={
                "scanned_port_count": len(scan_data["ports"]),
                "ports_sampled": list(scan_data["ports"])[:20]
            }
        )
        
        del potential_udp_scans[attacker_ip]

# --- Main Packet Handler ---

def packet_sniffer_callback(packet):
    """
    This function is called by Scapy for every packet it sniffs.
    """
    if not packet.haslayer(IP):
        return

    source_ip = packet[IP].src
    
    # Ignore allowlisted IPs
    if source_ip in ALLOWLISTED_IPS:
        return

    # --- Handle TCP Packets ---
    if packet.haslayer(TCP):
        tcp_flags = packet[TCP].flags
        dest_ip = packet[IP].dst
        
        # Only analyze traffic TO our Victim VM
        if dest_ip != VICTIM_IP:
            return
        
        # 1. XMAS Scan Detection (FIN, PSH, URG)
        if tcp_flags & 0x29 == 0x29: # 0x29 is 00101001 (URG, PSH, FIN)
            print("\n" + "="*40)
            print("   !!! XMAS SCAN DETECTED !!!")
            print(f"   Source IP: {source_ip}")
            print("="*40 + "\n")
            send_alert(
                alert_type="XMAS Scan",
                severity="High",
                source_ip=source_ip,
                details={"destination_port": packet[TCP].dport, "flags": "FIN, PSH, URG"}
            )
            return # Don't check for other scans

        # 2. NULL Scan Detection (No flags set)
        if tcp_flags == 0x00:
            print("\n" + "="*40)
            print("   !!! NULL SCAN DETECTED !!!")
            print(f"   Source IP: {source_ip}")
            print("="*40 + "\n")
            send_alert(
                alert_type="NULL Scan",
                severity="High",
                source_ip=source_ip,
                details={"destination_port": packet[TCP].dport, "flags": "None"}
            )
            return # Don't check for other scans

        # 3. TCP Port Scan Detection (SYN packet)
        if tcp_flags == 0x02: # SYN flag
            if source_ip != VICTIM_IP and source_ip != HOST_IP:
                check_for_port_scan(source_ip, packet[TCP].dport)
        
        return # Done with TCP

    # --- Handle UDP Packets ---
    if packet.haslayer(UDP):
        dest_ip = packet[IP].dst

        # Only analyze traffic TO our Victim VM
        if dest_ip != VICTIM_IP:
            return
        
        # Ignore traffic from ourselves or the Host
        if source_ip == VICTIM_IP or source_ip == HOST_IP:
            return

        # Check for UDP Scan
        check_for_udp_scan(source_ip, packet[UDP].dport)
        return

# --- Sniffer Start ---

def start_sniffer():
    """
    Starts the Scapy sniffer.
    """
    fetch_allowlist() # Fetch the allowlist on startup
    
    print(f"Starting network sniffer. Listening for all TCP and UDP traffic...")
    print(f"Detection Threshold: {PORT_SCAN_THRESHOLD} ports in {TIME_WINDOW} seconds.")
    print("NOTE: This script must be run with 'sudo' privileges.")
    
    try:
        # We must specify the interface 'ens37'
        # Filter is just 'tcp or udp'
        sniff(iface="ens37", filter="tcp or udp", prn=packet_sniffer_callback, store=0)
    except PermissionError:
        print("\n[ERROR] Permission denied. Scapy requires root privileges.")
        print("Please run this script again using 'sudo':")
        print(f"sudo {sys.executable} nids_service.py") 
    except Exception as e:
        print(f"\nAn error occurred while starting the sniffer: {e}")
        print("--- FULL TRACEBACK ---")
        traceback.print_exc()
        print("----------------------")

if __name__ == "__main__":
    start_sniffer()