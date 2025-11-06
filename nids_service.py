import requests
import json
from scapy.all import sniff, TCP, IP
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
    # This gets the IP address of the machine the script is running on
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

# Global Data Structure
potential_scans = defaultdict(lambda: {"ports": set(), "first_seen": time.time()})
ALLOWLISTED_IPS = set() # For our new allowlist feature

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

def check_for_port_scan(attacker_ip, port):
    """
    Checks if a packet contributes to a port scan and sends an alert if it does.
    """
    global potential_scans
    current_time = time.time()
    
    scan_data = potential_scans[attacker_ip]

    if current_time - scan_data["first_seen"] > TIME_WINDOW:
        # Time window expired, reset
        scan_data["ports"] = {port}
        scan_data["first_seen"] = current_time
        return

    scan_data["ports"].add(port)

    if len(scan_data["ports"]) >= PORT_SCAN_THRESHOLD:
        print("\n" + "="*40)
        print("   !!! TCP PORT SCAN DETECTED !!!")
        print(f"   Source IP: {attacker_ip}")
        print(f"   Ports Scanned: {len(scan_data['ports'])}")
        print(f"   Port Sample: {list(scan_data['ports'])[:20]}")
        print("="*40 + "\n")
        
        # 1. Send the alert to the Flask backend
        try:
            alert_payload = {
                "alert_type": "TCP Port Scan",
                "severity": "Medium", # Port scans are Medium severity
                "source_ip": attacker_ip,
                "details": {
                    "scanned_port_count": len(scan_data["ports"]),
                    "ports_sampled": list(scan_data["ports"])[:20]
                }
            }
            # Use a timeout to prevent hanging
            response = requests.post(ALERT_API_URL, json=alert_payload, timeout=3)
            if response.status_code == 201:
                print(f"Successfully sent alert to dashboard at {ALERT_API_URL}")
            else:
                print(f"Failed to send alert. Server responded with: {response.status_code}")
        
        except requests.exceptions.ConnectionError:
            print(f"[ERROR] Connection Error: Could not connect to alert server at {ALERT_API_URL}")
            print(f"         Is the NIDS_API server running on {HOST_IP}:5001?")
        except requests.exceptions.Timeout:
            print(f"[ERROR] Connection Timeout: Server at {ALERT_API_URL} did not respond.")
        except Exception as e:
            print(f"An error occurred while sending alert: {e}")

        # 2. Clear this IP's record
        del potential_scans[attacker_ip]

def packet_sniffer_callback(packet):
    """
    This function is called by Scapy for every packet it sniffs.
    """
    if not packet.haslayer(IP): # Check for IP layer first
        return

    source_ip = packet[IP].src
    
    # Check if source IP is on the allowlist
    if source_ip in ALLOWLISTED_IPS:
        return # Ignore this packet

    if not packet.haslayer(TCP):
        return
    
    # --- START NEW XMAS SCAN DETECTION ---
    tcp_flags = packet[TCP].flags
    
    # XMAS Scan Detection (FIN, PSH, URG flags set)
    # 0x29 is 00101001 in binary (URG=32, PSH=8, FIN=1)
    if tcp_flags & 0x29 == 0x29:
        dest_ip = packet[IP].dst
        
        # Only analyze traffic TO our Victim VM
        if dest_ip != VICTIM_IP:
            return

        print("\n" + "="*40)
        print("   !!! XMAS SCAN DETECTED !!!")
        print(f"   Source IP: {source_ip}")
        print(f"   Destination Port: {packet[TCP].dport}")
        print("="*40 + "\n")
        
        try:
            alert_payload = {
                "alert_type": "XMAS Scan",
                "severity": "High", # This is a high-severity alert
                "source_ip": source_ip,
                "details": {
                    "destination_port": packet[TCP].dport,
                    "flags": "FIN, PSH, URG"
                }
            }
            response = requests.post(ALERT_API_URL, json=alert_payload, timeout=3)
            if response.status_code == 201:
                print(f"Successfully sent XMAS alert to dashboard.")
            else:
                print(f"Failed to send XMAS alert. Server responded with: {response.status_code}")
        
        except Exception as e:
            print(f"An error occurred while sending XMAS alert: {e}")
        
        return # This was a XMAS packet, don't check it for port scan
    # --- END NEW XMAS SCAN DETECTION ---

    # Original Port Scan Detection (SYN packet)
    if tcp_flags == 0x02: # 0x02 is SYN flag
        
        dest_ip = packet[IP].dst
        dest_port = packet[TCP].dport
        
        # Only analyze traffic TO our Victim VM
        if dest_ip != VICTIM_IP:
            return
            
        # Ignore traffic from ourselves or the Host
        if source_ip == VICTIM_IP or source_ip == HOST_IP:
            return
            
        check_for_port_scan(source_ip, dest_port)

def start_sniffer():
    """
    Starts the Scapy sniffer.
    """
    fetch_allowlist() # Fetch the allowlist on startup
    
    print(f"Starting network sniffer. Listening for TCP traffic...")
    print(f"Detection Threshold: {PORT_SCAN_THRESHOLD} ports in {TIME_WINDOW} seconds.")
    print("NOTE: This script must be run with 'sudo' privileges.")
    
    try:
        # We must specify the interface 'ens37'
        sniff(iface="ens37", filter="tcp", prn=packet_sniffer_callback, store=0)
    except PermissionError:
        print("\n[ERROR] Permission denied. Scapy requires root privileges.")
        print("Please run this script again using 'sudo':")
        # Use sys.executable to get the path to the python
        print(f"sudo {sys.executable} nids_service.py") 
    except Exception as e:
        print(f"\nAn error occurred while starting the sniffer: {e}")
        # Print the full error
        print("--- FULL TRACEBACK ---")
        traceback.print_exc()
        print("----------------------")

if __name__ == "__main__":
    start_sniffer()
