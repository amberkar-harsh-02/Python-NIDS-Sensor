import requests
import json
from scapy.all import sniff, TCP, IP
from collections import defaultdict
import time
from threading import Thread
import socket
import sys # Import sys to get executable path

# --- Configuration ---
# IPs for your virtual network (VMnet8)
HOST_IP = "192.168.23.1"
VICTIM_IP = "192.168.23.131"
ATTACKER_IP = "192.168.23.132"

# URL of your NIDS Flask server's alert endpoint
# We use the HOST_IP and the new port 5001
ALERT_API_URL = f"http://{HOST_IP}:5001/api/ingest_alert"

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
TIME_WINDOW = 5         # within 5 seconds

# Global Data Structure
potential_scans = defaultdict(lambda: {"ports": set(), "first_seen": time.time()})

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
        print("  !!! TCP PORT SCAN DETECTED !!!")
        print(f"  Source IP: {attacker_ip}")
        print(f"  Ports Scanned: {len(scan_data['ports'])}")
        print(f"  Port Sample: {list(scan_data['ports'])[:20]}")
        print("="*40 + "\n")
        
        # 1. Send the alert to the Flask backend
        try:
            alert_payload = {
                "alert_type": "TCP Port Scan",
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
            print(f"        Is the NIDS_API server running on {HOST_IP}:5001?")
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
    if not packet.haslayer(TCP) or not packet.haslayer(IP):
        return

    if packet[TCP].flags == 0x02: # SYN packet
        
        source_ip = packet[IP].src
        dest_ip = packet[IP].dest
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
    print(f"Starting network sniffer. Listening for TCP traffic...")
    print(f"Detection Threshold: {PORT_SCAN_THRESHOLD} ports in {TIME_WINDOW} seconds.")
    print("NOTE: This script must be run with 'sudo' privileges.")
    
    try:
        sniff(filter="tcp", prn=packet_sniffer_callback, store=0)
    except PermissionError:
        print("\n[ERROR] Permission denied. Scapy requires root privileges.")
        print("Please run this script again using 'sudo':")
        # Use sys.executable to get the path to the python in the venv
        print(f"sudo {sys.executable} nids_service.py") 
    except Exception as e:
        print(f"\nAn error occurred while starting the sniffer: {e}")

if __name__ == "__main__":
    start_sniffer()