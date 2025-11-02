import requests
import json
from scapy.all import sniff, TCP
from collections import defaultdict
import time
from threading import Thread

# --- Configuration ---
# URL of your Flask server's alert endpoint
# This MUST be your Host IP (VMnet1), not localhost
ALERT_API_URL = "http://192.168.80.1:5000/api/ingest_alert"

# Get the Victim VM's own IP (we don't want to detect scans *from* ourselves)
# Note: This is a simple way; for a real VM, you might need to find this dynamically
# or configure it. Let's find it automatically.
import socket
VICTIM_IP = socket.gethostbyname(socket.gethostname())
print(f"--- NIDS Sensor Service ---")
print(f"Monitoring traffic on host: {VICTIM_IP}")
print(f"Alerts will be sent to: {ALERT_API_URL}")

# --- Detection Parameters ---
# We will track TCP SYN packets (the start of a connection)
# A port scan is defined as: [PORT_SCAN_THRESHOLD] SYN packets to
# different ports from a single source IP within [TIME_WINDOW] seconds.
PORT_SCAN_THRESHOLD = 10  # e.g., 10 different ports
TIME_WINDOW = 5         # e.g., within 5 seconds

# --- Global Data Structure to track potential scans ---
# This dictionary will hold our scan data
# Format: { "attacker_ip_1": { "ports": {port1, port2}, "first_seen": timestamp },
#           "attacker_ip_2": { ... } }
potential_scans = defaultdict(lambda: {"ports": set(), "first_seen": time.time()})

def check_for_port_scan(attacker_ip, port):
    """
    Checks if a packet contributes to a port scan and sends an alert if it does.
    """
    global potential_scans
    
    current_time = time.time()
    
    # Get the record for this attacker IP
    scan_data = potential_scans[attacker_ip]

    # Check if the time window for this IP has expired
    if current_time - scan_data["first_seen"] > TIME_WINDOW:
        # Time window expired, reset this IP's record
        scan_data["ports"] = {port} # Start a new set with the current port
        scan_data["first_seen"] = current_time
        return

    # Add the new port to the set of scanned ports for this IP
    scan_data["ports"].add(port)

    # --- DETECTION LOGIC ---
    # Check if this IP has now scanned enough unique ports to trigger an alert
    if len(scan_data["ports"]) >= PORT_SCAN_THRESHOLD:
        print(f"\n*** PORT SCAN DETECTED ***")
        print(f"Source IP: {attacker_ip}")
        print(f"Ports Scanned: {len(scan_data['ports'])} (e.g., {list(scan_data['ports'])[:5]}...)")
        
        # 1. Send the alert to the Flask backend
        try:
            alert_payload = {
                "alert_type": "TCP Port Scan",
                "source_ip": attacker_ip,
                "details": {
                    "scanned_port_count": len(scan_data["ports"]),
                    "ports_sampled": list(scan_data["ports"])[:20] # Send a sample of ports
                }
            }
            response = requests.post(ALERT_API_URL, json=alert_payload)
            if response.status_code == 201:
                print(f"Successfully sent alert to dashboard at {ALERT_API_URL}")
            else:
                print(f"Failed to send alert. Server responded with: {response.status_code}")
        
        except requests.exceptions.ConnectionError:
            print(f"Connection Error: Could not connect to alert server at {ALERT_API_URL}")
        except Exception as e:
            print(f"An error occurred while sending alert: {e}")

        # 2. After alerting, clear this IP's record to prevent spamming alerts
        # (In a real system, you might just "mute" it for 5 minutes)
        del potential_scans[attacker_ip]

def packet_sniffer_callback(packet):
    """
    This function is called by Scapy for every packet it sniffs.
    """
    # We only care about TCP packets
    if not packet.haslayer(TCP):
        return

    # We only care about SYN packets (flags=0x02 or 'S')
    # This indicates the start of a new connection attempt
    if packet[TCP].flags == 0x02: # 0x02 is the SYN flag
        
        # Get source IP and destination port
        source_ip = packet[IP].src
        dest_port = packet[TCP].dport
        
        # Ignore traffic from ourselves (Victim VM)
        if source_ip == VICTIM_IP:
            return
            
        # Uncomment the line below for *very* noisy debugging
        # print(f"SYN packet detected: {source_ip} -> {dest_port}")
        
        # Check if this packet triggers our port scan logic
        check_for_port_scan(source_ip, dest_port)

# --- Main function to start the sniffer ---
def start_sniffer():
    """
    Starts the Scapy sniffer.
    
    'prn' specifies the callback function to run on each packet.
    'filter' is a BPF filter string. 'tcp' means "only capture TCP packets".
    'store=0' means don't store packets in memory (we process them live).
    """
    print(f"\nStarting network sniffer. Listening for TCP traffic...")
    print(f"Detection Threshold: {PORT_SCAN_THRESHOLD} ports in {TIME_WINDOW} seconds.")
    try:
        # Note: You must run this script as root (with sudo) for Scapy to work
        sniff(filter="tcp", prn=packet_sniffer_callback, store=0)
    except PermissionError:
        print("\n[ERROR] Permission denied. Scapy requires root privileges.")
        print("Please run this script again using 'sudo':")
        print("sudo python3 nids_service.py")
    except Exception as e:
        print(f"\nAn error occurred while starting the sniffer: {e}")

if __name__ == "__main__":
    # We need to import 'IP' layer here for the callback to work correctly when run as main
    from scapy.all import IP
    start_sniffer()
