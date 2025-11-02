from scapy.all import sniff, TCP, IP
from collections import defaultdict
import time

# --- Configuration ---
# Your network IPs
HOST_IP = "192.168.23.1"
VICTIM_IP = "192.168.23.131"
ATTACKER_IP = "192.168.23.132"

# --- Detection Parameters ---
# A port scan is defined as: [PORT_SCAN_THRESHOLD] SYN packets to
# different ports from a single source IP within [TIME_WINDOW] seconds.
PORT_SCAN_THRESHOLD = 10  # 10 different ports
TIME_WINDOW = 5         # within 5 seconds

# --- Global Data Structure to track potential scans ---
# Format: { "attacker_ip_1": { "ports": {port1, port2}, "first_seen": timestamp }, ... }
potential_scans = defaultdict(lambda: {"ports": set(), "first_seen": time.time()})

def check_for_port_scan(attacker_ip, port):
    """
    Checks if a packet contributes to a port scan and prints an alert if it does.
    """
    global potential_scans
    current_time = time.time()
    
    scan_data = potential_scans[attacker_ip]

    # Check if the time window for this IP has expired
    if current_time - scan_data["first_seen"] > TIME_WINDOW:
        # Time window expired, reset this IP's record
        scan_data["ports"] = {port} # Start a new set
        scan_data["first_seen"] = current_time
        return

    # Add the new port to the set of scanned ports
    scan_data["ports"].add(port)

    # --- DETECTION LOGIC ---
    if len(scan_data["ports"]) >= PORT_SCAN_THRESHOLD:
        print("\n" + "="*40)
        print("  !!! TCP PORT SCAN DETECTED !!!")
        print(f"  Source IP: {attacker_ip}")
        print(f"  Ports Scanned: {len(scan_data['ports'])}")
        print(f"  Port Sample: {list(scan_data['ports'])[:20]}")
        print("="*40 + "\n")
        
        # In the future, we will send this alert to a Flask server.
        # For now, we just print it.
        
        # Clear this IP's record to prevent spamming
        del potential_scans[attacker_ip]

def packet_sniffer_callback(packet):
    """
    This function is called by Scapy for every packet it sniffs.
    """
    # We only care about TCP packets
    if not packet.haslayer(TCP):
        return

    # Packet must have an IP layer to get source/dest IPs
    if not packet.haslayer(IP):
        return

    # We only care about SYN packets (flags=0x02 or 'S')
    if packet[TCP].flags == 0x02:
        
        source_ip = packet[IP].src
        dest_ip = packet[IP].dst
        dest_port = packet[TCP].dport
        
        # --- IMPORTANT FILTER ---
        # We only want to analyze scans targeting our Victim VM.
        # Ignore all other traffic (like Host-to-Attacker pings, etc.)
        if dest_ip != VICTIM_IP:
            return
            
        # Ignore traffic from ourselves (Victim VM) or the Host
        if source_ip == VICTIM_IP or source_ip == HOST_IP:
            return
            
        # At this point, we are only looking at packets
        # from an *external* source (like the Attacker VM)
        # sent *to* our Victim VM.
        
        # Uncomment for very noisy debugging:
        # print(f"SYN packet: {source_ip} -> {dest_ip}:{dest_port}")
        
        check_for_port_scan(source_ip, dest_port)

# --- Main function to start the sniffer ---
def start_sniffer():
    """
    Starts the Scapy sniffer.
    """
    print("--- NIDS Sensor Service ---")
    print(f"Monitoring traffic on host: {VICTIM_IP}")
    print(f"Detection Threshold: {PORT_SCAN_THRESHOLD} ports in {TIME_WINDOW} seconds.")
    print("Starting network sniffer. Listening for TCP traffic...")
    print("NOTE: This script must be run with 'sudo' privileges.")
    
    try:
        # 'filter="tcp"' tells scapy to only capture TCP packets
        # 'prn' specifies the callback function to run on each packet
        # 'store=0' means don't store packets in memory (we process live)
        sniff(filter="tcp", prn=packet_sniffer_callback, store=0)
    except PermissionError:
        print("\n[ERROR] Permission denied. Scapy requires root privileges.")
        print("Please run this script again using 'sudo':")
        print("sudo python3 nids_service.py")
    except Exception as e:
        print(f"\nAn error occurred while starting the sniffer: {e}")

if __name__ == "__main__":
    start_sniffer()