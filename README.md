# Real-Time NIDS & Security Alerting Pipeline

This project is a multi-virtual-machine Network Intrusion Detection System (NIDS) that detects a TCP port scan in real-time and displays an alert on a live web dashboard.

## Project Architecture

The system uses three separate machines communicating over a virtual network:

* **Host Machine:** Runs the Flask/Socket.IO API server, the PostgreSQL database, and the React frontend.
* **Victim VM (Ubuntu):** Runs a Python Scapy sensor (`nids_service.py`) that "sniffs" network traffic.
* **Attacker VM (Ubuntu/Kali):** Uses `nmap` to launch a simulated attack against the Victim VM.

### How it Works
1.  The **Attacker VM** launches an `nmap -sS` scan against the **Victim VM**.
2.  The `nids_service.py` sensor on the Victim detects the rapid SYN packets from a single source.
3.  The sensor sends an HTTP POST request with the alert data to the **Flask API Server** (on the Host).
4.  The API server stores the alert in the **PostgreSQL DB** and instantly emits a `new_alert` message via **WebSockets**.
5.  The **React Dashboard** (running in the Host's browser) receives the WebSocket message and immediately updates the UI with the new alert.

## Core Features
* **Live Packet Sniffing:** Uses Scapy to monitor a live network interface.
* **Heuristic-Based Detection:** Detects a port scan based on a threshold of ports hit in a time window.
* **Full-Stack Alert Pipeline:** Real-time alerting from sensor to UI using HTTP, WebSockets, and a SQL database.
* **Realistic VM-Based Architecture:** Demonstrates understanding of network segmentation and client-server communication across different machines.

## How to Run

### 1. Backend Setup (Host Machine)
```bash
# Install dependencies
pip install Flask flask_sqlalchemy psycopg2-binary flask_cors flask_socketio pytz

# Create the database table in PostgreSQL
python
>>> from nids_api import db, app
>>> app.app_context().push()
>>> db.create_all()
>>> exit()

# Run the API server (listens on port 5001)
python nids_api.py
```

### 2. Sensor Setup (Victim VM)
```bash
# Install dependencies
sudo apt-get update
sudo apt-get install python3-pip python3-scapy python3-requests -y

# (Remember to edit nids_service.py with the correct 'iface' name)

# Run the sensor (must use sudo)
sudo python3 nids_service.py
```

### 3. Frontend Setup (Host Machine)
```bash
# Navigate to the dashboard folder
cd nids-dashboard

# Install dependencies
npm install socket.io-client axios

# Run the React app (opens on http://localhost:3000)
npm start
```

### 4. Test (Attacker VM)
```bash
# Run an nmap scan against the Victim VM
sudo nmap -sS -p 1-100 <VICTIM_IP_HERE>
```
