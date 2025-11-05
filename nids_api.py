from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_socketio import SocketIO
import json
import pytz
from datetime import datetime
import os

# --- Initialize App and Extensions ---
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# --- Database Configuration ---
# Point to your *new* nids_db
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:Harsh%408866@localhost:8866/nids_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*")
# --- End Configuration ---

# --- Database Model ---
class SecurityAlert(db.Model):
    __tablename__ = 'security_alerts'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.String(50), nullable=False)
    alert_type = db.Column(db.String(100), nullable=False)
    source_ip = db.Column(db.String(50), nullable=True)
    severity = db.Column(db.String(20), nullable=False, default='Medium')
    geolocation = db.Column(db.String(100), nullable=True)
    ip_reputation = db.Column(db.Text, nullable=True)

    details = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f'<Alert {self.id} | {self.alert_type}>'
class AllowedlistedIP(db.Model):
    __tablename__ = 'allowlisted_ips'
    id = db.Column(db.String(50), primary_key=True, nullable = False, unique =True)
    ip_address = db.Column(db.String(50), nullable=True)

    def __repr__(self):
        return f'<AllowedlistedIP {self.ip_address}>'
# --- End Models ---


# --- API Endpoints ---
@app.route("/api/ingest_alert", methods=['POST'])
def ingest_alert():
    """Receives an alert from a sensor, stores it, and notifies clients."""
    alert_data = request.get_json()
    if not alert_data:
        return jsonify({"error": "Invalid request: No data provided"}), 400

    print(f"--- NIDS API: ALERT RECEIVED ---: {alert_data}")

    try:
        # Get current time in PDT
        pacific_tz = pytz.timezone('America/Los_Angeles')
        current_time_pdt = datetime.now(pacific_tz).isoformat(timespec='seconds')

        new_alert = SecurityAlert(
            timestamp=current_time_pdt, # Use server time
            alert_type=alert_data.get('alert_type', 'Unknown'),
            source_ip=alert_data.get('source_ip', 'Unknown'),
            details=json.dumps(alert_data.get('details', {}))
        )
        db.session.add(new_alert)
        db.session.commit()

        # Emit WebSocket message to all connected clients
        socketio.emit('new_alert', {
            'id': new_alert.id,
            'timestamp': new_alert.timestamp,
            'alert_type': new_alert.alert_type,
            'source_ip': new_alert.source_ip,
            'details': alert_data.get('details', {})
        })
        print(f"Stored alert and emitted 'new_alert' for {new_alert.source_ip}")
        return jsonify({"message": "Alert received and stored"}), 201

    except Exception as e:
        db.session.rollback()
        print(f"Error storing alert: {e}")
        return jsonify({"error": "Database error occurred"}), 500

@app.route("/api/get_alerts", methods=['GET'])
def get_alerts():
    """Fetches all stored security alerts from the database."""
    alerts_list = []
    try:
        alerts = SecurityAlert.query.order_by(db.desc(SecurityAlert.timestamp)).all()
        for alert in alerts:
            details_dict = {}
            try:
                details_dict = json.loads(alert.details) if alert.details else {}
            except json.JSONDecodeError:
                details_dict = {"error": "invalid format"}

            alerts_list.append({
                'id': alert.id,
                'timestamp': alert.timestamp,
                'alert_type': alert.alert_type,
                'source_ip': alert.source_ip,
                'details': details_dict
            })
        return jsonify(alerts_list)
    except Exception as e:
        print(f"Error fetching alerts: {e}")
        return jsonify({"error": "Failed to fetch alerts"}), 500
# --- End API ---


# --- SocketIO Handlers ---
@socketio.on('connect')
def handle_connect():
    print(f'NIDS API: Client connected: {request.sid}')

@socketio.on('disconnect')
def handle_disconnect():
    print(f'NIDS API: Client disconnected: {request.sid}')
# --- End Handlers ---


if __name__ == '__main__':
    print("Starting NIDS Flask-SocketIO server...")
    # Run on host='0.0.0.0' to be accessible from your VMs
    # We use port 5001 to avoid conflicts with your *other* project (game-security-dashboard)
    socketio.run(app, host='0.0.0.0', port=5001, debug=True, use_reloader=False, allow_unsafe_werkzeug=True)