import React, { useState, useEffect } from 'react';
import io from 'socket.io-client';
import axios from 'axios';
import './App.css';

// --- Configuration ---
// Use your Host IP and the API Port (5001)
const API_BASE_URL = 'http://192.168.23.1:5001';
const SOCKETIO_URL = 'http://192.168.23.1:5001';
// --- End Configuration ---

const socket = io(SOCKETIO_URL);

function App() {
  const [securityAlerts, setSecurityAlerts] = useState([]);

  // 1. Fetch all alerts from the database when the page loads
  useEffect(() => {
    axios.get(`${API_BASE_URL}/api/get_alerts`)
      .then(response => {
        setSecurityAlerts(response.data);
      })
      .catch(error => {
        console.error("Error fetching initial alerts:", error);
      });
  }, []);

  // 2. Listen for 'new_alert' messages from the WebSocket
  useEffect(() => {
    socket.on('new_alert', (newAlert) => {
      console.log("New alert received via WebSocket:", newAlert);
      // Add the new alert to the top of the list
      setSecurityAlerts(prevAlerts => [newAlert, ...prevAlerts]);
    });

    // Clean up the socket listener when component unmounts
    return () => {
      socket.off('new_alert');
    };
  }, []);

  return (
    <div className="App">
      <header className="App-header">
        <h1>NIDS Security Alert Dashboard</h1>
      </header>
      <div className="content">
        <h2>Live Security Alerts</h2>
        <p>Connection: {socket.connected ? "Connected" : "Disconnected"}</p>
        <table className="alerts-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Type</th>
              <th>Source IP</th>
              <th>Details (Port Count)</th>
            </tr>
          </thead>
          <tbody>
            {securityAlerts.map(alert => (
              <tr key={alert.id}>
                <td>{new Date(alert.timestamp).toLocaleString()}</td>
                <td>{alert.alert_type}</td>
                <td>{alert.source_ip}</td>
                <td>{alert.details?.scanned_port_count || 'N/A'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default App;