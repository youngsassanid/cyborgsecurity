# cyborgsecurity.py

"""
CyborgSecurity: A simulated cybersecurity suite for human-machine interfaces (HMI).
This prototype scans for spoofed biosignal data, monitors neural device communication,
and detects anomalies in implant I/O traffic to defend cyborg systems from attacks.
Includes signal frequency drift detection, memory integrity verification,
replay attack detection, system clock tampering alerts, email alerts,
real-time JSON alert export, CSV logging, dashboard reporting, alert encryption,
and basic auto-remediation for critical anomalies.

Usage:
  python cyborgsecurity.py --debug      # Turn debug mode ON
  python cyborgsecurity.py --no-debug   # Turn debug mode OFF
  You'll be prompted before monitoring starts.
"""

import random
import time
import hashlib
import statistics
import logging
from datetime import datetime, timedelta
import json
import csv
import os
import smtplib
from email.message import EmailMessage
from flask import Flask, jsonify, render_template_string, request
from cryptography.fernet import Fernet
import argparse

# ========== Logger Setup ==========
logging.basicConfig(
    filename="cyborgsecurity.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# ========== Encryption Key ==========
ENCRYPTION_KEY = Fernet.generate_key()
cipher = Fernet(ENCRYPTION_KEY)

# ========== Debug Mode ==========
DEBUG_MODE = False

# ========== Simulated Cyborg Device ==========
class CyborgInterface:
    def __init__(self, device_id):
        self.device_id = device_id
        self.implant_type = "NeuroLink V3"  # Added implant type
        self.signal_baseline = [random.gauss(50, 5) for _ in range(100)]
        self.traffic_log = []
        self.memory_fingerprint = self.generate_memory_fingerprint()
        self.last_packet_timestamps = set()

    def generate_biosignal(self):
        if random.random() < 0.05:
            return random.gauss(90, 20)  # spoofed or corrupted
        return random.gauss(50, 5)  # normal

    def send_packet(self):
        timestamp = time.time()
        payload = str(random.randint(1000, 9999)) + str(timestamp)
        checksum = hashlib.sha256(payload.encode()).hexdigest()
        return {"payload": payload, "checksum": checksum, "timestamp": timestamp}

    def receive_data(self):
        signal = self.generate_biosignal()
        packet = self.send_packet()
        self.traffic_log.append((signal, packet))
        return signal, packet

    def generate_memory_fingerprint(self):
        memory_data = json.dumps({"config": [1, 2, 3], "version": "1.0.0"})
        return hashlib.md5(memory_data.encode()).hexdigest()

# ========== Security Monitor ==========
class CyborgSecurityMonitor:
    def __init__(self, interface: CyborgInterface):
        self.interface = interface
        self.alerts = []
        self.signal_window = []
        self.last_check_time = datetime.now()
        self.csv_file = "alerts.csv"
        self.json_file = "alerts.json"
        self.exported_alerts = []

    def detect_spoofed_signal(self, signal):
        mean = statistics.mean(self.interface.signal_baseline)
        stdev = statistics.stdev(self.interface.signal_baseline)
        if abs(signal - mean) > 3 * stdev:
            self.raise_alert("Spoofed signal detected", signal)

    def detect_signal_drift(self, signal):
        self.signal_window.append(signal)
        if len(self.signal_window) > 20:
            self.signal_window.pop(0)
            window_stdev = statistics.stdev(self.signal_window)
            if window_stdev > 10:
                self.raise_alert("Signal drift anomaly detected", self.signal_window[-5:])

    def verify_packet(self, packet):
        payload = packet["payload"]
        checksum = packet["checksum"]
        expected = hashlib.sha256(payload.encode()).hexdigest()
        if checksum != expected:
            self.raise_alert("Tampered packet detected", packet)

    def detect_replay_attack(self, packet):
        timestamp = packet.get("timestamp")
        if timestamp in self.interface.last_packet_timestamps:
            self.raise_alert("Replay attack detected", packet)
        else:
            self.interface.last_packet_timestamps.add(timestamp)

    def detect_clock_tampering(self):
        now = datetime.now()
        if now < self.last_check_time:
            self.raise_alert("System clock tampering detected", {
                "previous_time": self.last_check_time.isoformat(),
                "current_time": now.isoformat()
            })
        self.last_check_time = now

    def verify_memory_integrity(self):
        expected = self.interface.memory_fingerprint
        actual = self.interface.generate_memory_fingerprint()
        if expected != actual:
            self.raise_alert("Memory fingerprint mismatch", {"expected": expected, "actual": actual})

    def compute_threat_score(self, reason):
        score_map = {
            "spoofed": 4,
            "drift": 2,
            "tampered": 5,
            "replay": 5,
            "clock": 3,
            "memory": 4
        }
        for keyword, score in score_map.items():
            if keyword in reason.lower():
                return score
        return 1

    def raise_alert(self, reason, data):
        severity = self.compute_threat_score(reason)
        alert = {
            "time": datetime.now().isoformat(),
            "reason": reason,
            "severity": severity,
            "data": data,
            "device_id": self.interface.device_id
        }
        encrypted_alert = cipher.encrypt(json.dumps(alert).encode()).decode()
        logging.warning(f"{reason}: {data} (Severity: {severity})")
        self.alerts.append(encrypted_alert)
        self.exported_alerts.append(alert)
        self.export_alert_to_csv(alert)
        self.export_alerts_to_json()
        self.send_email_alert(alert)
        self.auto_remediate_if_critical(reason)
        if DEBUG_MODE:
            print(f"[DEBUG] Alert raised: {reason} | Severity: {severity}\nData: {data}")

    def export_alert_to_csv(self, alert):
        file_exists = os.path.isfile(self.csv_file)
        with open(self.csv_file, mode='a', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=alert.keys())
            if not file_exists:
                writer.writeheader()
            writer.writerow(alert)

    def export_alerts_to_json(self):
        with open(self.json_file, 'w') as f:
            json.dump(self.exported_alerts, f, indent=4)

    def send_email_alert(self, alert):
        pass

    def auto_remediate_if_critical(self, reason):
        if "tampering" in reason.lower() or "replay" in reason.lower():
            logging.info("Auto-remediation triggered: Isolating affected node...")
            time.sleep(0.5)

    def run_monitoring_cycle(self, cycles=100):
        for _ in range(cycles):
            self.detect_clock_tampering()
            signal, packet = self.interface.receive_data()
            self.detect_spoofed_signal(signal)
            self.detect_signal_drift(signal)
            self.verify_packet(packet)
            self.detect_replay_attack(packet)
            time.sleep(0.01)
        self.verify_memory_integrity()

# ========== Flask Dashboard ==========
app = Flask(__name__)
monitor_instance = None

@app.route('/')
def dashboard():
    decrypted_alerts = [json.loads(cipher.decrypt(a.encode())) for a in monitor_instance.alerts]
    return render_template_string('''
    <h1>CyborgSecurity Dashboard</h1>
    <p><strong>Implant Type:</strong> {{ implant_type }}</p>
    <p>Total Alerts: {{alerts|length}}</p>
    <ul>
    {% for alert in alerts %}
        <li><strong>{{ alert.reason }}</strong> (Severity: {{ alert.severity }}) at {{ alert.time }} - {{ alert.device_id }}</li>
    {% endfor %}
    </ul>
    ''', alerts=decrypted_alerts, implant_type=monitor_instance.interface.implant_type)

@app.route('/api/alerts', methods=['GET'])
def api_alerts():
    decrypted_alerts = [json.loads(cipher.decrypt(a.encode())) for a in monitor_instance.alerts]
    return jsonify(decrypted_alerts)

# ========== Main Simulation ==========
def main():
    global DEBUG_MODE, monitor_instance

    # User prompt to toggle debug mode
    print("[INPUT] Welcome to CyborgSecurity.")
    print("[INPUT] Type 'on' to enable debug mode, 'off' to disable, or 'exit' to quit.")
    user_input = input("[INPUT] Set debug mode: ").strip().lower()
    if user_input == 'exit':
        print("[INFO] Exiting program...")
        return
    elif user_input == 'on':
        DEBUG_MODE = True
        print("[INFO] Debug mode ENABLED")
    elif user_input == 'off':
        DEBUG_MODE = False
        print("[INFO] Debug mode DISABLED")
    else:
        print("[INFO] Invalid input. Defaulting to debug mode OFF")

    device = CyborgInterface(device_id="CYB-2025-001")
    monitor = CyborgSecurityMonitor(device)
    monitor_instance = monitor
    print("[INFO] Implant type:", device.implant_type)
    print("[INFO] Running CyborgSecurity monitoring...")
    monitor.run_monitoring_cycle(200)
    print(f"[INFO] Monitoring complete. {len(monitor.alerts)} alerts detected.")
    print("[INFO] Launching dashboard... Press Ctrl+C to stop the server.")
    app.run(debug=DEBUG_MODE, port=5000)

if __name__ == '__main__':
    main()
