# cyborgsecurity.py

"""
CyborgSecurity: A simulated cybersecurity suite for human-machine interfaces (HMI).
This prototype scans for spoofed biosignal data, monitors neural device communication,
and detects anomalies in implant I/O traffic to defend cyborg systems from attacks.
Includes signal frequency drift detection, memory integrity verification,
replay attack detection, system clock tampering alerts, email alerts,
real-time JSON alert export, CSV logging, dashboard reporting, alert encryption,
basic auto-remediation, authentication, unit tests, and more.

Usage:
  python cyborgsecurity.py --debug      # Turn debug mode ON
  python cyborgsecurity.py --no-debug   # Turn debug mode OFF
  python cyborgsecurity.py test         # Run unit tests
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
import threading
import unittest

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
        self.implant_type = "NeuroLink V3"
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
            baseline_mean = statistics.mean(self.interface.signal_baseline)
            baseline_stdev = statistics.stdev(self.interface.signal_baseline)
            current_mean = statistics.mean(self.signal_window)
            if abs(current_mean - baseline_mean) > 2 * baseline_stdev:
                self.raise_alert("Adaptive signal drift detected", self.signal_window[-5:])

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
        try:
            # In a real implementation, use environment variables for credentials
            msg = EmailMessage()
            msg.set_content(f"ALERT: {alert['reason']}\nSeverity: {alert['severity']}\nTime: {alert['time']}\nDevice ID: {alert['device_id']}")
            msg['Subject'] = f"[CyborgSecurity] Critical Alert - {alert['reason']}"
            msg['From'] = "cyborgsecurity@example.com"
            msg['To'] = "admin@example.com"

            # This is a mock implementation - in production, use actual SMTP settings
            if DEBUG_MODE:
                print(f"[EMAIL] Would send alert: {alert['reason']} to admin@example.com")
            # Uncomment and configure for real email sending:
            # with smtplib.SMTP('smtp.example.com', 587) as server:
            #     server.starttls()
            #     server.login("cyborgsecurity@example.com", "your_password")
            #     server.send_message(msg)

            logging.info("Email alert sent successfully.")
        except Exception as e:
            logging.error(f"Failed to send email alert: {e}")

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

# Basic authentication for dashboard
from flask import request, Response
import functools

def check_auth(username, password):
    """This function is called to check if a username /
    password combination is valid.
    """
    return username == 'admin' and password == 'cyborg123'

def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
    'Could not verify your access level for that URL.\n'
    'You have to login with proper credentials', 401,
    {'WWW-Authenticate': 'Basic realm="Login Required"'})

def requires_auth(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

# HTML content for the main page
MAIN_PAGE_HTML = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyborgSecurity - Advanced Cybersecurity Suite</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary: #00ff41;
            --secondary: #008f11;
            --dark: #003b00;
            --darker: #001a00;
            --black: #000000;
            --gray: #1a1a1a;
            --light-gray: #2a2a2a;
            --critical: #ff0033;
            --warning: #ffaa00;
            --info: #00aaff;
            --purple: #8a2be2;
        }
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            background: linear-gradient(135deg, var(--black), var(--darker));
            color: #e0e0e0;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.7;
            overflow-x: hidden;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        header {
            text-align: center;
            padding: 60px 20px;
            background: linear-gradient(135deg, rgba(0, 59, 0, 0.3), rgba(0, 0, 0, 0.8));
            border-radius: 20px;
            margin: 20px 0 40px 0;
            position: relative;
            overflow: hidden;
            border: 1px solid var(--secondary);
            box-shadow: 0 0 30px rgba(0, 255, 65, 0.1);
        }
        header::before {
            content: "";
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, var(--primary), var(--purple), var(--primary));
            animation: gradient 3s ease-in-out infinite;
        }
        @keyframes gradient {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }
        h1 {
            font-size: 4rem;
            letter-spacing: 6px;
            margin-bottom: 20px;
            background: linear-gradient(90deg, var(--primary), var(--info));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            text-shadow: 0 0 20px rgba(0, 255, 65, 0.3);
            font-weight: 800;
        }
        .subtitle {
            font-size: 1.4rem;
            color: var(--primary);
            max-width: 800px;
            margin: 0 auto 30px;
            font-weight: 300;
        }
        .tagline {
            font-size: 1.1rem;
            color: var(--secondary);
            max-width: 800px;
            margin: 0 auto;
        }
        .features {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 30px;
            margin: 50px 0;
        }
        .feature-card {
            background: linear-gradient(145deg, var(--darker), var(--dark));
            border: 1px solid rgba(0, 143, 17, 0.3);
            padding: 30px;
            border-radius: 15px;
            transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
            position: relative;
            overflow: hidden;
        }
        .feature-card::before {
            content: "";
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 4px;
            background: linear-gradient(90deg, var(--primary), var(--purple));
            transform: scaleX(0);
            transform-origin: left;
            transition: transform 0.4s ease;
        }
        .feature-card:hover {
            transform: translateY(-10px);
            box-shadow: 0 15px 35px rgba(0, 255, 65, 0.2);
            border-color: rgba(0, 255, 65, 0.5);
        }
        .feature-card:hover::before {
            transform: scaleX(1);
        }
        .feature-icon {
            font-size: 2.5rem;
            color: var(--primary);
            margin-bottom: 20px;
        }
        .feature-card h3 {
            color: var(--primary);
            margin-bottom: 15px;
            font-size: 1.5rem;
            font-weight: 600;
        }
        .feature-card p {
            color: #ccc;
            font-size: 1rem;
            line-height: 1.6;
        }
        .terminal {
            background: linear-gradient(145deg, var(--darker), var(--black));
            border: 2px solid var(--primary);
            border-radius: 15px;
            padding: 30px;
            margin: 50px 0;
            position: relative;
            overflow: hidden;
            box-shadow: 0 0 30px rgba(0, 255, 65, 0.2);
        }
        .terminal::before {
            content: "";
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 40px;
            background: rgba(0, 255, 65, 0.1);
            border-bottom: 1px solid var(--primary);
        }
        .terminal-header {
            display: flex;
            align-items: center;
            margin-bottom: 25px;
            padding-left: 15px;
            position: relative;
            z-index: 1;
        }
        .terminal-dots {
            display: flex;
            gap: 10px;
        }
        .dot {
            width: 14px;
            height: 14px;
            border-radius: 50%;
        }
        .dot-red { background: #ff5f56; box-shadow: 0 0 10px #ff5f56; }
        .dot-yellow { background: #ffbd2e; box-shadow: 0 0 10px #ffbd2e; }
        .dot-green { background: #27c93f; box-shadow: 0 0 10px #27c93f; }
        .terminal-title {
            color: var(--primary);
            margin-left: 20px;
            font-size: 1rem;
            font-weight: 500;
        }
        .terminal-content {
            font-family: 'Courier New', monospace;
            font-size: 1rem;
            line-height: 2;
            color: #00ff41;
            position: relative;
            z-index: 1;
            padding: 0 15px;
        }
        .terminal-content span {
            color: #00aaff;
        }
        .usage {
            background: linear-gradient(145deg, var(--darker), var(--dark));
            border-left: 4px solid var(--primary);
            padding: 25px;
            margin: 40px 0;
            border-radius: 0 15px 15px 0;
        }
        .usage h3 {
            margin-bottom: 20px;
            color: var(--primary);
            font-size: 1.4rem;
        }
        .usage code {
            display: block;
            background: var(--black);
            padding: 20px;
            border-radius: 10px;
            margin: 15px 0;
            font-family: 'Courier New', monospace;
            color: var(--primary);
            overflow-x: auto;
            border: 1px solid rgba(0, 255, 65, 0.2);
            white-space: pre;
        }
        .section {
            margin: 60px 0;
            padding: 40px;
            background: linear-gradient(145deg, var(--darker), var(--dark));
            border-radius: 20px;
            border: 1px solid rgba(0, 143, 17, 0.3);
        }
        .section h2 {
            color: var(--primary);
            margin-bottom: 30px;
            font-size: 2.5rem;
            font-weight: 700;
            position: relative;
            padding-bottom: 15px;
        }
        .section h2::after {
            content: "";
            position: absolute;
            bottom: 0;
            left: 0;
            width: 100px;
            height: 3px;
            background: linear-gradient(90deg, var(--primary), var(--purple));
            border-radius: 2px;
        }
        .section h3 {
            color: var(--secondary);
            margin: 25px 0 15px 0;
            font-size: 1.4rem;
            font-weight: 600;
        }
        .section ul {
            margin: 20px 0;
            padding-left: 25px;
        }
        .section li {
            margin: 12px 0;
            color: #ccc;
            position: relative;
            padding-left: 20px;
        }
        .section li::before {
            content: "▶";
            color: var(--primary);
            position: absolute;
            left: 0;
            top: 0;
        }
        .section p {
            margin: 15px 0;
            font-size: 1.1rem;
            line-height: 1.8;
        }
        .social-buttons {
            text-align: center;
            margin: 50px 0;
            display: flex;
            justify-content: center;
            gap: 20px;
            flex-wrap: wrap;
        }
        .social-button {
            display: inline-flex;
            align-items: center;
            gap: 10px;
            background: linear-gradient(145deg, var(--secondary), var(--dark));
            color: white;
            padding: 15px 30px;
            font-size: 1.1rem;
            text-decoration: none;
            border-radius: 50px;
            font-weight: 600;
            transition: all 0.3s ease;
            border: 2px solid var(--primary);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.3);
        }
        .social-button:hover {
            background: linear-gradient(145deg, var(--primary), var(--secondary));
            color: var(--black);
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(0, 255, 65, 0.4);
        }
        .cta-section {
            text-align: center;
            padding: 80px 40px;
            background: linear-gradient(135deg, rgba(0, 59, 0, 0.2), rgba(0, 0, 0, 0.8));
            margin: 60px 0;
            border-radius: 20px;
            position: relative;
            overflow: hidden;
            border: 1px solid var(--secondary);
        }
        .cta-section::before {
            content: "";
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, var(--primary), var(--purple), var(--primary));
        }
        .cta-section h2 {
            font-size: 3rem;
            margin-bottom: 20px;
            background: linear-gradient(90deg, var(--primary), var(--info));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .cta-section p {
            font-size: 1.3rem;
            color: var(--secondary);
            max-width: 700px;
            margin: 0 auto 40px;
        }
        .cta-button {
            display: inline-block;
            background: linear-gradient(145deg, var(--primary), var(--secondary));
            color: var(--black);
            padding: 20px 50px;
            font-size: 1.3rem;
            text-decoration: none;
            border-radius: 50px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 2px;
            transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
            border: none;
            box-shadow: 0 10px 30px rgba(0, 255, 65, 0.3);
            margin: 10px;
        }
        .cta-button:hover {
            transform: translateY(-5px) scale(1.05);
            box-shadow: 0 15px 40px rgba(0, 255, 65, 0.5);
        }
        .dashboard-button {
            display: inline-block;
            background: linear-gradient(145deg, var(--info), var(--secondary));
            color: white;
            padding: 15px 30px;
            font-size: 1.1rem;
            text-decoration: none;
            border-radius: 50px;
            font-weight: 600;
            transition: all 0.3s ease;
            border: 2px solid var(--primary);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.3);
            margin-top: 20px;
        }
        .dashboard-button:hover {
            background: linear-gradient(145deg, var(--primary), var(--info));
            color: var(--black);
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(0, 255, 65, 0.4);
        }
        footer {
            text-align: center;
            padding: 40px 0;
            border-top: 1px solid var(--secondary);
            color: var(--secondary);
            font-size: 1rem;
            margin-top: 60px;
        }
        .pulse {
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0% { opacity: 0.6; }
            50% { opacity: 1; }
            100% { opacity: 0.6; }
        }
        .glow {
            animation: glow 3s ease-in-out infinite alternate;
        }
        @keyframes glow {
            from { text-shadow: 0 0 5px var(--primary); }
            to { text-shadow: 0 0 20px var(--primary), 0 0 30px var(--secondary); }
        }
        @media (max-width: 768px) {
            h1 {
                font-size: 2.5rem;
            }
            .subtitle {
                font-size: 1.1rem;
            }
            .container {
                padding: 15px;
            }
            .section {
                padding: 25px;
            }
            .section h2 {
                font-size: 2rem;
            }
            .features {
                grid-template-columns: 1fr;
            }
            .social-button {
                width: 100%;
                justify-content: center;
            }
        }
        .hero-content {
            max-width: 800px;
            margin: 0 auto;
            padding: 40px 20px;
        }
        .hero-title {
            font-size: 3.5rem;
            margin-bottom: 20px;
            background: linear-gradient(90deg, var(--primary), #00aaff);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            text-shadow: 0 0 15px rgba(0, 255, 65, 0.2);
        }
        .hero-subtitle {
            font-size: 1.3rem;
            color: var(--primary);
            margin-bottom: 25px;
            font-weight: 300;
        }
        .hero-tagline {
            font-size: 1.1rem;
            color: #a0a0a0;
            margin-bottom: 30px;
            max-width: 700px;
            margin-left: auto;
            margin-right: auto;
        }
        .hero-button {
            display: inline-block;
            background: linear-gradient(145deg, var(--primary), var(--secondary));
            color: var(--black);
            padding: 18px 45px;
            font-size: 1.2rem;
            text-decoration: none;
            border-radius: 50px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            transition: all 0.3s ease;
            border: none;
            box-shadow: 0 8px 25px rgba(0, 255, 65, 0.4);
            margin-top: 20px;
        }
        .hero-button:hover {
            transform: translateY(-3px) scale(1.03);
            box-shadow: 0 12px 30px rgba(0, 255, 65, 0.6);
        }
        .hero-button i {
            margin-right: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="hero-content">
                <h1 class="hero-title glow">CyborgSecurity</h1>
                <p class="hero-subtitle">Advanced Cybersecurity Suite for Human-Machine Interfaces</p>
                <p class="hero-tagline">Protecting next-generation cyborg systems from sophisticated cyber threats</p>
                <a href="/dashboard" class="hero-button">
                    <i class="fas fa-shield-alt"></i> Access Security Dashboard
                </a>
            </div>
        </header>
        <section class="section">
            <h2>About CyborgSecurity</h2>
            <p>CyborgSecurity is a simulated cybersecurity suite for monitoring and protecting human-machine interfaces (HMI), specifically designed for cyborg implants such as neural links, pacemakers, and electronic prosthetics. This Python-based tool detects spoofed signals, communication tampering, memory anomalies, and more — complete with real-time alert encryption, dashboard visualization, and an extensible architecture.</p>
        </section>
        <section class="section">
            <h2>What It Does</h2>
            <ul>
                <li>Monitors neural biosignals for spoofing, drift, and replay attacks</li>
                <li>Validates data packet integrity and detects clock tampering</li>
                <li>Verifies device memory fingerprints to prevent firmware-level hacks</li>
                <li>Calculates threat severity scores for triage</li>
                <li>Auto-remediates certain critical threats</li>
                <li>Logs alerts to encrypted JSON and CSV files</li>
                <li>Sends alerts to a local Flask dashboard</li>
                <li>Supports encrypted alert logging and future email notifications</li>
            </ul>
        </section>
        <section class="features">
            <div class="feature-card">
                <div class="feature-icon">
                    <i class="fas fa-brain"></i>
                </div>
                <h3>Biosignal Spoofing Detection</h3>
                <p>Advanced statistical analysis to detect anomalous biosignal patterns that may indicate spoofing attempts or corrupted data transmission.</p>
            </div>
            <div class="feature-card">
                <div class="feature-icon">
                    <i class="fas fa-network-wired"></i>
                </div>
                <h3>Neural Device Monitoring</h3>
                <p>Real-time monitoring of neural device communication protocols with checksum verification and replay attack detection.</p>
            </div>
            <div class="feature-card">
                <div class="feature-icon">
                    <i class="fas fa-exchange-alt"></i>
                </div>
                <h3>Implant I/O Traffic Analysis</h3>
                <p>Deep packet inspection and traffic analysis to identify suspicious patterns in implant input/output operations.</p>
            </div>
            <div class="feature-card">
                <div class="feature-icon">
                    <i class="fas fa-wave-square"></i>
                </div>
                <h3>Signal Frequency Drift Detection</h3>
                <p>Continuous monitoring of signal stability to detect frequency drift anomalies that could indicate system compromise.</p>
            </div>
            <div class="feature-card">
                <div class="feature-icon">
                    <i class="fas fa-shield-alt"></i>
                </div>
                <h3>Memory Integrity Verification</h3>
                <p>Cryptographic verification of system memory to ensure configuration and operational integrity.</p>
            </div>
            <div class="feature-card">
                <div class="feature-icon">
                    <i class="fas fa-lock"></i>
                </div>
                <h3>Encrypted Alert System</h3>
                <p>Military-grade encryption for all security alerts with real-time JSON export and CSV logging capabilities.</p>
            </div>
        </section>
        <section class="section">
            <h2>Features</h2>
            <ul>
                <li><strong>Cyborg Simulation:</strong> Emulates biosignals and I/O traffic for implantable devices</li>
                <li><strong>Threat Detection:</strong> Identifies spoofed, replayed, and tampered data</li>
                <li><strong>Flask Web Dashboard:</strong> View alerts and implant type in real time</li>
                <li><strong>Email Placeholder:</strong> Easily extend to send alerts via email</li>
                <li><strong>Logging:</strong> CSV, JSON, and plaintext logging of all anomalies</li>
                <li><strong>Encryption:</strong> Alerts are encrypted using Fernet (symmetric AES)</li>
                <li><strong>Debug Mode Toggle:</strong> Turn debug output on or off via terminal</li>
            </ul>
        </section>
        <section class="section">
            <h2>How to Run</h2>
            <h3>1. Clone the Repository</h3>
            <div class="usage">
                <code>git clone https://github.com/youngsassanid/cyborgsecurity.git
cd cyborgsecurity</code>
            </div>
            <h3>2. Set Up the Virtual Environment</h3>
            <div class="usage">
                <code>python -m venv .venv
source .venv/bin/activate       # On Windows use: .venv\\Scripts\\activate
pip install -r requirements.txt</code>
            </div>
            <p>If requirements.txt does not exist, you can manually install:</p>
            <div class="usage">
                <code>pip install flask cryptography</code>
            </div>
            <h3>3. Run the Program</h3>
            <div class="usage">
                <code>python cyborgsecurity.py</code>
            </div>
            <p>You'll be prompted to toggle debug mode and the system will begin scanning.</p>
        </section>
        <section class="section">
            <h2>Accessing the Dashboard</h2>
            <p>Once the system finishes scanning:</p>
            <ul>
                <li>Open your browser and go to: <strong>http://localhost:5000/dashboard</strong></li>
                <li>View all alerts, threat severities, and device metadata.</li>
            </ul>
        </section>
        <section class="section">
            <h2>Output Files</h2>
            <ul>
                <li><strong>cyborgsecurity.log:</strong> System events & errors</li>
                <li><strong>alerts.json:</strong> Decrypted alert data for external integrations</li>
                <li><strong>alerts.csv:</strong> Tabular version of all alerts</li>
                <li><strong>ENCRYPTION_KEY:</strong> Not stored — ephemeral key is generated at runtime (for now)</li>
            </ul>
        </section>
        <section class="section">
            <h2>Debug Mode</h2>
            <p>When launching, type <strong>on</strong> to enable debug mode or <strong>off</strong> to keep it silent.</p>
            <div class="usage">
                <code>[INPUT] Type 'on' to enable debug mode, 'off' to disable, or 'exit' to quit.</code>
            </div>
        </section>
        <section class="section">
            <h2>Implant Simulation</h2>
            <p>The system currently simulates a NeuroLink V3 implant, but you can expand the CyborgInterface class to model:</p>
            <ul>
                <li>Electronic prosthetic limbs</li>
                <li>Implantable cardioverter-defibrillators (ICDs)</li>
                <li>Smart cochlear implants</li>
                <li>Retinal chip implants</li>
                <li>Brain-computer interfaces (BCIs)</li>
            </ul>
        </section>
         <section class="section">
            <h2>Author</h2>
            <div class="author-section">
                <div class="author-bio">
                    <p>Sām Kazemi is a dedicated <span class="highlight">Computer Science student at San Francisco State University</span> with a minor in Persian Studies, originally from Antioch, California and born in the East Bay Area. Born to Iranian immigrant parents, he was raised with strong values of hard work, resilience, and community commitment.</p>
                    <p>Having witnessed the impact of gang violence firsthand, Sām serves as a <span class="highlight">mentor and community figure</span> promoting positive change, discipline, and empowerment. As a <span class="highlight">natural bodybuilder and martial artist</span>, he exemplifies physical and mental strength while encouraging others to follow constructive paths.</p>
                    <p>Sām's passion for <span class="highlight">cybersecurity</span> drives his technical work, including developing <span class="highlight">CyborgSecurity</span>, a Python-based tool designed to protect advanced technologies like neural implants. Through this project, he aims to create solutions that safeguard privacy and security in today's connected world.</p>
                    <p>Proud of his Iranian heritage, Sām is committed to advancing his community through <span class="highlight">education, cultural awareness, and advocacy</span>, blending his technical expertise and personal discipline to inspire success grounded in identity and values.</p>
                </div>
            </div>
        </section>
        <div class="social-buttons">
            <a href="https://www.linkedin.com/in/mojtaba-kazemi-529264317/" class="social-button" target="_blank">
                <i class="fab fa-linkedin"></i> View LinkedIn Profile
            </a>
            <a href="https://github.com/youngsassanid/cyborgsecurity" class="social-button" target="_blank">
                <i class="fab fa-github"></i> View GitHub Repository
            </a>
        </div>
        <section class="cta-section">
            <h2>Ready to Secure Your Cyborg Infrastructure?</h2>
            <p>Download CyborgSecurity today and protect your human-machine interfaces from advanced cyber threats</p>
            <a href="https://github.com/youngsassanid/cyborgsecurity" class="cta-button" target="_blank">
                Download Now
            </a>
            <a href="/dashboard" class="cta-button">
                <i class="fas fa-tachometer-alt"></i> View Dashboard
            </a>
        </section>
        <footer>
            <p>CyborgSecurity | Advanced Cybersecurity for the Future of Human-Machine Integration</p>
            <p>This is a simulation prototype. Not for production use.</p>
        </footer>
    </div>
</body>
</html>
'''

@app.route('/')
def home():
    return MAIN_PAGE_HTML

@app.route('/dashboard')
@requires_auth
def dashboard():
    decrypted_alerts = [json.loads(cipher.decrypt(a.encode())) for a in monitor_instance.alerts]
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>CyborgSecurity Dashboard</title>
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; background-color: #001a00; color: #e0e0e0; }
            h1, h2 { color: #00ff41; text-shadow: 0 0 10px rgba(0, 255, 65, 0.5); }
            .alert { 
                background-color: #003b00; 
                border-left: 5px solid #ff3300; 
                padding: 15px; 
                margin: 10px 0; 
                border-radius: 4px;
                box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
            }
            .severity-high { border-left-color: #ff0000; }
            .severity-medium { border-left-color: #ff9900; }
            .severity-low { border-left-color: #00cc00; }
            .device-info { background-color: #008f11; padding: 15px; border-radius: 8px; margin-bottom: 20px; }
            a { color: #00aaff; text-decoration: none; }
            a:hover { text-decoration: underline; }
        </style>
    </head>
    <body>
        <h1>CyborgSecurity Dashboard</h1>
        <div class="device-info">
            <strong>Implant Type:</strong> {{ implant_type }}<br>
            <strong>Device ID:</strong> {{ device_id }}
        </div>
        <h2>Security Alerts ({{alerts|length}})</h2>
        {% for alert in alerts %}
        <div class="alert severity-{{ 'high' if alert.severity >= 4 else 'medium' if alert.severity >= 2 else 'low' }}">
            <strong>{{ alert.reason }}</strong> (Severity: {{ alert.severity }})<br>
            Time: {{ alert.time }}<br>
            Data: {{ alert.data }}
        </div>
        {% endfor %}
        <p><a href="/">← Back to Home</a></p>
    </body>
    </html>
    ''', alerts=decrypted_alerts, 
        implant_type=monitor_instance.interface.implant_type,
        device_id=monitor_instance.interface.device_id)

@app.route('/api/alerts', methods=['GET'])
@requires_auth
def api_alerts():
    decrypted_alerts = [json.loads(cipher.decrypt(a.encode())) for a in monitor_instance.alerts]
    return jsonify(decrypted_alerts)

# ========== Unit Tests ==========
class TestCyborgSecurity(unittest.TestCase):
    def setUp(self):
        self.device = CyborgInterface("TEST-001")
        self.monitor = CyborgSecurityMonitor(self.device)

    def test_spoofed_signal_detection(self):
        # Test that clearly out-of-bounds signals trigger alerts
        self.monitor.detect_spoofed_signal(200)
        self.assertTrue(len(self.monitor.alerts) > 0)
        self.assertIn("Spoofed signal detected", str(self.monitor.alerts))

    def test_normal_signal_no_alert(self):
        # Test that normal signals don't trigger alerts
        initial_alerts = len(self.monitor.alerts)
        self.monitor.detect_spoofed_signal(50)  # Normal value
        self.assertEqual(len(self.monitor.alerts), initial_alerts)

    def test_packet_verification(self):
        # Test that tampered packets are detected
        packet = {"payload": "test", "checksum": "invalid_checksum", "timestamp": time.time()}
        self.monitor.verify_packet(packet)
        self.assertTrue(any("Tampered packet detected" in str(alert) for alert in self.monitor.alerts))

    def test_replay_attack_detection(self):
        # Test that replay attacks are detected
        packet = self.device.send_packet()
        # Send the same packet twice
        self.monitor.detect_replay_attack(packet)
        self.monitor.detect_replay_attack(packet)
        self.assertTrue(any("Replay attack detected" in str(alert) for alert in self.monitor.alerts))

    def test_memory_integrity_check(self):
        # Test that memory changes are detected
        original_fingerprint = self.device.memory_fingerprint
        # Simulate memory corruption
        self.device.memory_fingerprint = "corrupted_fingerprint"
        self.monitor.verify_memory_integrity()
        self.assertTrue(any("Memory fingerprint mismatch" in str(alert) for alert in self.monitor.alerts))
        # Restore for other tests
        self.device.memory_fingerprint = original_fingerprint

# ========== Main Simulation ==========
def run_monitoring_in_background(monitor, cycles=200):
    def monitor_loop():
        monitor.run_monitoring_cycle(cycles)
    thread = threading.Thread(target=monitor_loop)
    thread.daemon = True
    thread.start()
    return thread

def main():
    global DEBUG_MODE, monitor_instance

    parser = argparse.ArgumentParser(description="CyborgSecurity HMI Monitor")
    parser.add_argument('--debug', action='store_true', help="Enable debug mode")
    parser.add_argument('command', nargs='?', default='run', help="Command: run or test")
    args = parser.parse_args()
    
    DEBUG_MODE = args.debug

    if args.command == 'test':
        # Run unit tests
        unittest.main(argv=['cyborgsecurity.py', 'TestCyborgSecurity'], exit=False, verbosity=2)
        return

    device = CyborgInterface(device_id="CYB-2025-001")
    monitor = CyborgSecurityMonitor(device)
    monitor_instance = monitor
    
    print("[INFO] Implant type:", device.implant_type)
    print("[INFO] Running CyborgSecurity monitoring...")
    
    # Start monitoring in background thread
    monitor_thread = run_monitoring_in_background(monitor, 200)
    
    # Wait a moment for some alerts to be generated
    time.sleep(2)
    
    print(f"[INFO] Monitoring started. {len(monitor.alerts)} alerts detected so far.")
    print("[INFO] Visit http://localhost:5000 for the main page")
    print("[INFO] Visit http://localhost:5000/dashboard for the protected dashboard")
    print("[INFO] Dashboard login - username: admin, password: cyborg123")
    print("[INFO] Press Ctrl+C to stop the server.")
    
    try:
        app.run(debug=DEBUG_MODE, port=5000, use_reloader=False)
    except KeyboardInterrupt:
        print("\n[INFO] Shutting down...")
        # Wait for monitoring thread to finish
        monitor_thread.join(timeout=2)
        print("[INFO] Monitoring stopped.")

if __name__ == '__main__':
    main()
