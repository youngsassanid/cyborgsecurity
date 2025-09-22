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
# from email.mime.text import MIMEText
from flask import Flask, jsonify, render_template_string, request
from cryptography.fernet import Fernet
import argparse
import threading
import unittest
import html
import subprocess
from datetime import datetime, timedelta
from flask import Flask, render_template_string, jsonify
from datetime import datetime
import logging

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
        self.implant_type = "Connexus"
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
    <link rel="icon" type="image/png" href="/favicon.png">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
    .hero-logo {
        width: 150px;
        height: 150px;
        margin: 0 auto 20px auto;
        display: block;
        border-radius: 50%;
}
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
    padding: 10px 15px; /* Minimal vertical padding */
    text-align: center;
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
        .purple-glow {
    background: linear-gradient(145deg, var(--purple), #6a0dad) !important;
    color: white;
    box-shadow: 0 8px 25px rgba(138, 43, 226, 0.7) !important; /* purple idle glow */
}
.purple-glow:hover {
    box-shadow: 0 12px 30px rgba(138, 43, 226, 0.8) !important; /* stronger purple hover glow */
    transform: translateY(-3px) scale(1.03);
}

        .hero-button {
            display: inline-block;
            background: linear-gradient(145deg, var(--primary), var(--secondary));
            color: var(--black);
            padding: 10px 35px;
            font-size: 1rem;
            text-decoration: none;
            border-radius: 50px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            transition: all 0.3s ease;
            border: none;
            box-shadow: 0 8px 25px rgba(0, 255, 65, 0.4);
            margin-top: 8px;
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
    <!-- ========== Navigation Bar ========== -->
    <nav style="
        background: rgba(0, 59, 0, 0.3);
        padding: 12px 20px;
        border-radius: 10px;
        margin-bottom: 20px;
        display: flex;
        justify-content: center;
        gap: 30px;
        font-weight: 600;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
        border: 1px solid rgba(0, 255, 65, 0.2);
    ">
        <a href="/" style="color: var(--primary); text-decoration: none;">CyborgSecurity</a> 
        <a href="/guide" style="color: var(--primary); text-decoration: none;">Setup Guide</a>
        <a href="/resources" style="color: var(--primary); text-decoration: none;">Resources</a>
        <a href="/pricing" style="color: var(--primary); text-decoration: none;">Pricing</a>
        <a href="/about" style="color: var(--primary); text-decoration: none;">About</a>
        <a href="/contact" style="color: var(--primary); text-decoration: none;">Contact</a>
    </nav>

    <div class="container">
        <header>
            <div class="hero-content">
                <img src="/favicon.png" alt="CyborgSecurity Logo" class="hero-logo">

                <h1 class="hero-title glow">CyborgSecurity</h1>
                <p class="hero-subtitle">Protecting next-generation medical implants from sophisticated cyber threats</p>
                <!-- <p class="hero-tagline">Protecting next-generation cyborg systems from sophisticated cyber threats</p> -->
                <a href="/dashboard" class="hero-button">
                    <i class="fas fa-shield-alt"></i> Access Security Dashboard
                </a>
                <a href="/threat-intel" class="hero-button purple-glow" style="background: linear-gradient(145deg, var(--purple), #6a0dad); margin-top: 15px;">
    <i class="fas fa-globe"></i> Open Threat Intelligence
                </a>
                <a href="/goat-mode" class="hero-button" style="
    background: linear-gradient(145deg, #00e6b8, #00a88a); 
    color: var(--black); 
    margin-top: 15px; 
    box-shadow: 0 8px 25px rgba(0, 230, 184, 0.5);
    text-shadow: 0 0 5px rgba(255, 255, 255, 0.6);
">
    <i class="fas fa-crown"></i> ACTIVATE GOAT MODE
</a>
               <a href="/health" class="hero-button" style="
    background: linear-gradient(145deg, #4b6cb7, #6a8ddc);
    color: var(--black);
    margin-top: 15px;
    box-shadow: 0 8px 25px rgba(75, 108, 183, 0.8);
    text-shadow: 0 0 5px rgba(255, 255, 255, 0.7);
">
    <i class="fas fa-stethoscope"></i> Run Health Monitor
</a> 
            </div>
        </header>

                <img src="cyborgsecurity_visualizer.gif" 
     alt="The GOAT stops a cyber threat" 
     style="display:block; margin:15px auto; width:100%; border-radius:12px; 
     box-shadow:0 4px 12px rgba(0,0,0,0.3);">

        <section class="section">
            <h2>About CyborgSecurity</h2>
            <p>CyborgSecurity is a simulated cybersecurity suite for monitoring and protecting human-machine interfaces (HMI), specifically designed 
            for medical implants such as neural links, pacemakers, and electronic prosthetics. This Python-based tool detects spoofed signals, communication 
            tampering, memory anomalies, and more — complete with real-time alert encryption, dashboard visualization, and an extensible architecture.</p>
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
        <li><strong>Threat Detection:</strong> Identifies spoofed, tampered, or replayed data, calculates severity scores, and auto remediates critical threats</li>
        <li><strong>Web Dashboard:</strong> Real-time alert monitoring and implant overview via Flask interface</li>
        <li><strong>Health Monitoring:</strong> Tracks biomedical metrics in real time</li>
        <li><strong>Logging & Encryption:</strong> Logs anomalies in CSV, JSON, or plaintext; alerts encrypted using Fernet (AES)</li>
        <li><strong>Developer Tools:</strong> Unit testing integration and debug mode toggle</li>
        <li><strong>Dynamic Threat Injection:</strong> Searchable and filterable attack data for training and demonstration</li>
        <li><strong>GOAT Mode:</strong> Emergency zero-trust lockdown API endpoints</li>
    </ul>
</section>

        <section class="cta-section">
            <h2>Ready to Secure Your Cyborg Infrastructure?</h2>
            <p>Download CyborgSecurity today and protect your human-machine interfaces from advanced cyber threats</p>
            <a href="https://github.com/youngsassanid/cyborgsecurity" class="cta-button" target="_blank">
                Download Now
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
def CyborgSecurity():
    return MAIN_PAGE_HTML

@app.route('/dashboard')
@requires_auth
def dashboard():
    decrypted_alerts = [json.loads(cipher.decrypt(a.encode())) for a in monitor_instance.alerts]
    # Reverse so newest alerts appear first
    decrypted_alerts.reverse()

    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
        <title>Dashboard | CyborgSecurity</title>
        <link rel="icon" type="image/png" href="/favicon.png">                     
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
                --success: #00cc00;
            }
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, var(--black), var(--darker));
                color: #e0e0e0;
                margin: 0;
                padding: 20px;
                line-height: 1.7;
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
            }
            header {
                text-align: center;
                padding: 30px;
                background: rgba(0, 59, 0, 0.2);
                border-radius: 15px;
                margin-bottom: 30px;
                border: 1px solid var(--secondary);
            }
            h1 {
                font-size: 2.8rem;
                color: var(--primary);
                margin-bottom: 10px;
                text-shadow: 0 0 15px rgba(0, 255, 65, 0.4);
            }
            .device-info {
                background: linear-gradient(145deg, var(--dark), var(--darker));
                padding: 18px;
                border-radius: 12px;
                margin: 20px 0;
                border: 1px solid rgba(0, 255, 65, 0.2);
                font-size: 1.1rem;
            }
            .controls {
                display: flex;
                flex-wrap: wrap;
                gap: 15px;
                margin: 20px 0;
                padding: 15px;
                background: rgba(0, 59, 0, 0.2);
                border-radius: 12px;
                border: 1px solid rgba(0, 143, 17, 0.3);
            }
            .controls input, .controls select, .controls button {
                padding: 10px 14px;
                border: none;
                border-radius: 8px;
                font-size: 1rem;
                background: var(--darker);
                color: var(--primary);
            }
            .controls input::placeholder {
                color: #777;
            }
            .controls button {
                background: var(--primary);
                color: var(--black);
                font-weight: bold;
                cursor: pointer;
                transition: all 0.3s ease;
            }
            .controls button:hover {
                transform: translateY(-2px);
                box-shadow: 0 5px 15px rgba(0, 255, 65, 0.4);
            }
            .alert-list {
                max-height: 70vh;
                overflow-y: auto;
                margin-top: 20px;
            }
            .alert {
                background: rgba(0, 59, 0, 0.2);
                border-left: 6px solid var(--info);
                padding: 16px;
                margin: 12px 0;
                border-radius: 8px;
                box-shadow: 0 3px 10px rgba(0, 0, 0, 0.3);
                transition: transform 0.2s;
            }
            .alert:hover {
                transform: translateX(5px);
            }
            .alert.critical { border-left-color: var(--critical); }
            .alert.high { border-left-color: #ff3300; }
            .alert.medium { border-left-color: var(--warning); }
            .alert.low { border-left-color: var(--success); }

            .alert-header {
                display: flex;
                justify-content: space-between;
                font-weight: 600;
                color: var(--primary);
            }
            .alert-reason {
                font-size: 1.2rem;
            }
            .alert-severity {
                font-size: 0.9rem;
                background: rgba(255, 255, 255, 0.1);
                padding: 3px 8px;
                border-radius: 5px;
            }
            .alert-time {
                font-size: 0.9rem;
                color: var(--secondary);
            }
            .alert-data {
                margin-top: 8px;
                font-family: monospace;
                font-size: 0.95rem;
                color: #ccc;
                background: rgba(0, 0, 0, 0.3);
                padding: 10px;
                border-radius: 6px;
                overflow-x: auto;
            }
                    footer {
            text-align: center;
            padding: 40px 0;
            border-top: 1px solid var(--secondary);
            color: var(--secondary);
            font-size: 1rem;
            margin-top: 60px;
        }
            .empty-state {
                text-align: center;
                padding: 40px;
                color: #777;
                font-style: italic;
            }
            @media (max-width: 768px) {
                .controls {
                    flex-direction: column;
                }
                .controls button {
                    width: 100%;
                }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1><i class="fas fa-shield-alt"></i> CyborgSecurity Dashboard</h1>
                <p>Real-Time Threat Monitoring for Neural Implants</p>
            </header>
            <div class="device-info">
                <strong>Implant Type:</strong> {{ implant_type }} |
                <strong>Device ID:</strong> {{ device_id }} |
                <strong>Total Alerts:</strong> <span id="alert-count">{{ alerts|length }}</span>
            </div>

            <!-- Interactive Controls -->
            <div class="controls">
                <input type="text" id="searchInput" placeholder="🔍 Search reason or data..." />
                <select id="severityFilter">
                    <option value="">All Severities</option>
                    <option value="5">Critical (5)</option>
                    <option value="4">High (4)</option>
                    <option value="3">Medium (3)</option>
                    <option value="2">Low-Medium (2)</option>
                    <option value="1">Low (1)</option>
                </select>
                <button onclick="refreshAlerts()">
                    <i class="fas fa-sync"></i> Refresh
                </button>
                <label>
                    <input type="checkbox" id="autoRefresh" onchange="toggleAutoRefresh(this)">
                    Auto-refresh
                </label>
                <button onclick="clearAlerts()" style="background:#ff3300">
                    <i class="fas fa-trash"></i> Clear All
                </button>
                <button onclick="exportToJson()">
                    <i class="fas fa-file-export"></i> Export JSON
                </button>
                <button onclick="exportToCsv()">
                    <i class="fas fa-file-csv"></i> Export CSV
                </button>
                <button onclick="downloadTests()" style="background:var(--primary); color:var(--black);">
                    <i class="fas fa-vial"></i> Download Unit Tests
                </button>
                <button onclick="window.location='/test'" style="background:var(--primary); color:var(--black);">
    <i class="fas fa-vial"></i> Run Unit Tests
</button>

            </div>

            <!-- Alert List -->
            <div class="alert-list" id="alertList">
                {% if alerts %}
                    {% for alert in alerts %}
                        <div class="alert alert-{{ 'critical' if alert.severity == 5 else 'high' if alert.severity >= 4 else 'medium' if alert.severity >= 2 else 'low' }}"
                             data-severity="{{ alert.severity }}" data-reason="{{ alert.reason }}" data-data='{{ alert.data | tojson }}'>
                            <div class="alert-header">
                                <span class="alert-reason">{{ alert.reason }}</span>
                                <span class="alert-severity">Severity: {{ alert.severity }}</span>
                            </div>
                            <div class="alert-time">{{ alert.time }}</div>
                            <div class="alert-data">{{ alert.data }}</div>
                        </div>
                    {% endfor %}
                {% else %}
                    <div class="empty-state">
                        <i class="fas fa-check-circle" style="font-size:3rem; color:var(--success);"></i>
                        <p>No alerts detected. System secure.</p>
                    </div>
                {% endif %}
            </div>

            <div class="footer">
                <p>CyborgSecurity | <a href="/" style="color:var(--info)">← Back to Home</a> | 
                <a href="/threat-intel" style="color:var(--primary)">Threat Intel</a> 
                | <a href="/goat-mode" style="color:var(--primary)">GOAT Mode</a> | 
                <a href="/health" style="color:var(--primary)">Health Monitor</a> | Last updated: <span id="lastUpdate">{{ now }}</span></p>
            </div>
        </div>

        <script>
            let autoRefreshInterval;

            function filterAlerts() {
                const search = document.getElementById('searchInput').value.toLowerCase();
                const severity = document.getElementById('severityFilter').value;
                const alerts = document.querySelectorAll('.alert');

                alerts.forEach(alert => {
                    const reason = alert.getAttribute('data-reason').toLowerCase();
                    const data = alert.getAttribute('data-data').toLowerCase();
                    const alertSeverity = alert.getAttribute('data-severity');

                    const matchesSearch = reason.includes(search) || data.includes(search);
                    const matchesSeverity = !severity || alertSeverity === severity;

                    alert.style.display = matchesSearch && matchesSeverity ? 'block' : 'none';
                });

                updateAlertCount();
            }

            function updateAlertCount() {
                const visible = document.querySelectorAll('.alert[style*="display: block"], .alert:not([style])').length;
                document.getElementById('alert-count').textContent = visible;
            }
            
            function downloadTests() {
    const link = document.createElement('a');
    link.href = '/download/test';
    link.download = 'test_cyborgsecurity.py';
    link.click();
}

            function refreshAlerts() {
                fetch('/api/alerts')
                    .then(res => res.json())
                    .then(data => {
                        const alertList = document.getElementById('alertList');
                        let html = '';

                        if (data.length === 0) {
                            html = `
                                <div class="empty-state">
                                    <i class="fas fa-check-circle" style="font-size:3rem; color:var(--success);"></i>
                                    <p>No alerts detected. System secure.</p>
                                </div>`;
                        } else {
                            data.reverse(); // newest first
                            data.forEach(alert => {
                                const level = alert.severity === 5 ? 'critical' :
                                             alert.severity >= 4 ? 'high' :
                                             alert.severity >= 2 ? 'medium' : 'low';
                                html += `
                                <div class="alert alert-${level}" data-severity="${alert.severity}" data-reason="${alert.reason}" data-data='${JSON.stringify(alert.data)}'>
                                    <div class="alert-header">
                                        <span class="alert-reason">${alert.reason}</span>
                                        <span class="alert-severity">Severity: ${alert.severity}</span>
                                    </div>
                                    <div class="alert-time">${alert.time}</div>
                                    <div class="alert-data">${JSON.stringify(alert.data)}</div>
                                </div>`;
                            });
                        }
                        alertList.innerHTML = html;
                        filterAlerts();
                        document.getElementById('lastUpdate').textContent = new Date().toLocaleString();
                    })
                    .catch(err => console.error('Failed to refresh alerts:', err));
            }

            function toggleAutoRefresh(checkbox) {
                if (checkbox.checked) {
                    autoRefreshInterval = setInterval(refreshAlerts, 3000);
                } else {
                    clearInterval(autoRefreshInterval);
                }
            }

            function clearAlerts() {
                if (confirm("Are you sure you want to clear all alerts? This cannot be undone.")) {
                    fetch('/api/clear_alerts', { method: 'POST' })
                        .then(() => {
                            document.getElementById('alertList').innerHTML = `
                                <div class="empty-state">
                                    <i class="fas fa-check-circle" style="font-size:3rem; color:var(--success);"></i>
                                    <p>All alerts cleared. System reset.</p>
                                </div>`;
                            updateAlertCount();
                        })
                        .catch(err => alert('Failed to clear alerts.'));
                }
            }

            function exportToJson() {
                fetch('/api/alerts')
                    .then(res => res.json())
                    .then(data => {
                        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = `cyborgsecurity_alerts_${new Date().toISOString().split('T')[0]}.json`;
                        a.click();
                    });
            }

            function exportToCsv() {
                fetch('/api/alerts')
                    .then(res => res.json())
                    .then(data => {
                        const headers = ['time', 'reason', 'severity', 'data', 'device_id'];
                        const rows = data.map(alert => [
                            alert.time,
                            alert.reason,
                            alert.severity,
                            JSON.stringify(alert.data),
                            alert.device_id
                        ]);
                        let csv = headers.join(',') + '\\n' + rows.map(row => row.map(cell => `"${cell}"`).join(',')).join('\\n');

                        const blob = new Blob([csv], { type: 'text/csv' });
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = `cyborgsecurity_alerts_${new Date().toISOString().split('T')[0]}.csv`;
                        a.click();
                    });
            }

            // Initialize
            document.getElementById('searchInput').addEventListener('input', filterAlerts);
            document.getElementById('severityFilter').addEventListener('change', filterAlerts);

            // Set initial count
            updateAlertCount();

            // Auto-refresh off by default
            document.getElementById('autoRefresh').checked = false;
        </script>
    </body>
    </html>
    ''',
    alerts=decrypted_alerts,
    implant_type=monitor_instance.interface.implant_type,
    device_id=monitor_instance.interface.device_id,
    now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

@app.route('/api/alerts', methods=['GET'])
@requires_auth
def api_alerts():
    decrypted_alerts = [json.loads(cipher.decrypt(a.encode())) for a in monitor_instance.alerts]
    return jsonify(decrypted_alerts)

# ========== New Interactive API Endpoints ==========

@app.route('/api/clear_alerts', methods=['POST'])
@requires_auth
def clear_alerts():
    global monitor_instance
    # Clear alerts in memory
    monitor_instance.alerts.clear()
    monitor_instance.exported_alerts.clear()
    # Clear files
    open('alerts.json', 'w').close()
    open('alerts.csv', 'w').close()
    logging.info("All alerts cleared via dashboard.")
    return jsonify({"status": "success", "message": "All alerts cleared."}), 200

# ========== Threat Intelligence Feed ==========
@app.route('/threat-intel')
@requires_auth
def threat_intel():
    # Simulated real-time threat intelligence data
    sample_threats = [
        {"type": "IP", "value": "192.168.220.45", "source": "Botnet C2", "severity": "High", "timestamp": "2025-04-27T14:22:33"},
        {"type": "Hash", "value": "a1b2c3d4e5f67890abcdef1234567890", "source": "Ransomware Variant X", "severity": "Critical", "timestamp": "2025-04-27T14:20:11"},
        {"type": "Domain", "value": "malware-c2[.]shadownet", "source": "Phishing Campaign", "severity": "High", "timestamp": "2025-04-27T14:18:05"},
        {"type": "IP", "value": "10.5.5.177", "source": "Insider Threat", "severity": "Medium", "timestamp": "2025-04-27T14:15:44"},
        {"type": "Hash", "value": "f0e1d2c3b4a5968778695a4b3c2d1e0f", "source": "Spyware Module", "severity": "Critical", "timestamp": "2025-04-27T14:12:20"},
        {"type": "Domain", "value": "fake-login[.]cyber-scam.com", "source": "Credential Harvester", "severity": "High", "timestamp": "2025-04-27T14:10:01"},
    ]
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
        <title>Threat Intel | CyborgSecurity</title>
        <link rel="icon" type="image/png" href="/favicon.png">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            :root {
                --primary: #00ff41;
                --secondary: #008f11;
                --dark: #003b00;
                --darker: #001a00;
                --black: #000000;
                --gray: #1a1a1a;
                --critical: #ff0033;
                --warning: #ffaa00;
                --info: #00aaff;
                --purple: #8a2be2;
            }
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, var(--black), var(--darker));
                color: #e0e0e0;
                margin: 0;
                padding: 20px;
                line-height: 1.7;
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
            }
            header {
                text-align: center;
                padding: 30px;
                background: rgba(0, 59, 0, 0.2);
                border-radius: 15px;
                margin-bottom: 30px;
                border: 1px solid var(--secondary);
            }
            h1 {
                font-size: 2.8rem;
                color: var(--primary);
                margin-bottom: 10px;
                text-shadow: 0 0 15px rgba(0, 255, 65, 0.4);
            }
            .subtitle {
                font-size: 1.1rem;
                color: var(--secondary);
                margin-bottom: 20px;
            }
            .controls {
                display: flex;
                flex-wrap: wrap;
                gap: 15px;
                margin: 20px 0;
                padding: 15px;
                background: rgba(0, 59, 0, 0.2);
                border-radius: 12px;
                border: 1px solid rgba(0, 143, 17, 0.3);
            }
            .controls input, .controls select, .controls button {
                padding: 10px 14px;
                border: none;
                border-radius: 8px;
                font-size: 1rem;
                background: var(--darker);
                color: var(--primary);
            }
            .controls input::placeholder {
                color: #777;
            }
            .controls button {
                background: var(--primary);
                color: var(--black);
                font-weight: bold;
                cursor: pointer;
                transition: all 0.3s ease;
            }
            .controls button:hover {
                transform: translateY(-2px);
                box-shadow: 0 5px 15px rgba(0, 255, 65, 0.4);
            }
            .threat-list {
                max-height: 70vh;
                overflow-y: auto;
                margin-top: 20px;
            }
            .threat {
                background: rgba(0, 59, 0, 0.2);
                border-left: 6px solid var(--info);
                padding: 16px;
                margin: 12px 0;
                border-radius: 8px;
                box-shadow: 0 3px 10px rgba(0, 0, 0, 0.3);
                transition: transform 0.2s;
            }
            .threat:hover {
                transform: translateX(5px);
            }
            .threat.critical { border-left-color: var(--critical); }
            .threat.high { border-left-color: #ff3300; }
            .threat.medium { border-left-color: var(--warning); }
            .threat.ip { border-left-width: 8px; }
            .threat.hash { background: rgba(138, 43, 226, 0.1); }
            .threat.domain { background: rgba(0, 170, 255, 0.1); }
            .threat-header {
                display: flex;
                justify-content: space-between;
                font-weight: 600;
                color: var(--primary);
            }
            .threat-value {
                font-size: 1.2rem;
                font-family: monospace;
                word-break: break-all;
            }
            .threat-type {
                font-size: 0.9rem;
                background: rgba(255, 255, 255, 0.1);
                padding: 3px 8px;
                border-radius: 5px;
            }
            .threat-source {
                color: var(--secondary);
                font-size: 0.95rem;
            }
            .threat-time {
                font-size: 0.9rem;
                color: var(--secondary);
            }
            .footer {
                text-align: center;
                margin-top: 40px;
                padding: 20px;
                color: var(--secondary);
                font-size: 0.9rem;
            }
            .empty-state {
                text-align: center;
                padding: 40px;
                color: #777;
                font-style: italic;
            }
            .pulse {
                animation: pulse 2s infinite;
            }
            @keyframes pulse {
                0% { opacity: 0.7; }
                50% { opacity: 1; }
                100% { opacity: 0.7; }
            }
            @media (max-width: 768px) {
                .controls {
                    flex-direction: column;
                }
                .controls button {
                    width: 100%;
                }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1><i class="fas fa-globe"></i> Threat Intelligence Feed</h1>
                <p class="subtitle pulse">Live simulated global cyber threat data</p>
            </header>

            <div class="controls">
                <input type="text" id="searchThreat" placeholder="🔍 Search IP, hash, or domain..." />
                <select id="filterType">
                    <option value="">All Types</option>
                    <option value="IP">IP Address</option>
                    <option value="Hash">Malware Hash</option>
                    <option value="Domain">Domain</option>
                </select>
                <select id="filterSeverity">
                    <option value="">All Severities</option>
                    <option value="Critical">Critical</option>
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                </select>
                <button onclick="refreshThreatFeed()">
                    <i class="fas fa-sync"></i> Refresh
                </button>
                <button onclick="simulateNewThreat()" style="background:var(--purple)">
                    <i class="fas fa-bolt"></i> Inject Threat
                </button>
            </div>

            <div class="threat-list" id="threatList">
                {% for threat in threats %}
                    <div class="threat threat-{{ threat.severity|lower }} threat-{{ threat.type|lower }}"
                         data-type="{{ threat.type }}" data-severity="{{ threat.severity }}" data-value="{{ threat.value }}">
                        <div class="threat-header">
                            <span class="threat-value">{{ threat.value }}</span>
                            <span class="threat-type">{{ threat.type }} - {{ threat.severity }}</span>
                        </div>
                        <div class="threat-source">Source: {{ threat.source }}</div>
                        <div class="threat-time">{{ threat.timestamp }}</div>
                    </div>
                {% endfor %}
            </div>

            <div class="footer">
                <p>CyborgSecurity | <a href="/" style="color:var(--info)">← Back to Home</a> | <a href="/dashboard" style="color:var(--primary)">Security Dashboard</a> | 
                <a href="/goat-mode" style="color:var(--primary)">GOAT Mode</a> | 
                <a href="/health" style="color:var(--primary)">Health Monitor</a> | Last updated: <span id="lastUpdate">{{ now }}</span></p>
            </div>
        </div>

        <script>
            function filterThreats() {
                const search = document.getElementById('searchThreat').value.toLowerCase();
                const type = document.getElementById('filterType').value;
                const severity = document.getElementById('filterSeverity').value;
                const threats = document.querySelectorAll('.threat');

                threats.forEach(threat => {
                    const value = threat.getAttribute('data-value').toLowerCase();
                    const threatType = threat.getAttribute('data-type');
                    const threatSeverity = threat.getAttribute('data-severity');

                    const matchesSearch = value.includes(search);
                    const matchesType = !type || threatType === type;
                    const matchesSeverity = !severity || threatSeverity === severity;

                    threat.style.display = matchesSearch && matchesType && matchesSeverity ? 'block' : 'none';
                });
            }

            function refreshThreatFeed() {
                // Simulate fetching new data
                const mockThreats = [
                    {type: "IP", value: generateIP(), source: "DDoS Botnet", severity: randomSeverity(), timestamp: new Date().toISOString().slice(0, 19)},
                    {type: "Hash", value: generateHash(), source: "Trojan Downloader", severity: "Critical", timestamp: new Date().toISOString().slice(0, 19)},
                    {type: "Domain", value: generateDomain(), source: "Phishing Kit", severity: "High", timestamp: new Date().toISOString().slice(0, 19)}
                ];
                const threatList = document.getElementById('threatList');
                let html = '';
                mockThreats.forEach(t => {
                    const level = t.severity === 'Critical' ? 'critical' : t.severity === 'High' ? 'high' : 'medium';
                    html += `
                    <div class="threat threat-${level.toLowerCase()} threat-${t.type.toLowerCase()}" 
                         data-type="${t.type}" data-severity="${t.severity}" data-value="${t.value}">
                        <div class="threat-header">
                            <span class="threat-value">${t.value}</span>
                            <span class="threat-type">${t.type} - ${t.severity}</span>
                        </div>
                        <div class="threat-source">Source: ${t.source}</div>
                        <div class="threat-time">${t.timestamp}</div>
                    </div>`;
                });
                // Add new threats to top
                threatList.innerHTML = html + threatList.innerHTML;
                filterThreats();
                document.getElementById('lastUpdate').textContent = new Date().toLocaleString();
            }

            function simulateNewThreat() {
                const types = ['IP', 'Hash', 'Domain'];
                const sources = ['APT Group 9002', 'Ransomware Gang', 'Insider Leak', 'IoT Botnet'];
                const type = types[Math.floor(Math.random() * types.length)];
                const value = type === 'IP' ? generateIP() : type === 'Hash' ? generateHash() : generateDomain();
                const source = sources[Math.floor(Math.random() * sources.length)];
                const severity = ['Critical', 'High'][Math.floor(Math.random() * 2)];
                const timestamp = new Date().toISOString().slice(0, 19);

                const threatList = document.getElementById('threatList');
                const level = severity === 'Critical' ? 'critical' : 'high';
                const newThreat = document.createElement('div');
                newThreat.className = `threat threat-${level.toLowerCase()} threat-${type.toLowerCase()} pulse`;
                newThreat.setAttribute('data-type', type);
                newThreat.setAttribute('data-severity', severity);
                newThreat.setAttribute('data-value', value);
                newThreat.innerHTML = `
                    <div class="threat-header">
                        <span class="threat-value">${value}</span>
                        <span class="threat-type">${type} - ${severity}</span>
                    </div>
                    <div class="threat-source">Source: ${source} (Injected)</div>
                    <div class="threat-time">${timestamp}</div>
                `;
                threatList.prepend(newThreat);
                // Remove pulse after animation
                setTimeout(() => newThreat.classList.remove('pulse'), 2000);
                filterThreats();
            }

            function generateIP() {
                return `192.168.${Math.floor(Math.random()*200)}.${Math.floor(Math.random()*255)}`;
            }
            function generateHash() {
                return Array(32).fill(0).map(() => Math.floor(Math.random()*16).toString(16)).join('');
            }
            function generateDomain() {
                const subs = ['login', 'secure', 'update', 'account'];
                const doms = ['cyber', 'net', 'web', 'cloud'];
                const tlds = ['com', 'biz', 'info', 'ru'];
                return `${subs[Math.floor(Math.random()*subs.length)]}-${doms[Math.floor(Math.random()*doms.length)]}.${tlds[Math.floor(Math.random()*tlds.length)]}`;
            }
            function randomSeverity() {
                const r = Math.random();
                return r < 0.3 ? 'Critical' : r < 0.7 ? 'High' : 'Medium';
            }

            // Initialize
            document.getElementById('searchThreat').addEventListener('input', filterThreats);
            document.getElementById('filterType').addEventListener('change', filterThreats);
            document.getElementById('filterSeverity').addEventListener('change', filterThreats);
            document.getElementById('lastUpdate').textContent = new Date().toLocaleString();
        </script>
    </body>
    </html>
    ''', threats=sample_threats, now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

# ========= GOAT Mode ==========
@app.route('/goat-mode')
@requires_auth
def goat_mode():
    goat_status = {
        "active": True,
        "airgapped": False,
        "secure_enclave_healthy": True,
        "neural_consent_required": True,
        "last_verified": datetime.now().isoformat(),
        "critical_commands_blocked": 7,
        "memory_integrity_checks": "Passed",
        "firmware_signature": "Valid",
        "wireless_interface": "Secured",
        "audit_log_integrity": "Immutable"
    }

    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>GOAT Mode | CyborgSecurity</title>
<link rel="icon" type="image/png" href="/favicon.png">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>
    :root {
        --primary: #00ff41; --secondary: #008f11; --dark: #003b00; --darker: #001a00;
        --black: #000000; --gray: #1a1a1a; --critical: #ff0033; --warning: #ffaa00;
        --info: #00aaff; --success: #00cc00; --goat: #00ff41;
    }
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, var(--black), var(--darker)); color: #e0e0e0; margin:0; padding:20px; line-height:1.7; }
    .container { max-width:1200px; margin:0 auto; }
    header { text-align:center; padding:30px; background:rgba(0,59,0,0.2); border-radius:15px; margin-bottom:30px; border:1px solid var(--secondary); }
    h1 { font-size:2.8rem; color: var(--goat); }
    .subtitle { font-size:1.1rem; color: var(--secondary); margin-bottom:20px; }
    .status-grid { display:grid; grid-template-columns:repeat(auto-fit, minmax(300px, 1fr)); gap:18px; margin:20px 0; }
    .status-card { background:rgba(0,59,0,0.2); border-radius:12px; padding:20px; border:1px solid rgba(0,255,65,0.2); box-shadow:0 4px 12px rgba(0,0,0,0.3); }
    .status-card h3 { color:var(--primary); margin-bottom:12px; font-size:1.2rem; }
    .status-item { display:flex; justify-content:space-between; margin-bottom:8px; font-size:0.95rem; }
    .status-label { color:var(--secondary); }
    .status-value { font-weight:600; color: var(--primary); }
    .status-value.good { color: var(--success); }
    .status-value.bad { color: var(--critical); }
    .pulse { animation:pulse 1.5s ease-in-out 1; }
    @keyframes pulse { 0% {opacity:0.3;} 50% {opacity:1;} 100% {opacity:0.3;} }

    .controls { display:flex; flex-wrap:wrap; gap:15px; margin:30px 0; padding:15px; background:rgba(0,59,0,0.2); border-radius:12px; border:1px solid rgba(0,143,17,0.3); }
    .controls button { padding:12px 18px; border:none; border-radius:8px; font-size:1rem; font-weight:bold; cursor:pointer; transition:all 0.3s ease; flex:1; min-width:160px; }
    .controls button:hover { transform:translateY(-2px); box-shadow:0 5px 15px rgba(0,255,65,0.4); }
    .btn-airgap { background: var(--critical); color:white; }
    .btn-audit { background: var(--info); color:white; }
    .btn-verify { background: var(--primary); color: var(--black); }

    .footer { text-align:center; margin-top:60px; padding:20px; border-top:1px solid var(--secondary); color:var(--secondary); font-size:0.9rem; }

    .airgap-banner { display:none; background:var(--critical); color:#fff; text-align:center; padding:10px; border-radius:8px; margin-bottom:20px; font-weight:bold; }
    .airgap-active { display:block; }

    @media (max-width:768px) { .controls { flex-direction:column; } .controls button { width:100%; } }
</style>
</head>
<body>
<div class="container">
    <div id="airgapBanner" class="airgap-banner">⚠️ AIRGAP ACTIVE: Wireless Interfaces Disabled</div>
    <header>
        <h1><i class="fas fa-crown"></i> GOAT Mode: Active</h1>
        <p class="subtitle">Zero-Trust Protection for Human-Machine Interfaces</p>
    </header>

    <div class="status-grid">
        <div class="status-card">
            <h3>System Integrity</h3>
            <div class="status-item"><span class="status-label">Secure Enclave:</span><span id="enclave" class="status-value good">Healthy</span></div>
            <div class="status-item"><span class="status-label">Memory Shield:</span><span id="memory" class="status-value good">Verified</span></div>
            <div class="status-item"><span class="status-label">Firmware:</span><span id="firmware" class="status-value good">Signed & Valid</span></div>
            <div class="status-item"><span class="status-label">Audit Log:</span><span id="audit" class="status-value good">Immutable</span></div>
        </div>
        <div class="status-card">
            <h3>Access Control</h3>
            <div class="status-item"><span class="status-label">Wireless Interface:</span><span id="wireless" class="status-value">Secured</span></div>
            <div class="status-item"><span class="status-label">Neural Consent:</span><span id="neural" class="status-value">Required</span></div>
            <div class="status-item"><span class="status-label">Last Verified:</span><span id="lastVerified">{{ status.last_verified.split('T')[1].split('.')[0] }}</span></div>
            <div class="status-item"><span class="status-label">Critical Blocks:</span><span id="criticalBlocks">{{ status.critical_commands_blocked }}</span></div>
        </div>
        <div class="status-card">
            <h3>Live Defense</h3>
            <div class="status-item"><span class="status-label">Spoofed Signals:</span><span id="spoof" class="status-value good">Blocked</span></div>
            <div class="status-item"><span class="status-label">Replay Attacks:</span><span id="replay" class="status-value good">Blocked</span></div>
            <div class="status-item"><span class="status-label">Clock Tampering:</span><span id="clock" class="status-value good">Detected & Rejected</span></div>
            <div class="status-item"><span class="status-label">AI Override:</span><span id="ai" class="status-value good">Denied</span></div>
        </div>
    </div>

    <div class="controls">
        <button id="airgapBtn" onclick="toggleAirgap()" class="btn-airgap">
            <i class="fas fa-radiation"></i> EMERGENCY AIRGAP
        </button>
        <button onclick="viewAuditLog()" class="btn-audit"><i class="fas fa-book"></i> View Audit Log</button>
        <button onclick="verifyIntegrity()" class="btn-verify"><i class="fas fa-shield-alt"></i> Verify System</button>
    </div>

    <div class="footer">
        <p>
            GOAT Mode enforces <strong>zero-trust signal validation</strong>, <strong>neural consent</strong>, and <strong>hardware-enforced isolation</strong>.<br>
            No command executes without cryptographic + biological verification.
        </p>
        <p>
            <a href="/" style="color:var(--info)">← Back to Home</a> |
            <a href="/dashboard" style="color:var(--primary)">Security Dashboard</a> | <a href="/threat-intel" style="color:var(--primary)">Threat Intel</a> |
            <a href="/health" style="color:var(--primary)">Health Monitor</a> | Last updated: <span id="lastUpdate">{{ now }}</span>
        </p>
    </div>
</div>

<script>
const status = {{ status|tojson }};

function toggleAirgap() {
    const banner = document.getElementById('airgapBanner');
    const btn = document.getElementById('airgapBtn');
    const isActive = banner.classList.contains('airgap-active');

    if(!isActive) {
        if(confirm("⚠️ ACTIVATE AIRGAP MODE? This will disable ALL wireless communication. Proceed?")) {
            fetch('/api/goat-mode/airgap', { method:'POST' })
            .then(r => r.json())
            .then(data => {
                banner.classList.add('airgap-active');
                btn.textContent = "DEACTIVATE AIRGAP";
                alert("🛡️ AIRGAP ACTIVE: You are now isolated.");
            });
        }
    } else {
        if(confirm("Deactivate Airgap? This will restore wireless communication.")) {
            fetch('/api/goat-mode/airgap/deactivate', { method:'POST' })
            .then(r => r.json())
            .then(data => {
                banner.classList.remove('airgap-active');
                btn.textContent = "EMERGENCY AIRGAP";
                alert("✅ Airgap deactivated. Wireless interfaces restored.");
            });
        }
    }
}

function viewAuditLog() {
    alert("🔐 Audit Log:\\n\\n- [14:22] Blocked firmware update (invalid signature)\\n- [14:19] Rejected neural reprogramming attempt\\n- [14:15] Detected spoofed pacemaker signal\\n- [14:10] Clock tampering alert\\n\\nAll events cryptographically signed and immutable.");
}

function verifyIntegrity() {
    const checks = [
        "Secure Enclave: OK",
        "Memory Fingerprint: MATCH",
        "Firmware Signature: VALID",
        "Neural Consent Module: READY",
        "Communication Stack: CLEAN"
    ];
    alert("✅ System Integrity Verified:\\n\\n" + checks.join("\\n"));
}

// Live simulation
setInterval(() => {
    document.getElementById('lastUpdate').textContent = new Date().toLocaleString();
    const blocksElem = document.getElementById('criticalBlocks');
    let blocks = parseInt(blocksElem.textContent);
    if(Math.random()<0.2){ blocks+=1; blocksElem.textContent=blocks; blocksElem.classList.add('pulse'); setTimeout(()=>blocksElem.classList.remove('pulse'),1500);}
}, 5000);
</script>
</body>
</html>
''', status=goat_status, now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

@app.route('/api/goat-mode/airgap', methods=['POST'])
@requires_auth
def api_goat_mode_airgap():
    logging.info("GOAT Mode: Emergency airgap activated. All wireless interfaces disabled.")
    return jsonify({"status":"airgapped","message":"All wireless communication disabled.","timestamp":datetime.now().isoformat()})

@app.route('/api/goat-mode/airgap/deactivate', methods=['POST'])
@requires_auth
def api_goat_mode_airgap_deactivate():
    logging.info("GOAT Mode: Airgap deactivated. Wireless interfaces restored.")
    return jsonify({"status":"active","message":"Wireless communication restored.","timestamp":datetime.now().isoformat()})

# ========= Health Monitor Page ==========
@app.route('/health')
@requires_auth
def health_monitor():
    # Simulated real-time health metrics
    health_data = [
        {"metric": "Heart Rate", "value": f"{random.randint(60, 100)} BPM", "status": "normal"},
        {"metric": "Neural Sync", "value": f"{random.randint(92, 99)}%", "status": "normal"},
        {"metric": "Cognitive Load", "value": f"{random.randint(25, 65)}%", "status": "normal"},
        {"metric": "Battery Level", "value": f"{random.randint(80, 99)}%", "status": "normal"},
        {"metric": "Oxygen Saturation", "value": f"{random.randint(96, 100)}%", "status": "normal"},
        {"metric": "Thermal Output", "value": f"{round(random.uniform(36.2, 37.6), 1)}°C", "status": "normal"},
        {"metric": "Signal Noise Ratio", "value": f"{round(random.uniform(1.3, 2.0), 2)} dB", "status": "normal"},
        {"metric": "Memory Integrity", "value": "OK", "status": "normal"},
        {"metric": "Firmware Version", "value": "v2.1.8-secure", "status": "normal"},
        {"metric": "Clock Drift", "value": f"+{round(random.uniform(-0.004, 0.004), 4)}s", "status": "normal"},
    ]

    # System statuses
    system_status = {
        "Secure Enclave": "Active",
        "Neural Firewall": "Enabled",
        "Auto-Remediation": "Online",
        "Wireless Encryption": "AES-256",
        "Audit Log": "Immutable",
        "Consent Module": "Ready"
    }

    # Recent health events
    recent_events = [
        {"time": "14:23", "event": "Microglial firewall triggered", "type": "security"},
        {"time": "14:21", "event": "Cognitive load peak detected", "type": "warning"},
        {"time": "14:19", "event": "Firmware self-check passed", "type": "info"},
        {"time": "14:17", "event": "Signal drift corrected", "type": "security"},
        {"time": "14:15", "event": "Bluetooth LE heartbeat confirmed", "type": "info"},
    ]

    # Health score
    health_score = random.randint(88, 100)

    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
        <title>Health Monitor | CyborgSecurity</title>
        <link rel="icon" type="image/png" href="/favicon.png">
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
                --success: #00cc00;
            }
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, var(--black), var(--darker));
                color: #e0e0e0;
                margin: 0;
                padding: 20px;
                line-height: 1.7;
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
            }
            header {
                text-align: center;
                padding: 30px;
                background: rgba(0, 59, 0, 0.2);
                border-radius: 15px;
                margin-bottom: 30px;
                border: 1px solid var(--secondary);
            }
            h1 {
                font-size: 2.8rem;
                color: var(--primary);
                margin-bottom: 10px;
                text-shadow: 0 0 15px rgba(0, 255, 65, 0.4);
            }
            .device-info {
                background: linear-gradient(145deg, var(--dark), var(--darker));
                padding: 18px;
                border-radius: 12px;
                margin: 20px 0;
                border: 1px solid rgba(0, 255, 65, 0.2);
                font-size: 1.1rem;
            }
            .health-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
                gap: 18px;
                margin: 20px 0;
            }
            .metric-card {
                background: rgba(0, 59, 0, 0.2);
                border-left: 6px solid var(--info);
                padding: 16px;
                border-radius: 8px;
                box-shadow: 0 3px 10px rgba(0, 0, 0, 0.3);
            }
            .metric-card.normal { border-left-color: var(--success); }
            .metric-card.warning { border-left-color: var(--warning); }
            .metric-card.critical { border-left-color: var(--critical); }

            .metric-header {
                display: flex;
                justify-content: space-between;
                font-weight: 600;
                color: var(--primary);
            }
            .metric-name {
                font-size: 1.1rem;
            }
            .metric-status {
                font-size: 0.9rem;
                background: rgba(255, 255, 255, 0.1);
                padding: 3px 8px;
                border-radius: 5px;
            }
            .metric-value {
                font-size: 1.4rem;
                font-weight: bold;
                margin-top: 6px;
                color: #fff;
            }
            .section-title {
                font-size: 1.5rem;
                color: var(--primary);
                margin: 30px 0 15px;
                padding-bottom: 8px;
                border-bottom: 1px solid var(--secondary);
            }
            .status-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
                gap: 14px;
                margin: 15px 0;
            }
            .status-item {
                background: rgba(0, 59, 0, 0.2);
                padding: 14px;
                border-radius: 8px;
                font-size: 1rem;
            }
            .status-label {
                font-weight: 600;
                color: var(--gray);
            }
            .status-value {
                color: var(--primary);
                font-weight: 500;
            }
            .events-list {
                margin-top: 20px;
            }
            .event {
                background: rgba(0, 59, 0, 0.2);
                padding: 12px;
                margin: 10px 0;
                border-radius: 8px;
                border-left: 4px solid var(--info);
                display: flex;
                align-items: center;
                font-size: 0.95rem;
            }
            .event.security { border-left-color: var(--primary); }
            .event.warning { border-left-color: var(--warning); }
            .event.info { border-left-color: var(--success); }
            .event-time {
                font-weight: bold;
                color: var(--secondary);
                min-width: 60px;
                margin-right: 10px;
            }
            .badge {
                font-size: 0.75rem;
                padding: 2px 6px;
                border-radius: 10px;
                margin-left: 8px;
            }
            .badge.security { background: var(--primary); color: var(--black); }
            .badge.warning { background: var(--warning); color: var(--black); }
            .badge.info { background: var(--success); color: var(--black); }
            .health-score {
                font-size: 3.5rem;
                font-weight: bold;
                color: var(--primary);
                text-align: center;
                margin: 30px 0;
                text-shadow: 0 0 10px rgba(0, 255, 65, 0.3);
            }
            footer {
                text-align: center;
                padding: 40px 0;
                border-top: 1px solid var(--secondary);
                color: var(--secondary);
                font-size: 1rem;
                margin-top: 60px;
            }
            .nav-links {
                display: flex;
                justify-content: center;
                gap: 25px;
                margin-bottom: 20px;
                font-weight: 500;
            }
            .nav-links a {
                color: var(--info);
                text-decoration: none;
            }
            .nav-links a:hover {
                text-decoration: underline;
            }
            @media (max-width: 768px) {
                .health-grid, .status-grid {
                    grid-template-columns: 1fr;
                }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1><i class="fas fa-heart-pulse"></i> Health Monitor</h1>
                <p>Real-Time Biomedical & System Diagnostics for Neural Implants</p>
            </header>

            <div class="device-info">
                <strong>Implant Type:</strong> {{ implant_type }} |
                <strong>Device ID:</strong> {{ device_id }} |
                <strong>Last Sync:</strong> <span id="current-time">{{ now }}</span>
            </div>

            <div class="health-score">
                {{ health_score }}/100
            </div>

            <h2 class="section-title"><i class="fas fa-heartbeat"></i> Vital Signs</h2>
            <div class="health-grid">
                {% for item in health_data %}
                <div class="metric-card metric-card-{{ 'critical' if 'fail' in item.value.lower() else 'warning' if 'warn' in item.value.lower() else 'normal' }}">
                    <div class="metric-header">
                        <span class="metric-name">{{ item.metric }}</span>
                        <span class="metric-status">{{ 'OK' if 'fail' not in item.value.lower() else 'ERROR' }}</span>
                    </div>
                    <div class="metric-value">{{ item.value }}</div>
                </div>
                {% endfor %}
            </div>

            <h2 class="section-title"><i class="fas fa-microchip"></i> System Status</h2>
            <div class="status-grid">
                {% for label, value in system_status.items() %}
                <div class="status-item">
                    <span class="status-label">{{ label }}</span>
                    <span class="status-value">{{ value }}</span>
                </div>
                {% endfor %}
            </div>

            <h2 class="section-title"><i class="fas fa-list"></i> Recent Neural Events</h2>
            <div class="events-list">
                {% for event in recent_events %}
                <div class="event event-{{ event.type }}">
                    <span class="event-time">{{ event.time }}</span>
                    <span>{{ event.event }}
                        <span class="badge {{ event.type }}">{{ event.type | title }}</span>
                    </span>
                </div>
                {% endfor %}
            </div>

            <footer>
                <p>CyborgSecurity | <a href="/" style="color:var(--info)">← Back to Home</a> | 
                <a href="/dashboard" style="color:var(--primary)">Security Dashboard</a> | 
                <a href="/threat-intel" style="color:var(--primary)">Threat Intel</a> | 
                <a href="/goat-mode" style="color:var(--primary)">GOAT Mode</a> | 
                Last updated: <span id="lastUpdate">{{ now }}</span></p>
            </footer>
        </div>

        <script>
            // Auto-update time
            function updateTime() {
                const now = new Date();
                document.getElementById('current-time').textContent = now.toLocaleString();
                document.getElementById('lastUpdate').textContent = now.toLocaleString();
            }
            setInterval(updateTime, 1000);
            updateTime();
        </script>
    </body>
    </html>
    ''',
    health_data=health_data,
    system_status=system_status,
    recent_events=recent_events,
    health_score=health_score,
    implant_type=monitor_instance.interface.implant_type,
    device_id=monitor_instance.interface.device_id,
    now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

# ========== Pricing Page ==========
@app.route('/pricing')
def pricing():
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
        <title>Pricing | CyborgSecurity</title>
        <link rel="icon" type="image/png" href="/favicon.png">
        <link rel="stylesheet" 
        href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            :root {
                --primary: #00ff41;
                --secondary: #008f11;
                --dark: #003b00;
                --darker: #001a00;
                --black: #000000;
                --light: #e0e0e0;
                --gray: #1a1a1a;
                --card-bg: rgba(0, 59, 0, 0.2);
                --support: #00c244; /* CashApp green */
            }
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, var(--black), var(--darker));
                color: var(--light);
                margin: 0;
                padding: 20px;
                line-height: 1.7;
            }
            .container {
                max-width: 1000px;
                margin: 0 auto;
                padding: 20px;
            }
            nav {
                background: rgba(0, 59, 0, 0.3);
                padding: 12px 20px;
                border-radius: 10px;
                margin-bottom: 30px;
                display: flex;
                justify-content: center;
                gap: 30px;
                font-weight: 600;
                box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
                border: 1px solid rgba(0, 255, 65, 0.2);
            }
            nav a {
                color: var(--light);
                text-decoration: none;
                transition: color 0.3s;
            }
            nav a:hover {
                color: var(--primary);
            }
            nav a.current {
                color: var(--primary);
                text-decoration: underline;
            }
            header {
                text-align: center;
                padding: 40px 20px;
                background: rgba(0, 59, 0, 0.2);
                border-radius: 15px;
                margin-bottom: 30px;
                border: 1px solid var(--secondary);
            }
            h1 {
                font-size: 2.8rem;
                color: var(--primary);
                margin-bottom: 10px;
                text-shadow: 0 0 15px rgba(0, 255, 65, 0.4);
            }
            .tagline {
                font-size: 1.2rem;
                color: var(--secondary);
                margin-bottom: 20px;
            }
            .pricing-card, .support-card {
                background: var(--card-bg);
                border-radius: 12px;
                padding: 30px;
                margin: 20px auto;
                max-width: 600px;
                text-align: center;
                border: 1px solid rgba(0, 255, 65, 0.2);
                box-shadow: 0 5px 15px rgba(0, 0, 0, 0.3);
            }
            .pricing-card h2, .support-card h2 {
                color: var(--primary);
                margin-top: 0;
            }
            .price {
                font-size: 3rem;
                font-weight: bold;
                color: var(--primary);
                margin: 15px 0;
            }
            .features {
                margin: 20px 0;
                text-align: left;
            }
            .features li {
                margin: 10px 0;
                color: #ccc;
            }
            .cta-button, .support-button {
                display: inline-block;
                margin-top: 20px;
                padding: 12px 25px;
                text-decoration: none;
                border-radius: 8px;
                font-weight: bold;
                transition: all 0.3s ease;
            }
            .cta-button {
                background: var(--primary);
                color: var(--black);
            }
            .cta-button:hover {
                transform: translateY(-3px);
                box-shadow: 0 5px 15px rgba(0, 255, 65, 0.4);
            }
            .support-button {
                background: var(--support);
                color: var(--black);
            }
            .support-button:hover {
                transform: translateY(-3px);
                box-shadow: 0 5px 15px rgba(0, 194, 68, 0.4);
            }
            .note {
                margin-top: 30px;
                padding: 15px;
                background: rgba(255, 255, 255, 0.05);
                border-radius: 8px;
                font-style: italic;
                color: var(--secondary);
                text-align: center;
            }
            .footer {
                text-align: center;
                margin-top: 50px;
                padding: 20px;
                color: var(--secondary);
                font-size: 0.9rem;
            }
        </style>
    </head>
    <body>
    <!-- ========== Navigation Bar ========== -->
    <nav>
        <a href="/" style="color: var(--primary); text-decoration: none;">CyborgSecurity</a>
        <a href="/guide" style="color: var(--primary); text-decoration: none;">Setup Guide</a>
        <a href="/resources" style="color: var(--primary); text-decoration: none;">Resources</a>
        <a href="/pricing" style="color: var(--primary); text-decoration: none;">Pricing</a>
        <a href="/about" style="color: var(--primary); text-decoration: none;">About</a>
        <a href="/contact" style="color: var(--primary); text-decoration: none;">Contact</a>
    </nav>

        <div class="container">
            <header>
                <h1><i class="fas fa-tags"></i> Transparent Pricing</h1>
                <p class="tagline">An application built for all of mankind (and cyborgkind).</p>
            </header>

            <!-- Pricing Card -->
            <div class="pricing-card">
                <h2>Open Source & Currently Free</h2>
                <div class="price">$0.00</div>
                <p>No hidden fees. No subscriptions. No paywalls.</p>

                <ul class="features">
                    <li><i class="fas fa-check" style="color:var(--primary);"></i> 100% Free to Use</li>
                    <li><i class="fas fa-check" style="color:var(--primary);"></i> Full Source Code Available</li>
                    <li><i class="fas fa-check" style="color:var(--primary);"></i> No Feature Locks</li>
                    <li><i class="fas fa-check" style="color:var(--primary);"></i> Commercial & Personal Use</li>
                    <li><i class="fas fa-check" style="color:var(--primary);"></i> Community Support</li>
                </ul>

                <a href="https://github.com/youngsassanid/cyborgsecurity" class="cta-button" target="_blank">
                    <i class="fab fa-github"></i> Download Now
                </a>
            </div>

            <!-- Support Card (separate section) -->
            <div class="support-card">
                <h2><i class="fas fa-hand-holding-heart"></i> Support the Project</h2>
                <p>If you’d like to help keep CyborgSecurity alive and growing, you can contribute directly:</p>
                <a href="https://cash.app/$PersianEmpireGoods/" class="cta-button" target="_blank">
                    <i class="fas fa-dollar-sign"></i> Support via CashApp
                </a>
            </div>

            <div class="note">
                <p>
                    <strong>Note:</strong> CyborgSecurity is a simulation prototype developed for educational and research purposes. 
                    While it models real-world security features, it is <strong>not intended for production use</strong>. 
                </p>
            </div>
        </div>

        <div class="footer">
            <p>CyborgSecurity | Advanced Cybersecurity for the Future of Human-Machine Integration</p>
            <p>This is a simulation prototype. Not for production use.</p>
        </div>
    </body>
    </html>
    ''')


# ========== Resources Page ==========
@app.route('/resources')
def resources():
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8" />
        <title>Resources | CyborgSecurity</title>
        <link rel="icon" type="image/png" href="/favicon.png">
        <link rel="stylesheet" 
        href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            :root {
                --primary: #00ff41;
                --secondary: #008f11;
                --dark: #003b00;
                --darker: #001a00;
                --black: #000000;
                --light: #e0e0e0;
                --info: #00aaff;
            }
            body {
                font-family: 'Segoe UI', sans-serif;
                background: linear-gradient(135deg, var(--black), var(--darker));
                color: var(--light);
                margin: 0;
                padding: 20px;
            }
            .container {
                max-width: 900px;
                margin: 0 auto;
                padding: 20px;
            }
            nav {
                background: rgba(0, 59, 0, 0.3);
                padding: 12px 20px;
                border-radius: 10px;
                margin-bottom: 30px;
                display: flex;
                justify-content: center;
                gap: 30px;
                font-weight: 600;
                border: 1px solid rgba(0, 255, 65, 0.2);
            }
            nav a {
                color: var(--light);
                text-decoration: none;
                transition: color 0.3s;
            }
            nav a:hover {
                color: var(--primary);
            }
            nav a.current {
                color: var(--primary);
                text-decoration: underline;
            }
            header {
                text-align: center;
                padding: 40px 20px;
                background: rgba(0, 59, 0, 0.2);
                border-radius: 15px;
                margin-bottom: 30px;
                border: 1px solid var(--secondary);
            }
            h1 {
                font-size: 2.8rem;
                color: var(--primary);
                margin-bottom: 10px;
                text-shadow: 0 0 15px rgba(0, 255, 65, 0.4);
            }
            .tagline {
                font-size: 1.2rem;
                color: var(--secondary);
                margin-bottom: 20px;
            }
            .section {
                background: rgba(0, 59, 0, 0.2);
                padding: 25px;
                border-radius: 12px;
                margin: 20px 0;
                border: 1px solid rgba(0, 255, 65, 0.1);
                box-shadow: 0 3px 10px rgba(0, 0, 0, 0.2);
            }
            h2 {
                color: var(--primary);
                margin-top: 0;
            }
            ul {
                padding-left: 20px;
            }
            li {
                margin: 10px 0;
                color: #ccc;
            }
            .external-link {
                color: var(--info);
                text-decoration: none;
            }
            .external-link:hover {
                text-decoration: underline;
            }
            .footer {
                text-align: center;
                margin-top: 50px;
                padding: 20px;
                color: var(--secondary);
                font-size: 0.9rem;
            }
        </style>
    </head>
    <body>
    <!-- ========== Navigation Bar ========== -->
    <nav style="
        background: rgba(0, 59, 0, 0.3);
        padding: 12px 20px;
        border-radius: 10px;
        margin-bottom: 20px;
        display: flex;
        justify-content: center;
        gap: 30px;
        font-weight: 600;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
        border: 1px solid rgba(0, 255, 65, 0.2);
    ">
        <a href="/" style="color: var(--primary); text-decoration: none;">CyborgSecurity</a>
        <a href="/guide" style="color: var(--primary); text-decoration: none;">Setup Guide</a>
        <a href="/resources" style="color: var(--primary); text-decoration: none;">Resources</a>
        <a href="/pricing" style="color: var(--primary); text-decoration: none;">Pricing</a>
        <a href="/about" style="color: var(--primary); text-decoration: none;">About</a>
        <a href="/contact" style="color: var(--primary); text-decoration: none;">Contact</a>
    </nav>

        
                <div class="container">
            <header>
                <h1><i class="fas fa-brain"></i> The Future of Cyber-Medical Security</h1>
                <p class="tagline">Understanding neural implants, medical devices, and the need for advanced protection.</p>
            </header>

<div class="section">
    <h2>What Are Brain-Computer Interfaces?</h2>
    <p>
        <strong>Brain-Computer Interfaces (BCIs)</strong> are devices that connect the human brain directly to computers, enabling communication between neural activity and digital systems. 
        They have the potential to treat neurological conditions (like Parkinson’s, epilepsy, and spinal cord injuries) and enhance human capabilities.
    </p>
    <p>
        BCIs typically use tiny electrodes to read and stimulate neural activity, transmitting data wirelessly. 
        While revolutionary, this creates new cybersecurity challenges: if compromised, a hacker could potentially manipulate neural signals, steal sensitive brain data, or disrupt device functionality.
    </p>
    <p>
        <strong>Learn more about BCIs:</strong>
        <ul>
            <li><a href="https://www.synchron.com/" class="external-link" target="_blank">Synchron – Minimally Invasive BCIs</a></li>
            <li><a href="https://www.brain-gate.org/" class="external-link" target="_blank">BrainGate – Clinical BCI Research</a></li>
            <li><a href="https://www.blackrockneurotech.com/" class="external-link" target="_blank">Blackrock Neurotech – Neural Implant Devices</a></li>
        </ul>
    </p>
</div>

<div class="section">
    <h2>Major BCI & Medical Implant Platforms</h2>
    <p>
        There are several companies pioneering brain-computer interfaces and medical implants, each with unique approaches and devices. 
        CyborgSecurity aims to protect the wider ecosystem, regardless of manufacturer.
    </p>
    <ul>
        <li><strong>Synchron</strong> – Minimally invasive “stentrode” BCIs implanted via blood vessels, reducing surgical risk.</li>
        <li><strong>Paradromics</strong> – High-bandwidth neural implants focused on restoring communication for patients with paralysis.</li>
        <li><strong>Blackrock Neurotech</strong> – Clinical-grade devices with decades of research in neuroprosthetics and BCIs.</li>
        <li><strong>Neuralink</strong> – Ultra-high bandwidth BCIs designed to treat neurological conditions and eventually enhance human-AI interaction.</li>
        <li><strong>Precision Neuroscience</strong> – Founded by a former Neuralink co-founder, focusing on scalable neural implants.</li>
        <li><strong>BrainGate</strong> – Pioneering research group developing implanted BCIs for restoring motor and communication functions.</li>
    </ul>
    <p>
        By supporting all of these platforms, CyborgSecurity remains independent, neutral, and focused on delivering reliable cybersecurity for every user in the BCI and medical implant ecosystem.
    </p>
</div>


            <div class="section">
                <h2>Cyber-Medical Implants: Pacemakers, Insulin Pumps & More</h2>
                <p>
                    Devices like <strong>pacemakers</strong>, <strong>insulin pumps</strong>, and <strong>neurostimulators</strong> are already in widespread use and 
                    rely on wireless communication for monitoring and updates. 
                    Unfortunately, many of these devices have known security vulnerabilities.
                </p>
                <p>
                    In 2017, the FDA recalled 500,000 pacemakers due to cybersecurity risks that could allow unauthorized access to alter pacing or deplete the battery. 
                    As these devices become more connected, they become targets for cyberattacks with life-threatening consequences.
                </p>
                <p>
                    <strong>Learn more:</strong>
                    <ul>
                        <li><a href="https://www.fda.gov/medical-devices/implants-and-prosthetics/cybersecurity-medical-devices" class="external-link" target="_blank">FDA on Medical Device Cybersecurity</a></li>
                        <li><a href="https://www.ncbi.nlm.nih.gov/pmc/articles/PMC7554872/" class="external-link" target="_blank">Security of Implantable Medical Devices (NCBI)</a></li>
                    </ul>
                </p>
            </div>

            <div class="section">
                <h2>How CyborgSecurity Simulates Real Protection</h2>
                <p>
                    While CyborgSecurity is a simulation, it models real-world threats to neural and medical implants:
                </p>
                <ul>
                    <li><strong>Spoofed Signal Detection:</strong> Simulates protection against fake neural commands (e.g., a hacker trying to trigger a false signal).</li>
                    <li><strong>Packet Integrity Verification:</strong> Uses SHA-256 to detect tampered data — critical for ensuring commands sent to a pacemaker are authentic.</li>
                    <li><strong>Replay Attack Prevention:</strong> Timestamps stop attackers from re-sending old commands (e.g., repeating a "disable" signal).</li>
                    <li><strong>Memory Integrity Checks:</strong> Monitors for unauthorized changes to device firmware or configuration.</li>
                </ul>
                <p>
                    This app is designed to <strong>educate, simulate, and inspire</strong> future developers and security researchers on the importance of securing human-machine interfaces.
                </p>
            </div>

            <!-- ✅ Moved inside .container -->
            <div class="section">
                <h2>Kazemi Cancer Research Assistant</h2>
                <p>
                    The <strong>Kazemi Cancer Research Assistant</strong> is a web-based oncology platform built by Sām Kazemi in 2025. 
                    It integrates clinical trial matching, drug interaction checks, and survival analysis tools with interactive dashboards to make cancer research more accessible and data-driven.
                </p>
                <p>
                    Kazemi also seeks to intersect this project with <strong>CyborgSecurity</strong>, creating an ecosystem of cyber-medical technologies that blend medicine, computer science, and cybersecurity knowledge. 
                    The goal is to empower researchers, educators, and patients with tools that support both health innovation and digital safety.
                </p>
                <p>
                    <strong>Learn more:</strong>
                    <ul>
                        <li><a href="https://github.com/youngsassanid/kazemi-cancer-research-assistant/tree/main" class="external-link" target="_blank">GitHub Repository (Demo)</a></li>
                        <li><a href="https://www.ncbi.nlm.nih.gov/pmc/articles/PMC7392189/" class="external-link" target="_blank">Survival Analysis in Oncology (NCBI)</a></li>
                    </ul>
                </p>
            </div>
        </div> <!-- closes .container -->

        <div class="footer">
            <p>CyborgSecurity | Advanced Cybersecurity for the Future of Human-Machine Integration</p>
            <p>This is a simulartion prototype. Not for production use.</p>
        </div>
    </body>
    </html>
    ''')

# ========== User Guide Page ==========
@app.route('/guide')
def guide():
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
        <title>Setup Guide | CyborgSecurity</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <link rel="icon" type="image/png" href="/favicon.png">
        <style>
            :root {
                --primary: #00ff41;
                --secondary: #008f11;
                --dark: #003b00;
                --darker: #001a00;
                --black: #000000;
                --light: #e0e0e0;
                --gray: #1a1a1a;
            }
            body {
                font-family: 'Segoe UI', sans-serif;
                background: linear-gradient(135deg, var(--black), var(--darker));
                color: var(--light);
                margin: 0;
                padding: 20px;
                line-height: 1.7;
            }
            .container {
                max-width: 900px;
                margin: 0 auto;
                padding: 20px;
            }
            nav {
                background: rgba(0, 59, 0, 0.3);
                padding: 12px 20px;
                border-radius: 10px;
                margin-bottom: 30px;
                display: flex;
                justify-content: center;
                gap: 30px;
                font-weight: 600;
                border: 1px solid rgba(0, 255, 65, 0.2);
            }
            nav a {
                color: var(--light);
                text-decoration: none;
                transition: color 0.3s;
            }
            nav a:hover {
                color: var(--primary);
            }
            nav a.current {
                color: var(--primary);
                text-decoration: underline;
            }
            header {
                text-align: center;
                padding: 40px 20px;
                background: rgba(0, 59, 0, 0.2);
                border-radius: 15px;
                margin-bottom: 30px;
                border: 1px solid var(--secondary);
            }
            h1 {
                font-size: 2.8rem;
                color: var(--primary);
                margin-bottom: 10px;
                text-shadow: 0 0 15px rgba(0, 255, 65, 0.4);
            }
            .tagline {
                font-size: 1.2rem;
                color: var(--secondary);
                margin-bottom: 20px;
            }
            .section {
                background: rgba(0, 59, 0, 0.2);
                padding: 25px;
                border-radius: 12px;
                margin: 20px 0;
                border: 1px solid rgba(0, 255, 65, 0.1);
                box-shadow: 0 3px 10px rgba(0, 0, 0, 0.2);
            }
            h2, h3 {
                color: var(--primary);
            }
            .usage {
                background: rgba(0, 0, 0, 0.3);
                padding: 15px;
                border-radius: 8px;
                font-family: 'Courier New', monospace;
                overflow-x: auto;
            }
            code {
                color: var(--primary);
                font-weight: bold;
            }
            ul {
                padding-left: 20px;
            }
            li {
                margin: 10px 0;
                color: #ccc;
            }
            .footer {
                text-align: center;
                margin-top: 50px;
                padding: 20px;
                color: var(--secondary);
                font-size: 0.9rem;
            }
        </style>
    </head>
    <body>
    <!-- ========== Navigation Bar ========== -->
    <nav style="
        background: rgba(0, 59, 0, 0.3);
        padding: 12px 20px;
        border-radius: 10px;
        margin-bottom: 20px;
        display: flex;
        justify-content: center;
        gap: 30px;
        font-weight: 600;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
        border: 1px solid rgba(0, 255, 65, 0.2);
    ">
        <a href="/" style="color: var(--primary); text-decoration: none;">CyborgSecurity</a>
        <a href="/guide" style="color: var(--primary); text-decoration: none;">Setup Guide</a>
        <a href="/resources" style="color: var(--primary); text-decoration: none;">Resources</a>
        <a href="/pricing" style="color: var(--primary); text-decoration: none;">Pricing</a>
        <a href="/about" style="color: var(--primary); text-decoration: none;">About</a>
        <a href="/contact" style="color: var(--primary); text-decoration: none;">Contact</a>
    </nav>

        <div class="container">
            <header>
                <h1><i class="fas fa-book-open"></i> Getting Started Guide</h1>
                <p class="tagline">Your complete walkthrough for installing, running, and understanding CyborgSecurity.</p>
            </header>

            <section class="section">
                <h2>How to Run</h2>
                <h3>1. Clone the Repository</h3>
                <div class="usage">
                    <code>git clone https://github.com/youngsassanid/cyborgsecurity.git<br>cd cyborgsecurity</code>
                </div>
                <h3>2. Set Up the Virtual Environment</h3>
                <div class="usage">
                    <code>python -m venv .venv<br>source .venv/bin/activate       # On Windows use: .venv\\Scripts\\activate<br>pip install -r requirements.txt</code>
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
                <p>The system currently simulates a NeuroLink V3 implant, but you can expand the <code>CyborgInterface</code> class to model:</p>
                <ul>
                    <li>Electronic prosthetic limbs</li>
                    <li>Implantable cardioverter-defibrillators (ICDs)</li>
                    <li>Smart cochlear implants</li>
                    <li>Retinal chip implants</li>
                    <li>Brain-computer interfaces (BCIs)</li>
                </ul>
            </section>
        </div>

        <div class="footer">
            <p>CyborgSecurity | Advanced Cybersecurity for the Future of Human-Machine Integration</p>
            <p>This is a simulation prototype. Not for production use.</p>
        </div>
    </body>
    </html>
    ''')

# ========== About Page ==========
@app.route('/about')
def about():
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
        <title>About | CyborgSecurity</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <link rel="icon" type="image/png" href="/favicon.png">
        <style>
            :root {
                --primary: #00ff41;
                --secondary: #008f11;
                --dark: #003b00;
                --darker: #001a00;
                --black: #000000;
                --light: #e0e0e0;
                --gray: #1a1a1a;
            }
            body {
                font-family: 'Segoe UI', sans-serif;
                background: linear-gradient(135deg, var(--black), var(--darker));
                color: var(--light);
                margin: 0;
                padding: 20px;
                line-height: 1.7;
            }
            .container {
                max-width: 900px;
                margin: 0 auto;
                padding: 20px;
            }
            nav {
                background: rgba(0, 59, 0, 0.3);
                padding: 12px 20px;
                border-radius: 10px;
                margin-bottom: 30px;
                display: flex;
                justify-content: center;
                gap: 30px;
                font-weight: 600;
                border: 1px solid rgba(0, 255, 65, 0.2);
            }
            nav a {
                color: var(--light);
                text-decoration: none;
                transition: color 0.3s;
            }
            nav a:hover {
                color: var(--primary);
            }
            nav a.current {
                color: var(--primary);
                text-decoration: underline;
            }
            header {
                text-align: center;
                padding: 40px 20px;
                background: rgba(0, 59, 0, 0.2);
                border-radius: 15px;
                margin-bottom: 30px;
                border: 1px solid var(--secondary);
            }
            h1 {
                font-size: 2.8rem;
                color: var(--primary);
                margin-bottom: 10px;
                text-shadow: 0 0 15px rgba(0, 255, 65, 0.4);
            }
            .tagline {
                font-size: 1.2rem;
                color: var(--secondary);
                margin-bottom: 20px;
            }
            .section {
                background: rgba(0, 59, 0, 0.2);
                padding: 30px;
                border-radius: 12px;
                margin: 20px 0;
                border: 1px solid rgba(0, 255, 65, 0.1);
                box-shadow: 0 3px 10px rgba(0, 0, 0, 0.2);
            }
            h2 {
                color: var(--primary);
                margin-top: 0;
            }
            .highlight {
                background: rgba(0, 255, 65, 0.2);
                color: var(--primary);
                padding: 2px 6px;
                border-radius: 4px;
                font-weight: 600;
            }
            .social-buttons {
                display: flex;
                flex-wrap: wrap;
                gap: 15px;
                justify-content: center;
                margin: 30px 0;
            }
            .social-button {
                display: inline-flex;
                align-items: center;
                gap: 10px;
                padding: 14px 24px;
                background: rgba(0, 59, 0, 0.4);
                color: var(--primary);
                text-decoration: none;
                border-radius: 8px;
                font-weight: 600;
                transition: all 0.3s ease;
                min-width: 220px;
                text-align: center;
            }
            .social-button:hover {
                background: rgba(0, 255, 65, 0.2);
                transform: translateY(-3px);
                box-shadow: 0 5px 15px rgba(0, 255, 65, 0.3);
            }
            .footer {
                text-align: center;
                margin-top: 50px;
                padding: 20px;
                color: var(--secondary);
                font-size: 0.9rem;
            }
        </style>
    </head>
    <body>
    <!-- ========== Navigation Bar ========== -->
    <nav style="
        background: rgba(0, 59, 0, 0.3);
        padding: 12px 20px;
        border-radius: 10px;
        margin-bottom: 20px;
        display: flex;
        justify-content: center;
        gap: 30px;
        font-weight: 600;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
        border: 1px solid rgba(0, 255, 65, 0.2);
    ">
        <a href="/" style="color: var(--primary); text-decoration: none;">CyborgSecurity</a>
        <a href="/guide" style="color: var(--primary); text-decoration: none;">Setup Guide</a>
        <a href="/resources" style="color: var(--primary); text-decoration: none;">Resources</a>
        <a href="/pricing" style="color: var(--primary); text-decoration: none;">Pricing</a>
        <a href="/about" style="color: var(--primary); text-decoration: none;">About</a>
        <a href="/contact" style="color: var(--primary); text-decoration: none;">Contact</a>
    </nav>

        <div class="container">
            <header>
                <h1><i class="fas fa-user"></i> About CyborgSecurity</h1>
                <p class="tagline">The story behind the code, the mission, and the GOAT.</p>
            </header>

            <!-- Section 1: The Developer -->
            <section class="section">
                <h2>The Developer</h2>
                <div class="author-bio">
            <img src="/sam.jpeg" alt="Sām Kazemi" 
             style="width:350px; height:auto; float:left; margin:0 20px 20px 0; border-radius:12px; border:2px solid var(--primary); box-shadow:0 0 15px rgba(0,255,65,0.5);">
            <p><strong>Sām Kazemi</strong> is a dedicated <strong>Computer Science student at San Francisco State University</strong> with a minor in Persian Studies, born and 
            raised in the East Bay Area. Born to Iranian immigrant parents, he was raised with strong values of hard work, resilience, and community commitment.</p>
            <p>Having witnessed the impact of gang violence firsthand, Sām serves as a <strong>mentor and community figure</strong> promoting positive change, discipline, 
            and empowerment. As a <strong>natural bodybuilder and martial artist</strong>, he exemplifies physical and mental strength while encouraging others to follow constructive paths.</p>
            <p>Sām's passion for <strong>cybersecurity</strong> drives his technical work, including developing <strong>CyborgSecurity</strong>, a Python-based tool designed to protect 
            advanced technologies like neural implants. Through this project, he aims to create solutions that safeguard privacy and security in today's connected world.</p>
            <p>Proud of his Iranian heritage, Sām is committed to advancing his community through <strong>education, cultural awareness, and advocacy</strong>, blending his technical 
            expertise and personal discipline to inspire success grounded in identity and values.</p>
            </div>
                        <div class="social-buttons">
                <a href="https://www.linkedin.com/in/mojtaba-kazemi-529264317/" class="social-button" target="_blank">
                    <i class="fab fa-linkedin"></i> View LinkedIn Profile
                </a>
                <a href="https://github.com/youngsassanid/cyborgsecurity" class="social-button" target="_blank">
                    <i class="fab fa-github"></i> View GitHub Repository
                </a>
            </div>
            </section>

            <!-- Section 2: Real-World Inspiration -->
            <section class="section">
                <h2>Inspired by Real-World Threats</h2>
                <p>CyborgSecurity was developed in response to <strong>real, life-threatening cybersecurity events</strong>, such as the <strong>FDA’s 2017 recall of 500,000 pacemakers</strong> 
                due to vulnerabilities that could allow hackers to disable the devices or deliver fatal shocks.</p>
                <p>As humans become increasingly integrated with technology—from neural implants to insulin pumps and prosthetics—securing these interfaces is not optional. It 
                is a <strong>life-or-death necessity</strong>.</p>
                <p>Through CyborgSecurity, Sām Kazemi explores this future from a technical and ethical perspective, building tools designed to safeguard the privacy and security of 
                human-machine integration.</p>
            </section>


            <!-- Section 3: Origin & The GOAT Ethos -->
            <section class="section">
                <h2>The Origin: From Rejection to the GOAT</h2>
            <img src="/the_goat.jpg" alt="The GOAT" 
             style="width:350px; height:auto; float:left; margin:0 20px 20px 0; border-radius:12px; border:2px solid var(--primary); box-shadow:0 0 15px rgba(0,255,65,0.5);">
                <p>CyborgSecurity began as a dream — literally. But its true origin lies in <strong>rage, rejection, and relentless hunger for success</strong>.</p>
                <p>Sām Kazemi began his education in computer science before a time of massive upheaval in tech. After the COVID-19 pandemic, the industry was hit by 
                mass layoffs, and the rise of AI tools like ChatGPT disrupted traditional hiring pipelines. The once-stable path of a computer science career suddenly 
                felt like a battlefield.</p>
                <p>Despite applying to dozens of internships and spending countless hours refining his applications, Sām was met with silence or rejection. As a martial artist, 
                bodybuilder, and fighter who grew up in poverty, this situation triggered a <strong>fight-or-flight response</strong>. Every morning, he reminded himself: 
                <em>"I will get an internship and a bright CS career — or die trying."</em></p>
                <p>In that fire, he came to a realization: it wasn’t enough to be <em>good</em> at computer science. He had to be the <strong>GOAT</strong> — the Greatest of All Time.</p>
                <p>The logo of CyborgSecurity isn’t random. It features a <strong>goat</strong> because <strong>GOAT stands for Greatest of All Time</strong>. Throughout his journey, 
                Sām saw that many in the field were soft and uninspired — but he approached tech like a fighter. <strong>Disciplined, brutal, and relentless</strong>, he vowed 
                to <strong>crush</strong> the competition in code the same way he would in a boxing ring.</p>
                <p><strong>This is the GOAT Ethos.</strong> And CyborgSecurity is his war cry.</p>
            </section>

        </div>

        <div class="footer">
            <p>CyborgSecurity | Advanced Cybersecurity for the Future of Human-Machine Integration</p>
            <p>This is a simulation prototype. Not for production use.</p>
        </div>
    </body>
    </html>
    ''')

# ========== Contact Page ==========
@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        # Get form data
        name = request.form.get('name', 'Anonymous')
        email = request.form.get('email', 'No email provided')
        message = request.form.get('message', '').strip()

        if not message:
            return '''
            <script>alert("Message cannot be empty."); window.history.back();</script>
            '''

        # Format email content
        subject = f"Contact Form Submission: {name}"
        body = f"""
        Name: {name}
        Email: {email}
        Message:
        {message}
        """
        msg = f"Subject: {subject}\n\n{body}"

        # Try to send email
        try:
            server = smtplib.SMTP('smtp.gmail.com', 587)  # Change if not using Gmail
            server.starttls()
            server.login('your_email@gmail.com', 'your_app_password')  # Use environment variables!
            server.sendmail('your_email@gmail.com', 'mkazemi@sfsu.edu', msg)
            server.quit()
            logging.info(f"Contact form submitted by {name} ({email})")
            return '''
            <script>alert("Message sent successfully! Thank you."); window.location.href="/contact";</script>
            '''
        except Exception as e:
            logging.error(f"Failed to send contact email: {e}")
            return '''
            <script>alert("Failed to send message. Please try again later."); window.location.href="/contact";</script>
            '''

    # GET request — show the form
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8" />
        <title>Contact | CyborgSecurity</title>
        <link rel="icon" type="image/png" href="/favicon.png">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            :root {
                --primary: #00ff41;
                --secondary: #008f11;
                --dark: #003b00;
                --darker: #001a00;
                --black: #000000;
                --light: #e0e0e0; /* Match your site's grayish-white */
                --info: #00aaff;
            }
            body {
                font-family: 'Segoe UI', sans-serif;
                background: linear-gradient(135deg, var(--black), var(--darker));
                color: var(--light); /* Fixed: now uses grayish-white */
                margin: 0;
                padding: 20px;
            }
            .container {
                max-width: 800px;
                margin: 0 auto;
                padding: 20px;
            }
            nav {
                background: rgba(0, 59, 0, 0.3);
                padding: 12px 20px;
                border-radius: 10px;
                margin-bottom: 30px;
                display: flex;
                justify-content: center;
                gap: 30px;
                font-weight: 600;
                border: 1px solid rgba(0, 255, 65, 0.2);
            }
            nav a {
                color: var(--light);
                text-decoration: none;
                transition: color 0.3s;
            }
            nav a:hover {
                color: var(--primary);
            }
            nav a.current {
                color: var(--primary);
                text-decoration: underline;
            }
            .card {
                background: rgba(0, 59, 0, 0.2);
                padding: 30px;
                border-radius: 12px;
                margin: 20px 0;
                border: 1px solid rgba(0, 255, 65, 0.1);
                box-shadow: 0 3px 10px rgba(0, 0, 0, 0.2);
            }
            h1, h2 {
                color: var(--primary);
            }
            label {
                display: block;
                margin: 15px 0 5px;
                color: var(--light);
            }
            input[type="text"], 
            input[type="email"], 
            textarea {
                width: 100%;
                padding: 10px;
                background: var(--darker);
                border: 1px solid rgba(0, 255, 65, 0.2);
                border-radius: 6px;
                color: var(--light);
                font-family: 'Segoe UI', sans-serif;
            }
            textarea {
                min-height: 150px;
                resize: vertical;
            }
            .submit-btn {
                margin-top: 20px;
                padding: 12px 25px;
                background: var(--primary);
                color: var(--black);
                border: none;
                border-radius: 8px;
                font-weight: bold;
                cursor: pointer;
                transition: all 0.3s ease;
            }
            .submit-btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 5px 15px rgba(0, 255, 65, 0.4);
            }
            .social-links {
                margin: 30px 0;
                display: flex;
                justify-content: center;
                gap: 20px;
            }
            .social-links a {
                font-size: 1.5rem;
                color: var(--primary);
                transition: transform 0.3s;
            }
            .social-links a:hover {
                transform: scale(1.3);
            }
            .footer {
                text-align: center;
                margin-top: 50px;
                padding: 20px;
                color: var(--secondary);
                font-size: 0.9rem;
            }
        </style>
    </head>
    <body>
    <!-- ========== Navigation Bar ========== -->
    <nav style="
        background: rgba(0, 59, 0, 0.3);
        padding: 12px 20px;
        border-radius: 10px;
        margin-bottom: 20px;
        display: flex;
        justify-content: center;
        gap: 30px;
        font-weight: 600;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
        border: 1px solid rgba(0, 255, 65, 0.2);
    ">
        <a href="/" style="color: var(--primary); text-decoration: none;">CyborgSecurity</a>
        <a href="/guide" style="color: var(--primary); text-decoration: none;">Setup Guide</a>
        <a href="/resources" style="color: var(--primary); text-decoration: none;">Resources</a>
        <a href="/pricing" style="color: var(--primary); text-decoration: none;">Pricing</a>
        <a href="/about" style="color: var(--primary); text-decoration: none;">About</a>
        <a href="/contact" style="color: var(--primary); text-decoration: none;">Contact</a>
    </nav>

<div class="container">
    <header>
        <h1><i class="fas fa-envelope"></i> Contact</h1>
        <p class="tagline pulse">Got feedback, bugs, or ideas? Reach out directly.</p>
    </header>

            <div class="card">
    <h2>📬 Get in Touch</h2>
    <div class="contact-content">
        <!-- Right side: Form -->
        <form method="POST" class="contact-form">
            <label for="name">Name</label>
            <input type="text" id="name" name="name" placeholder="Your name" required>

            <label for="email">Email</label>
            <input type="email" id="email" name="email" placeholder="your.email@example.com" required>

            <label for="message">Message</label>
            <textarea id="message" name="message" placeholder="Your message here..." required></textarea>

            <button type="submit" class="submit-btn">
                <i class="fas fa-paper-plane"></i> Send Message
            </button>
        </form>
    </div>
</div>

<div class="card" style="display: flex; justify-content: space-between; align-items: center; gap: 20px;">
    <!-- Left side: Links -->
    <div class="contact-info">
        <p><strong>Email:</strong> 
            <a href="mailto:mkazemi@sfsu.edu" style="color:var(--info)">mkazemi@sfsu.edu</a>
        </p>
        <p><strong>GitHub:</strong> 
            <a href="https://github.com/youngsassanid" class="external-link" target="_blank">@youngsassanid</a>
        </p>
        <p><strong>LinkedIn:</strong> 
            <a href="https://www.linkedin.com/company/cyborgsecurity-research/" class="external-link" target="_blank">CyborgSecurity Research</a>
        </p>
    </div>

    <!-- Right side: Image -->
    <div class="contact-image">
        <img src="/goat_image_2.png" alt="Contact Us" style="width:200px; height:auto; border-radius:10px;">
    </div>
</div>

<!-- Social links below -->
<div class="social-links">
    <a href="https://github.com/youngsassanid"><i class="fab fa-github"></i></a>
    <a href="https://www.linkedin.com/company/cyborgsecurity-research/"><i class="fab fa-linkedin"></i></a>
</div>


        <div class="footer">
            <p>CyborgSecurity | Advanced Cybersecurity for the Future of Human-Machine Integration</p>
            <p>This is a simulation prototype. Not for production use.</p>
        </div>
    </body>
    </html>
    ''')

# ========== Serve Test File ==========
@app.route('/download/test')
def download_test_file():
    try:
        return send_file(
            'test_cyborgsecurity.py',
            as_attachment=True,
            download_name='test_cyborgsecurity.py',
            mimetype='text/x-python'
        )
    except Exception as e:
        return f"File not found: {str(e)}", 404
    
# ========== Test Page ==========
@app.route('/test')
@requires_auth
def run_tests():
    try:
        result = subprocess.run(
            ['python', '-m', 'unittest', 'test_cyborgsecurity.py', '-v'],
            capture_output=True,
            text=True
        )
        output = html.escape(result.stdout + result.stderr)
        status = "✅ All tests passed!" if result.returncode == 0 else "❌ Some tests failed."
    except Exception as e:
        output = str(e)
        status = "💥 Test execution failed."

    return f'''
    <html><head><style>
        body {{ background:#001a00; color:#00ff41; font-family:monospace; padding:20px; }}
        pre {{ background:#000; padding:15px; border-radius:8px; overflow:auto; }}
    </style></head><body>
        <h2>Unit Test Results</h2>
        <p>{status}</p>
        <pre>{output}</pre>
        <a href="/dashboard" style="color:#00aaff;">← Back to Dashboard</a>
    </body></html>
    '''
    
# ========== Static Files ==========
from flask import send_from_directory
import os

@app.route('/favicon.png')
def favicon():
    return send_from_directory(os.getcwd(), 'favicon.png', mimetype='image/png')

from flask import send_file

@app.route('/sam.jpeg')
def serve_sam_image():
    return send_file('sam.jpeg', mimetype='image/jpeg')

@app.route('/the_goat.jpg')
def serve_goat_image():
    return send_file('the_goat.jpg', mimetype='image/jpg')

@app.route('/cyborgsecurity_visualizer.gif')
def serve_goat_shield():
    return send_file('cyborgsecurity_visualizer.gif', mimetype='image/gif')

@app.route('/goat_image_2.png')
def serve_goat_image_2():
    return send_file('goat_image_2.png', mimetype='image/gif')

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
    print("[INFO] Visit http://localhost:5000/threat-intel for the threat intelligence feed")
    print("[INFO] Visit http://localhost:5000/goat-mode for GOAT mode")
    print("[INFO] Visit http://localhost:5000/health for the health monitor")
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

