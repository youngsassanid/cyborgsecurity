import csv
import hashlib
import json
import logging
import os
import statistics
import time
from datetime import datetime

import config
from core.device import CyborgInterface


class CyborgSecurityMonitor:
    def __init__(self, interface: CyborgInterface):
        self.interface = interface
        self.alerts = []
        self.signal_window = []
        self.last_check_time = datetime.now()
        self.csv_file = config.ALERTS_CSV
        self.json_file = config.ALERTS_JSON
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
                "current_time": now.isoformat(),
            })
        self.last_check_time = now

    def verify_memory_integrity(self):
        expected = self.interface.memory_fingerprint
        actual = self.interface.generate_memory_fingerprint()
        if expected != actual:
            self.raise_alert("Memory fingerprint mismatch", {
                "expected": expected,
                "actual": actual,
            })

    def compute_threat_score(self, reason):
        score_map = {
            "spoofed": 4,
            "drift": 2,
            "tampered": 5,
            "replay": 5,
            "clock": 3,
            "memory": 4,
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
            "device_id": self.interface.device_id,
        }
        encrypted_alert = config.cipher.encrypt(json.dumps(alert).encode()).decode()
        logging.warning(f"{reason}: {data} (Severity: {severity})")
        self.alerts.append(encrypted_alert)
        self.exported_alerts.append(alert)
        self.export_alert_to_csv(alert)
        self.export_alerts_to_json()
        self.auto_remediate_if_critical(reason)
        if config.DEBUG_MODE:
            print(f"[DEBUG] Alert raised: {reason} | Severity: {severity}\nData: {data}")

    def export_alert_to_csv(self, alert):
        file_exists = os.path.isfile(self.csv_file)
        with open(self.csv_file, mode="a", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=alert.keys())
            if not file_exists:
                writer.writeheader()
            writer.writerow(alert)

    def export_alerts_to_json(self):
        with open(self.json_file, "w") as f:
            json.dump(self.exported_alerts, f, indent=4)

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
