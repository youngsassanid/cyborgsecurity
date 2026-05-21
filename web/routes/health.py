import random
from datetime import datetime

from flask import Blueprint, render_template

import state
from web.auth import requires_auth

health_bp = Blueprint("health", __name__)


@health_bp.route("/health")
@requires_auth
def health_monitor():
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
    system_status = {
        "Secure Enclave": "Active",
        "Neural Firewall": "Enabled",
        "Auto-Remediation": "Online",
        "Wireless Encryption": "AES-256",
        "Audit Log": "Immutable",
        "Consent Module": "Ready",
    }
    recent_events = [
        {"time": "14:23", "event": "Microglial firewall triggered", "type": "security"},
        {"time": "14:21", "event": "Cognitive load peak detected", "type": "warning"},
        {"time": "14:19", "event": "Firmware self-check passed", "type": "info"},
        {"time": "14:17", "event": "Signal drift corrected", "type": "security"},
        {"time": "14:15", "event": "Bluetooth LE heartbeat confirmed", "type": "info"},
    ]
    monitor = state.monitor_instance
    return render_template(
        "health.html",
        health_data=health_data,
        system_status=system_status,
        recent_events=recent_events,
        health_score=random.randint(88, 100),
        implant_type=monitor.interface.implant_type,
        device_id=monitor.interface.device_id,
        now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )
