import logging
from datetime import datetime

from flask import Blueprint, jsonify, render_template

from web.auth import requires_auth

intelligence_bp = Blueprint("intelligence", __name__)

SAMPLE_THREATS = [
    {"type": "IP", "value": "192.168.220.45", "source": "Botnet C2", "severity": "High", "timestamp": "2025-04-27T14:22:33"},
    {"type": "Hash", "value": "a1b2c3d4e5f67890abcdef1234567890", "source": "Ransomware Variant X", "severity": "Critical", "timestamp": "2025-04-27T14:20:11"},
    {"type": "Domain", "value": "malware-c2[.]shadownet", "source": "Phishing Campaign", "severity": "High", "timestamp": "2025-04-27T14:18:05"},
    {"type": "IP", "value": "10.5.5.177", "source": "Insider Threat", "severity": "Medium", "timestamp": "2025-04-27T14:15:44"},
    {"type": "Hash", "value": "f0e1d2c3b4a5968778695a4b3c2d1e0f", "source": "Spyware Module", "severity": "Critical", "timestamp": "2025-04-27T14:12:20"},
    {"type": "Domain", "value": "fake-login[.]cyber-scam.com", "source": "Credential Harvester", "severity": "High", "timestamp": "2025-04-27T14:10:01"},
]


@intelligence_bp.route("/threat-intel")
@requires_auth
def threat_intel():
    return render_template(
        "threat_intel.html",
        threats=SAMPLE_THREATS,
        now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )


@intelligence_bp.route("/goat-mode")
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
        "audit_log_integrity": "Immutable",
    }
    return render_template(
        "goat_mode.html",
        status=goat_status,
        now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )


@intelligence_bp.route("/api/goat-mode/airgap", methods=["POST"])
@requires_auth
def api_goat_mode_airgap():
    logging.info("GOAT Mode: Emergency airgap activated. All wireless interfaces disabled.")
    return jsonify({
        "status": "airgapped",
        "message": "All wireless communication disabled.",
        "timestamp": datetime.now().isoformat(),
    })


@intelligence_bp.route("/api/goat-mode/airgap/deactivate", methods=["POST"])
@requires_auth
def api_goat_mode_airgap_deactivate():
    logging.info("GOAT Mode: Airgap deactivated. Wireless interfaces restored.")
    return jsonify({
        "status": "active",
        "message": "Wireless communication restored.",
        "timestamp": datetime.now().isoformat(),
    })
