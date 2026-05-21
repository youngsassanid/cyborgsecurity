import json
import logging
from datetime import datetime

from flask import Blueprint, jsonify, render_template

import config
import state
from web.auth import requires_auth

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/dashboard")
@requires_auth
def dashboard():
    monitor = state.monitor_instance
    decrypted_alerts = [
        json.loads(config.cipher.decrypt(a.encode())) for a in monitor.alerts
    ]
    decrypted_alerts.reverse()
    return render_template(
        "dashboard.html",
        alerts=decrypted_alerts,
        implant_type=monitor.interface.implant_type,
        device_id=monitor.interface.device_id,
        now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )


@dashboard_bp.route("/api/alerts", methods=["GET"])
@requires_auth
def api_alerts():
    monitor = state.monitor_instance
    decrypted_alerts = [
        json.loads(config.cipher.decrypt(a.encode())) for a in monitor.alerts
    ]
    return jsonify(decrypted_alerts)


@dashboard_bp.route("/api/clear_alerts", methods=["POST"])
@requires_auth
def clear_alerts():
    monitor = state.monitor_instance
    monitor.alerts.clear()
    monitor.exported_alerts.clear()
    open(config.ALERTS_JSON, "w").close()
    open(config.ALERTS_CSV, "w").close()
    logging.info("All alerts cleared via dashboard.")
    return jsonify({"status": "success", "message": "All alerts cleared."}), 200
