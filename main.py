import argparse
import threading
import time
import unittest

import config
import state
from core.device import CyborgInterface
from core.monitor import CyborgSecurityMonitor
from web import create_app


def run_monitoring_in_background(monitor, cycles=200):
    def monitor_loop():
        monitor.run_monitoring_cycle(cycles)
    thread = threading.Thread(target=monitor_loop, daemon=True)
    thread.start()
    return thread


def main():
    parser = argparse.ArgumentParser(description="CyborgSecurity HMI Monitor")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("command", nargs="?", default="run", help="Command: run or test")
    args = parser.parse_args()

    config.DEBUG_MODE = args.debug

    if args.command == "test":
        unittest.main(argv=["main.py", "TestCyborgSecurity"], exit=False, verbosity=2)
        return

    device = CyborgInterface(device_id="CYB-2025-001")
    monitor = CyborgSecurityMonitor(device)
    state.monitor_instance = monitor

    print("[INFO] Implant type:", device.implant_type)
    print("[INFO] Running CyborgSecurity monitoring...")

    monitor_thread = run_monitoring_in_background(monitor, 200)
    time.sleep(2)

    print(f"[INFO] Monitoring started. {len(monitor.alerts)} alerts detected so far.")
    print("[INFO] Visit http://localhost:5000 for the main page")
    print("[INFO] Visit http://localhost:5000/dashboard for the protected dashboard")
    print("[INFO] Visit http://localhost:5000/threat-intel for the threat intelligence feed")
    print("[INFO] Visit http://localhost:5000/goat-mode for GOAT mode")
    print("[INFO] Visit http://localhost:5000/health for the health monitor")
    print("[INFO] Dashboard login - username: admin, password: cyborg123")
    print("[INFO] Press Ctrl+C to stop the server.")

    app = create_app()
    try:
        app.run(debug=config.DEBUG_MODE, port=5000, use_reloader=False)
    except KeyboardInterrupt:
        print("\n[INFO] Shutting down...")
        monitor_thread.join(timeout=2)
        print("[INFO] Monitoring stopped.")


if __name__ == "__main__":
    main()
