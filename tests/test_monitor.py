import hashlib
import json
import time
import unittest
from datetime import datetime, timedelta

import config
from core.device import CyborgInterface
from core.monitor import CyborgSecurityMonitor


def decrypted_alerts(monitor):
    return [json.loads(config.cipher.decrypt(a.encode())) for a in monitor.alerts]


class TestCyborgSecurity(unittest.TestCase):
    def setUp(self):
        self.device = CyborgInterface("TEST-001")
        self.monitor = CyborgSecurityMonitor(self.device)

    def test_device_creation(self):
        self.assertEqual(self.device.device_id, "TEST-001")
        self.assertEqual(self.device.implant_type, "Connexus")
        self.assertIsInstance(self.device.signal_baseline, list)
        self.assertEqual(len(self.device.signal_baseline), 100)
        self.assertEqual(len(self.device.memory_fingerprint), 32)

    def test_spoofed_signal_detection(self):
        initial = len(self.monitor.alerts)
        self.monitor.detect_spoofed_signal(200)
        self.assertGreater(len(self.monitor.alerts), initial)
        self.assertTrue(
            any("Spoofed signal detected" in a["reason"] for a in decrypted_alerts(self.monitor))
        )

    def test_normal_signal_no_alert(self):
        initial = len(self.monitor.alerts)
        self.monitor.detect_spoofed_signal(50)
        self.assertEqual(len(self.monitor.alerts), initial)

    def test_packet_verification_tampered(self):
        packet = {"payload": "test_payload", "checksum": "invalid", "timestamp": time.time()}
        self.monitor.verify_packet(packet)
        self.assertTrue(
            any("Tampered packet detected" in a["reason"] for a in decrypted_alerts(self.monitor))
        )

    def test_packet_verification_valid(self):
        payload = "test_payload"
        checksum = hashlib.sha256(payload.encode()).hexdigest()
        packet = {"payload": payload, "checksum": checksum, "timestamp": time.time()}
        initial = len(self.monitor.alerts)
        self.monitor.verify_packet(packet)
        self.assertEqual(len(self.monitor.alerts), initial)

    def test_replay_attack_detection(self):
        packet = self.device.send_packet()
        self.monitor.detect_replay_attack(packet)
        self.monitor.detect_replay_attack(packet)
        self.assertTrue(
            any("Replay attack detected" in a["reason"] for a in decrypted_alerts(self.monitor))
        )

    def test_clock_tampering_detection(self):
        self.monitor.last_check_time = datetime.now() + timedelta(minutes=5)
        self.monitor.detect_clock_tampering()
        self.assertTrue(
            any("System clock tampering detected" in a["reason"] for a in decrypted_alerts(self.monitor))
        )

    def test_memory_integrity_check(self):
        original = self.device.memory_fingerprint
        self.device.memory_fingerprint = "corrupted"
        self.monitor.verify_memory_integrity()
        self.assertTrue(
            any("Memory fingerprint mismatch" in a["reason"] for a in decrypted_alerts(self.monitor))
        )
        self.device.memory_fingerprint = original

    def test_threat_scoring(self):
        self.assertEqual(self.monitor.compute_threat_score("spoofed signal"), 4)
        self.assertEqual(self.monitor.compute_threat_score("Tampered packet"), 5)
        self.assertEqual(self.monitor.compute_threat_score("unknown issue"), 1)

    def test_alert_encryption(self):
        initial = len(self.monitor.alerts)
        self.monitor.raise_alert("Test alert", {"test": "data"})
        self.assertGreater(len(self.monitor.alerts), initial)
        decrypted = json.loads(config.cipher.decrypt(self.monitor.alerts[-1].encode()))
        self.assertIn("reason", decrypted)


if __name__ == "__main__":
    unittest.main()
