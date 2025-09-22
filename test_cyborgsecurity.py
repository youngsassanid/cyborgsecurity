# test_cyborgsecurity.py
"""
Unit tests for CyborgSecurity HMI Monitor.
Run with: python -m unittest test_cyborgsecurity
"""

import unittest
import time
import json
from datetime import datetime, timedelta
import hashlib
from cyborgsecurity import CyborgInterface, CyborgSecurityMonitor, cipher

class TestCyborgSecurity(unittest.TestCase):
    """Test suite for CyborgSecurity components."""

    def setUp(self):
        """Set up test fixtures before each test method."""
        self.device = CyborgInterface("TEST-001")
        self.monitor = CyborgSecurityMonitor(self.device)

    def test_device_creation(self):
        """Test that CyborgInterface initializes correctly."""
        self.assertEqual(self.device.device_id, "TEST-001")
        self.assertEqual(self.device.implant_type, "Connexus")
        self.assertIsInstance(self.device.signal_baseline, list)
        self.assertEqual(len(self.device.signal_baseline), 100)
        fingerprint = self.device.memory_fingerprint
        self.assertIsInstance(fingerprint, str)
        # MD5 is used here for simulation speed; not secure for production
        self.assertEqual(len(fingerprint), 32)  # SHA-256

    def test_spoofed_signal_detection(self):
        """Test detection of out-of-bounds biosignals."""
        initial_count = len(self.monitor.alerts)
        self.monitor.detect_spoofed_signal(200)
        self.assertGreater(len(self.monitor.alerts), initial_count)
        decrypted = [json.loads(cipher.decrypt(a.encode())) for a in self.monitor.alerts]
        self.assertTrue(
            any("Spoofed signal detected" in alert["reason"] for alert in decrypted)
        )

    def test_normal_signal_no_alert(self):
        """Ensure normal signals do not trigger alerts."""
        initial_count = len(self.monitor.alerts)
        self.monitor.detect_spoofed_signal(50)
        self.assertEqual(len(self.monitor.alerts), initial_count)

    def test_packet_verification_tampered(self):
        """Test that tampered packets are detected."""
        payload = "test_payload"
        correct = hashlib.sha256(payload.encode()).hexdigest()
        packet = {"payload": payload, "checksum": "invalid_checksum", "timestamp": time.time()}
        self.monitor.verify_packet(packet)
        decrypted = [json.loads(cipher.decrypt(a.encode())) for a in self.monitor.alerts]
        self.assertTrue(
            any("Tampered packet detected" in alert["reason"] for alert in decrypted)
        )

    def test_packet_verification_valid(self):
        """Test that valid packets pass verification."""
        payload = "test_payload"
        checksum = hashlib.sha256(payload.encode()).hexdigest()
        packet = {"payload": payload, "checksum": checksum, "timestamp": time.time()}
        initial_count = len(self.monitor.alerts)
        self.monitor.verify_packet(packet)
        self.assertEqual(len(self.monitor.alerts), initial_count)

    def test_replay_attack_detection(self):
        """Test replay attack detection."""
        packet = self.device.send_packet()
        self.monitor.detect_replay_attack(packet)
        self.monitor.detect_replay_attack(packet)
        decrypted = [json.loads(cipher.decrypt(a.encode())) for a in self.monitor.alerts]
        self.assertTrue(
            any("Replay attack detected" in alert["reason"] for alert in decrypted)
        )

    def test_clock_tampering_detection(self):
        """Test detection of system clock rollback."""
        self.monitor.last_check_time = datetime.now() + timedelta(minutes=5)
        self.monitor.detect_clock_tampering()
        decrypted = [json.loads(cipher.decrypt(a.encode())) for a in self.monitor.alerts]
        self.assertTrue(
            any("System clock tampering detected" in alert["reason"] for alert in decrypted)
        )

    def test_memory_integrity_check(self):
        """Test detection of memory fingerprint mismatch."""
        original = self.device.memory_fingerprint
        self.device.memory_fingerprint = "corrupted"
        self.monitor.verify_memory_integrity()
        decrypted = [json.loads(cipher.decrypt(a.encode())) for a in self.monitor.alerts]
        self.assertTrue(
            any("Memory fingerprint mismatch" in alert["reason"] for alert in decrypted)
        )
        self.device.memory_fingerprint = original

    def test_threat_scoring(self):
        """Test correct threat score assignment."""
        self.assertEqual(self.monitor.compute_threat_score("spoofed signal"), 4)
        self.assertEqual(self.monitor.compute_threat_score("Tampered packet"), 5)
        self.assertEqual(self.monitor.compute_threat_score("unknown issue"), 1)

    def test_raise_alert_encryption_and_logging(self):
        """Ensure alerts are encrypted and logged."""
        initial_count = len(self.monitor.alerts)
        self.monitor.raise_alert("Test alert", {"test": "data"})
        self.assertGreater(len(self.monitor.alerts), initial_count)
        # Try decrypting
        try:
            decrypted = json.loads(cipher.decrypt(self.monitor.alerts[-1].encode()))
            self.assertIn("reason", decrypted)
        except Exception as e:
            self.fail(f"Failed to decrypt alert: {e}")

if __name__ == '__main__':
    unittest.main()
