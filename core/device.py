import hashlib
import json
import random
import time


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
            return random.gauss(90, 20)
        return random.gauss(50, 5)

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
