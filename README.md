
# CyborgSecurity

**CyborgSecurity** is a simulated cybersecurity suite for monitoring and protecting human-machine interfaces (HMI), specifically designed for cyborg implants such as neural links, pacemakers, and electronic prosthetics. This Python-based tool detects spoofed signals, communication tampering, memory anomalies, and more — complete with real-time alert encryption, dashboard visualization, and an extensible architecture.

## What It Does

- Monitors neural biosignals for spoofing, drift, and replay attacks  
- Validates data packet integrity and detects clock tampering  
- Verifies device memory fingerprints to prevent firmware-level hacks  
- Calculates threat severity scores for triage  
- Auto-remediates certain critical threats  
- Logs alerts to encrypted JSON and CSV files  
- Sends alerts to a local Flask dashboard  
- Supports encrypted alert logging and future email notifications  

## Features

- Cyborg Simulation: Emulates biosignals and I/O traffic for implantable devices  
- Threat Detection: Identifies spoofed, replayed, and tampered data  
- Flask Web Dashboard: View alerts and implant type in real time  
- Email Placeholder: Easily extend to send alerts via email  
- Logging: CSV, JSON, and plaintext logging of all anomalies  
- Encryption: Alerts are encrypted using Fernet (symmetric AES)  
- Debug Mode Toggle: Turn debug output on or off via terminal  

## How to Run

### 1. Clone the Repository

```bash
git clone https://github.com/youngsassanid/cyborgsecurity.git
cd cyborgsecurity
```

### 2. Set Up the Virtual Environment

```bash
python -m venv .venv
source .venv/bin/activate       # On Windows use: .venv\Scripts\activate
pip install -r requirements.txt
```

> If `requirements.txt` does not exist, you can manually install:

```bash
pip install flask cryptography
```

### 3. Run the Program

```bash
python cyborgsecurity.py
```

You'll be prompted to toggle debug mode and the system will begin scanning.

## Accessing the Dashboard

Once the system finishes scanning:

* Open your browser and go to: `http://localhost:5000/dashboard`
* Login with:
  * Username: `admin`
  * Password: `cyborg123`
* View all alerts, threat severities, and device metadata.

## Output Files

* `cyborgsecurity.log`: System events & errors
* `alerts.json`: Decrypted alert data for external integrations
* `alerts.csv`: Tabular version of all alerts
* `ENCRYPTION_KEY`: Not stored — ephemeral key is generated at runtime (for now)

## Debug Mode

When launching, type `on` to enable debug mode or `off` to keep it silent.

```text
[INPUT] Type 'on' to enable debug mode, 'off' to disable, or 'exit' to quit.
```

## Implant Simulation

The system currently simulates a **NeuroLink V3** implant, but you can expand the `CyborgInterface` class to model:

* Electronic prosthetic limbs
* Implantable cardioverter-defibrillators (ICDs)
* Smart cochlear implants
* Retinal chip implants
* Brain-computer interfaces (BCIs)

## Author

Created by **Sam Kazemi**
