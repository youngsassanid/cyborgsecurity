import logging
import os

from cryptography.fernet import Fernet

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
PUBLIC_DIR = os.path.join(ROOT_DIR, "public")
ALERTS_CSV = os.path.join(ROOT_DIR, "alerts.csv")
ALERTS_JSON = os.path.join(ROOT_DIR, "alerts.json")

DEBUG_MODE = os.getenv("DEBUG", "false").lower() == "true"

ENCRYPTION_KEY = Fernet.generate_key()
cipher = Fernet(ENCRYPTION_KEY)

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
CONTACT_EMAIL = os.getenv("CONTACT_EMAIL", "mkazemi@sfsu.edu")

logging.basicConfig(
    filename=os.path.join(ROOT_DIR, "cyborgsecurity.log"),
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
