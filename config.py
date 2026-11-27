import os
from dotenv import load_dotenv

from pathlib import Path
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


def _bool(name, default="false"):
    return os.getenv(name, default).strip().lower() == "true"


class Config:
    DEBUG = False
    TESTING = False
    SECRET_KEY = os.getenv("SECRET_KEY")
    FERNET_KEY = os.getenv("FERNET_KEY")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///audit.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    REPORTS_DIR = os.getenv("REPORTS_DIR", "reports")

    # Domain & Canonical URL Configuration (production ready)
    APP_DOMAIN = os.getenv("APP_DOMAIN", "cloudsec.io")
    CANONICAL_URL_BASE = os.getenv("CANONICAL_URL_BASE", "https://cloudsec.io")

    # Password recovery mail (optional; configure SMTP to enable delivery).
    SMTP_HOST = os.getenv("SMTP_HOST", "")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
    SMTP_USE_TLS = _bool("SMTP_USE_TLS", "true")
    MAIL_FROM = os.getenv("MAIL_FROM", "")
    PASSWORD_RESET_MAX_AGE = int(os.getenv("PASSWORD_RESET_MAX_AGE", "3600"))

    # Scanning
    SCAN_MODE = os.getenv("SCAN_MODE", "auto")  # auto | prowler | demo
    SCAN_SYNC = False  # True runs scans inline (used by tests)
    SCAN_TIMEOUT = int(os.getenv("SCAN_TIMEOUT", "3600"))
    PROWLER_EXECUTABLE = os.getenv("PROWLER_EXECUTABLE", "")
    VERIFY_CREDENTIALS_LIVE = _bool("VERIFY_CREDENTIALS_LIVE", "true")

    # Gemini is called server-side. Never include this key in templates or JS.
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
    GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.6-flash")

    # Sessions / cookies / security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _bool("SESSION_COOKIE_SECURE", "true")
    MAX_CONTENT_LENGTH = 1024 * 1024  # 1 MB request cap
