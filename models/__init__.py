from datetime import datetime, timezone

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def utcnow():
    """Naive UTC timestamp (SQLite-friendly)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)
