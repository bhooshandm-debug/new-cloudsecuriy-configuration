import pytest
from pathlib import Path
from cryptography.fernet import Fernet

from app import create_app
from models import db


class TestConfig:
    TESTING = True
    SECRET_KEY = "test-secret"
    FERNET_KEY = Fernet.generate_key().decode()
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False
    SCAN_MODE = "demo"
    SCAN_SYNC = True
    SCAN_TIMEOUT = 5
    VERIFY_CREDENTIALS_LIVE = False
    SESSION_COOKIE_SECURE = False
    REPORTS_DIR = str(Path(__file__).resolve().parent.parent / "reports" / "test-output")


@pytest.fixture
def app():
    app = create_app(TestConfig)
    yield app
    with app.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def register_and_login(client, username="alice", password="Passw0rd!x"):
    client.post("/register", data={"username": username, "email": f"{username}@example.com",
                                   "password": password})
    return client.post("/login", data={"identifier": username, "password": password})


AWS_FORM = {"provider": "aws", "name": "Prod",
            "aws_access_key_id": "AKIAABCDEFGHIJKLMNOP",
            "aws_secret_access_key": "a" * 40}
