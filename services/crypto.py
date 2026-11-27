import json

from cryptography.fernet import Fernet
from flask import current_app


def _fernet():
    return Fernet(current_app.config["FERNET_KEY"].encode())


def encrypt_json(data):
    return _fernet().encrypt(json.dumps(data).encode()).decode()


def decrypt_json(token):
    return json.loads(_fernet().decrypt(token.encode()))
