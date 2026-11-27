import pytest
from models import db
from models.cloud_account import CloudAccount
from models.scan import Scan
from models.user import User
from tests.conftest import register_and_login


def test_admin_route_blocked_for_unauthenticated_and_regular_users(app, client):
    # Unauthenticated should be blocked
    resp = client.get("/admin/")
    assert resp.status_code in (302, 401)

    # First user registered is admin
    register_and_login(client, "adminuser", "Passw0rd123!")
    assert client.get("/admin/").status_code == 200

    # Second user is regular user
    client2 = app.test_client()
    register_and_login(client2, "regularuser", "Passw0rd123!")
    resp2 = client2.get("/admin/")
    assert resp2.status_code == 403


def test_user_data_isolation_idor_prevention(app, client):
    # Register Alice (admin)
    register_and_login(client, "alice", "Passw0rd123!")
    with app.app_context():
        alice = User.query.filter_by(username="alice").one()
        acc = CloudAccount(user_id=alice.id, provider="aws", name="Alice AWS",
                           identifier="111111111111", encrypted_credentials="enc")
        db.session.add(acc)
        db.session.flush()
        scan = Scan(account_id=acc.id, user_id=alice.id, status="completed", mode="demo")
        db.session.add(scan)
        db.session.commit()
        alice_scan_id = scan.id
        alice_acc_id = acc.id

    # Register Bob (regular user)
    bob_client = app.test_client()
    register_and_login(bob_client, "bob", "Passw0rd123!")

    # Bob cannot download Alice's report or see scan status or delete Alice's account
    assert bob_client.post(f"/reports/{alice_scan_id}/download", data={"format": "json"}).status_code == 404
    assert bob_client.get(f"/scans/{alice_scan_id}/status").status_code == 404
    assert bob_client.post(f"/accounts/{alice_acc_id}/delete").status_code == 404


def test_security_headers_present(app, client):
    register_and_login(client, "headeruser", "Passw0rd123!")
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert resp.headers.get("Referrer-Policy") == "same-origin"
    assert "default-src 'self'" in resp.headers.get("Content-Security-Policy", "")
    assert "no-store" in resp.headers.get("Cache-Control", "")


def test_password_hash_uses_scrypt():
    u = User(username="test_scrypt", email="scrypt@example.com")
    u.set_password("SecurePassword123!")
    assert u.password_hash.startswith("scrypt:")
    assert u.check_password("SecurePassword123!")
    assert not u.check_password("WrongPassword")
