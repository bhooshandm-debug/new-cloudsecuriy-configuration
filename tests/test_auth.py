from models.user import User
from tests.conftest import register_and_login


def test_first_user_is_admin_second_is_not(app, client):
    register_and_login(client, "alice")
    register_and_login(app.test_client(), "bob")
    with app.app_context():
        assert User.query.filter_by(username="alice").one().role == "admin"
        assert User.query.filter_by(username="bob").one().role == "user"


def test_weak_password_rejected(client):
    resp = client.post("/register", data={"username": "carol", "email": "c@example.com",
                                          "password": "short"}, follow_redirects=True)
    assert b"Password needs" in resp.data


def test_protected_pages_redirect_to_login(client):
    resp = client.get("/accounts/")
    assert resp.status_code == 302 and "/login" in resp.headers["Location"]


def test_wrong_password_and_lockout(client):
    register_and_login(client, "dave")
    client.post("/logout")
    for _ in range(5):
        client.post("/login", data={"identifier": "dave", "password": "wrong"})
    resp = client.post("/login", data={"identifier": "dave", "password": "Passw0rd!x"})
    assert b"Too many failed attempts" in resp.data


def test_open_redirect_blocked(client):
    client.post("/register", data={"username": "erin", "email": "e@example.com", "password": "Passw0rd!x"})
    resp = client.post("/login?next=//evil.example", data={"identifier": "erin", "password": "Passw0rd!x"})
    assert resp.status_code == 302 and "evil.example" not in resp.headers["Location"]


def test_admin_page_forbidden_for_regular_user(app, client):
    register_and_login(client, "alice")  # admin
    bob = app.test_client()
    register_and_login(bob, "bob")
    assert bob.get("/admin/").status_code == 403
    assert client.get("/admin/").status_code == 200
