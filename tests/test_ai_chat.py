from tests.conftest import register_and_login


def test_chat_requires_login(client):
    response = client.post("/assistant/chat", json={"message": "Help me prioritize"})
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_assistant_page_requires_login(client):
    response = client.get("/assistant/")
    assert response.status_code == 302


def test_assistant_page_and_dashboard_render(client):
    register_and_login(client)
    assert b"CloudSec AI Assistant" in client.get("/assistant/").data
    page = client.get("/")
    assert page.status_code == 200
    assert b"assistant-launch" in page.data
    assert b"assistant-input" in page.data


def test_chat_requires_gemini_key(app, client):
    register_and_login(client)
    app.config["GEMINI_API_KEY"] = ""
    response = client.post("/assistant/chat", json={"message": "Explain IAM"})
    assert response.status_code == 503
    assert b"GEMINI_API_KEY" in response.data


def test_chat_rejects_empty_oversized_and_bad_history(client):
    register_and_login(client)
    assert client.post("/assistant/chat", json={"message": "  "}).status_code == 400
    assert client.post("/assistant/chat", json={"message": "x" * 1001}).status_code == 400
    assert client.post("/assistant/chat", json={"message": "hello", "history": "bad"}).status_code == 400


def test_chat_passes_only_latest_findings_and_history(app, client, monkeypatch):
    register_and_login(client)
    app.config.update(GEMINI_API_KEY="AIza-test-key", GEMINI_MODEL="gemini-test-flash")
    captured = {}

    def fake_reply(message, history, findings, api_key, model):
        captured.update(message=message, history=history, findings=findings, api_key=api_key, model=model)
        return "Review critical findings first."

    monkeypatch.setattr("routes.assistant.generate_reply", fake_reply)
    response = client.post("/assistant/chat", json={
        "message": "What should I fix first?",
        "history": [{"role": "user", "content": "Earlier question"}],
    })
    assert response.status_code == 200
    assert response.json["reply"] == "Review critical findings first."
    assert response.json["mode"] == "gemini"
    assert captured["message"] == "What should I fix first?"
    assert captured["history"] == [{"role": "user", "content": "Earlier question"}]
    assert captured["findings"] == []
    assert captured["api_key"] == "AIza-test-key"
    assert captured["model"] == "gemini-test-flash"


def test_chat_includes_real_user_owned_audit_findings(app, client, monkeypatch):
    from models import db
    from models.cloud_account import CloudAccount
    from models.finding import Finding
    from models.scan import Scan
    from models.user import User

    register_and_login(client, "alice")
    bob = app.test_client()
    register_and_login(bob, "bob")
    with app.app_context():
        owner = User.query.filter_by(username="bob").one()
        account = CloudAccount(user_id=owner.id, provider="aws", name="Bob Prod",
                               identifier="123", encrypted_credentials="encrypted")
        db.session.add(account)
        db.session.flush()
        scan = Scan(account_id=account.id, user_id=owner.id, status="completed", mode="prowler")
        db.session.add(scan)
        db.session.flush()
        db.session.add(Finding(scan_id=scan.id, check_id="s3-public", title="Bucket permits public access",
                               severity="critical", severity_rank=4, status="FAIL", service="s3",
                               region="us-east-1", resource="arn:aws:s3:::bob-data",
                               detail="Public access is enabled.", remediation="Block public access."))
        db.session.commit()

    app.config["GEMINI_API_KEY"] = "AIza-test-key"
    seen = {}
    monkeypatch.setattr("routes.assistant.generate_reply",
                        lambda message, history, findings, key, model: seen.update(findings=findings) or "ok")
    assert bob.post("/assistant/chat", json={"message": "Explain my latest AWS audit"}).status_code == 200
    assert len(seen["findings"]) == 1
    assert seen["findings"][0]["account"] == "Bob Prod"
    assert seen["findings"][0]["resource"] == "arn:aws:s3:::bob-data"


def test_chat_handles_gemini_failures(app, client, monkeypatch):
    register_and_login(client)
    app.config["GEMINI_API_KEY"] = "AIza-test-key"

    def fail(*args, **kwargs):
        from services.ai_chat import AssistantError
        raise AssistantError("Gemini rate limit or quota reached.")

    monkeypatch.setattr("routes.assistant.generate_reply", fail)
    response = client.post("/assistant/chat", json={"message": "Explain IAM"})
    assert response.status_code == 503
    assert b"rate limit or quota" in response.data
