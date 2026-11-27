from models.cloud_account import CloudAccount
from models.finding import Finding
from models.scan import Scan
from services.crypto import decrypt_json
from services.finding_processor import normalize
from services.report_service import _safe_cell
from tests.conftest import AWS_FORM, register_and_login


def test_account_credentials_are_encrypted(app, client):
    register_and_login(client)
    client.post("/accounts/", data=AWS_FORM)
    with app.app_context():
        acc = CloudAccount.query.one()
        assert AWS_FORM["aws_secret_access_key"] not in acc.encrypted_credentials
        assert decrypt_json(acc.encrypted_credentials)["access_key_id"] == AWS_FORM["aws_access_key_id"]


def test_demo_scan_stores_findings_and_counts(app, client):
    register_and_login(client)
    client.post("/accounts/", data=AWS_FORM)
    with app.app_context():
        account_id = CloudAccount.query.one().id
    client.post(f"/scans/start/{account_id}")
    with app.app_context():
        scan = Scan.query.one()
        assert scan.status == "completed"
        assert scan.total_findings == Finding.query.count() > 0
        assert scan.failed_findings == Finding.query.filter_by(status="FAIL").count()


def test_users_cannot_see_each_others_accounts(app, client):
    register_and_login(client, "alice")
    client.post("/accounts/", data=AWS_FORM)
    bob = app.test_client()
    register_and_login(bob, "bob")
    with app.app_context():
        account_id = CloudAccount.query.one().id
    assert bob.post(f"/scans/start/{account_id}").status_code == 404


def test_report_download(app, client):
    register_and_login(client)
    client.post("/accounts/", data=AWS_FORM)
    with app.app_context():
        account_id = CloudAccount.query.one().id
    client.post(f"/scans/start/{account_id}")
    with app.app_context():
        scan_id = Scan.query.one().id
    resp = client.post(f"/reports/{scan_id}/download", data={"format": "csv"})
    assert resp.status_code == 200 and b"severity,status" in resp.data


def test_normalize_ocsf_record():
    raw = {"metadata": {"event_code": "s3_bucket_public"}, "finding_info": {"title": "Bucket is public"},
           "severity": "High", "status_code": "FAIL",
           "resources": [{"uid": "arn:aws:s3:::b", "region": "us-east-1", "group": {"name": "s3"}}],
           "remediation": {"desc": "Block public access."}}
    out = normalize(raw)
    assert (out["check_id"], out["severity"], out["status"], out["service"]) == \
           ("s3_bucket_public", "high", "FAIL", "s3")
    assert out["resource"] == "arn:aws:s3:::b" and out["remediation"] == "Block public access."


def test_csv_formula_injection_neutralised():
    assert _safe_cell("=HYPERLINK(\"x\")").startswith("'")
    assert _safe_cell("normal") == "normal"


def test_diff_findings_new_resolved_persisting():
    from services.finding_processor import diff_findings

    def f(cid, status, sev="high"):
        return {"check_id": cid, "resource": "r", "region": "g", "status": status,
                "severity": sev, "title": cid}

    old = [f("a", "FAIL"), f("b", "FAIL"), f("c", "FAIL"), f("d", "PASS")]
    new = [f("a", "FAIL"), f("b", "PASS"), f("d", "FAIL", "critical"), f("e", "FAIL")]
    out = diff_findings(old, new)
    assert [x["check_id"] for x in out["new_issues"]] == ["d", "e"]       # critical sorts first
    assert {x["check_id"]: x["now"] for x in out["resolved"]} == {"b": "Passing", "c": "No longer reported"}
    assert [x["check_id"] for x in out["persisting"]] == ["a"]


def test_compare_page(app, client):
    register_and_login(client)
    client.post("/accounts/", data=AWS_FORM)
    with app.app_context():
        account_id = CloudAccount.query.one().id
    client.post(f"/scans/start/{account_id}")
    client.post(f"/scans/start/{account_id}")
    with app.app_context():
        ids = [s.id for s in Scan.query.order_by(Scan.id).all()]
    resp = client.get(f"/scans/compare?base={ids[0]}&target={ids[1]}")
    assert resp.status_code == 200 and b"New issues" in resp.data
    assert b"Compare with" in client.get("/scans/").data
    assert b"different scans" in client.get(f"/scans/compare?base={ids[0]}&target={ids[0]}").data
