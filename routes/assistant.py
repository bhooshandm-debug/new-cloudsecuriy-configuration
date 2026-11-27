from flask import Blueprint, current_app, jsonify, render_template, request
from flask_login import current_user, login_required

from models.finding import Finding
from models.scan import Scan
from services.ai_chat import AssistantError, generate_reply
from services.authentication import visible_accounts
from services.rate_limit import limit

bp = Blueprint("assistant", __name__, url_prefix="/assistant")
MAX_MESSAGE_LENGTH = 1000


@bp.get("/")
@login_required
def index():
    return render_template("assistant.html")


def _latest_findings(user):
    """Return failed findings from each visible account's latest completed scan."""
    result = []
    for account in visible_accounts(user).all():
        scan = account.scans.filter_by(status="completed").order_by(Scan.id.desc()).first()
        if not scan:
            continue
        rows = (Finding.query.filter_by(scan_id=scan.id, status="FAIL")
                .order_by(Finding.severity_rank.desc(), Finding.id.asc()).limit(30).all())
        result.extend({
            "provider": account.provider.upper(), "account": account.name,
            "scan_id": scan.id, "title": row.title, "check_id": row.check_id,
            "severity": row.severity, "status": row.status, "service": row.service,
            "region": row.region, "resource": row.resource, "detail": row.detail,
            "remediation": row.remediation,
        } for row in rows)
    result.sort(key=lambda item: ({"critical": 0, "high": 1, "medium": 2,
                                  "low": 3, "informational": 4}.get(item["severity"], 5),
                                 item["scan_id"], item["title"]))
    return result[:60]


@bp.post("/chat")
@limit("assistant_chat", 20, 60)
@login_required
def chat():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="Send a chat message to get started."), 400
    message = data.get("message")
    if not isinstance(message, str) or not message.strip():
        return jsonify(error="Write a message before sending."), 400
    message = message.strip()
    if len(message) > MAX_MESSAGE_LENGTH:
        return jsonify(error=f"Messages must be {MAX_MESSAGE_LENGTH} characters or fewer."), 400
    history = data.get("history", [])
    if not isinstance(history, list):
        return jsonify(error="Chat history must be a list."), 400
    if len(history) > 8:
        history = history[-8:]

    api_key = current_app.config.get("GEMINI_API_KEY", "")
    if not isinstance(api_key, str) or not api_key.strip():
        return jsonify(error="Gemini is not configured. Add GEMINI_API_KEY to .env and restart the app."), 503
    try:
        reply = generate_reply(message, history, _latest_findings(current_user), api_key.strip(),
                               current_app.config.get("GEMINI_MODEL", "gemini-3.6-flash"))
    except AssistantError as exc:
        return jsonify(error=str(exc)), 503
    return jsonify(reply=reply, mode="gemini")
