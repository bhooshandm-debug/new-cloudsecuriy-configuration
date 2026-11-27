from flask import Blueprint, render_template, request
from flask_login import current_user, login_required

from models.finding import Finding
from models.scan import Scan
from services.authentication import visible_scans
from services.finding_processor import SEVERITY_RANK

bp = Blueprint("findings", __name__, url_prefix="/findings")


@bp.route("/")
@login_required
def index():
    q = Finding.query.join(Scan, Finding.scan_id == Scan.id)
    if not current_user.is_admin:
        q = q.filter(Scan.user_id == current_user.id)

    scan_id = request.args.get("scan_id", type=int)
    severity = request.args.get("severity", "")
    status = request.args.get("status", "")
    if scan_id:
        q = q.filter(Finding.scan_id == scan_id)
    if severity in SEVERITY_RANK:
        q = q.filter(Finding.severity == severity)
    if status in ("PASS", "FAIL", "MANUAL"):
        q = q.filter(Finding.status == status)

    page = q.order_by(Finding.severity_rank.desc(), Finding.id.desc()) \
            .paginate(page=request.args.get("page", 1, type=int), per_page=25, error_out=False)
    scans = visible_scans(current_user).filter_by(status="completed").order_by(Scan.id.desc()).limit(50).all()
    return render_template("findings.html", page=page, scans=scans, severities=list(SEVERITY_RANK),
                           filters={"scan_id": scan_id or "", "severity": severity, "status": status})
