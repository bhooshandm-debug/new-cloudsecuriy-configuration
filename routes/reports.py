import os

from flask import Blueprint, flash, redirect, render_template, request, send_file, url_for
from flask_login import current_user, login_required

from models.scan import Scan
from services.authentication import get_owned_or_404, log_action, visible_scans
from services.report_service import FORMATS, generate_report

bp = Blueprint("reports", __name__, url_prefix="/reports")


@bp.route("/")
@login_required
def index():
    scans = visible_scans(current_user).filter_by(status="completed").order_by(Scan.id.desc()).all()
    return render_template("reports.html", scans=scans, formats=FORMATS)


@bp.route("/<int:scan_id>/download", methods=["POST"])
@login_required
def download(scan_id):
    scan = get_owned_or_404(Scan, scan_id)
    fmt = request.form.get("format", "csv")
    if scan.status != "completed" or fmt not in FORMATS:
        flash("That report is not available.", "error")
        return redirect(url_for("reports.index"))
    path = generate_report(scan, fmt)
    log_action("report_generated", f"scan={scan.id} format={fmt}")
    return send_file(path, as_attachment=True, download_name=os.path.basename(path))
