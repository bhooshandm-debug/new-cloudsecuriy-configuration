from datetime import timedelta

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from models import db, utcnow
from models.cloud_account import CloudAccount
from models.scan import Scan
from providers import ProviderError
from services.authentication import get_owned_or_404, visible_accounts, visible_scans
from services.finding_processor import compare_scans
from services.scanner_service import start_scan
from services.rate_limit import limit

bp = Blueprint("scans", __name__, url_prefix="/scans")


@bp.route("/")
@login_required
def index():
    scans = visible_scans(current_user).order_by(Scan.id.desc()).limit(100).all()
    accounts = visible_accounts(current_user).all()
    # For each completed scan, the previous completed scan of the same account (if any)
    previous, last_seen = {}, {}
    for s in sorted((s for s in scans if s.status == "completed"), key=lambda s: s.id):
        if s.account_id in last_seen:
            previous[s.id] = last_seen[s.account_id]
        last_seen[s.account_id] = s.id
    return render_template("scans.html", scans=scans, accounts=accounts, previous=previous)


@bp.route("/compare")
@login_required
def compare():
    completed = visible_scans(current_user).filter_by(status="completed") \
        .order_by(Scan.id.desc()).limit(100).all()
    base_id = request.args.get("base", type=int)
    target_id = request.args.get("target", type=int)
    base = target = result = None

    if base_id and target_id:
        base = get_owned_or_404(Scan, base_id)
        target = get_owned_or_404(Scan, target_id)
        if base.id > target.id:  # always treat the older scan as the baseline
            base, target = target, base
        if base.id == target.id:
            flash("Pick two different scans.", "error")
        elif base.account_id != target.account_id:
            flash("Both scans must belong to the same account.", "error")
        elif base.status != "completed" or target.status != "completed":
            flash("Only completed scans can be compared.", "error")
        else:
            result = compare_scans(base, target)
    return render_template("compare.html", scans=completed, base=base, target=target, result=result)


@bp.route("/start/<int:account_id>", methods=["POST"])
@limit("start_scan", 5, 3600)
@login_required
def start(account_id):
    account = get_owned_or_404(CloudAccount, account_id)
    try:
        scan = start_scan(account, current_user.id, request.form.get("mode"))
    except ProviderError as exc:
        flash(str(exc), "error")
    else:
        flash(f"Scan #{scan.id} started for {account.name}.", "success")
    return redirect(url_for("scans.index"))


@bp.route("/<int:scan_id>/status")
@limit("scan_status", 120, 60, methods=["GET"])
@login_required
def status(scan_id):
    scan = get_owned_or_404(Scan, scan_id)
    if scan.status == "pending" and (utcnow() - scan.created_at) > timedelta(minutes=2):
        scan.status = "failed"
        scan.error = "The scan worker did not start. Retry the scan."
        scan.finished_at = utcnow()
        db.session.commit()
    elif scan.status == "running" and scan.started_at and (utcnow() - scan.started_at) > timedelta(seconds=3900):
        scan.status = "failed"
        scan.error = "The scan timed out. Retry the scan."
        scan.finished_at = utcnow()
        db.session.commit()
    started = scan.started_at or scan.created_at
    elapsed = max(0, int((utcnow() - started).total_seconds()))
    return jsonify(id=scan.id, status=scan.status, error=scan.error,
                   total=scan.total_findings, failed=scan.failed_findings,
                   elapsed=elapsed)
