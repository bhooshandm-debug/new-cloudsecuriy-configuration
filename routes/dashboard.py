from flask import Blueprint, jsonify, render_template
from flask_login import login_required, current_user

from models.scan import Scan
from services.authentication import visible_scans
from services.finding_processor import dashboard_stats
from services.rate_limit import limit

bp = Blueprint("dashboard", __name__)


@bp.route("/")
@login_required
def index():
    recent = visible_scans(current_user).order_by(Scan.id.desc()).limit(5).all()
    return render_template("dashboard.html", stats=dashboard_stats(current_user), recent=recent)


@bp.route("/dashboard/stats")
@limit("dashboard_stats", 60, 60, methods=["GET"])
@login_required
def stats():
    return jsonify(dashboard_stats(current_user))
