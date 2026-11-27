from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from models import db
from models.cloud_account import CloudAccount
from providers import ProviderError, supported_providers
from services.authentication import get_owned_or_404, log_action, visible_accounts
from services.cloud_discovery import register_account
from services.rate_limit import limit

bp = Blueprint("cloud_accounts", __name__, url_prefix="/accounts")


@bp.route("/", methods=["GET", "POST"])
@limit("cloud_accounts", 10, 3600)
@login_required
def index():
    if request.method == "POST":
        try:
            acc = register_account(current_user, request.form.get("provider"),
                                   request.form.get("name"), request.form)
        except ProviderError as exc:
            flash(str(exc), "error")
        else:
            log_action("account_added", f"account={acc.id} provider={acc.provider}")
            flash(f"Connected {acc.name}. Credentials are stored encrypted.", "success")
            return redirect(url_for("cloud_accounts.index"))
    accounts = visible_accounts(current_user).order_by(CloudAccount.id.desc()).all()
    return render_template("cloud_accounts.html", accounts=accounts, providers=supported_providers())


@bp.route("/<int:account_id>/delete", methods=["POST"])
@login_required
def delete(account_id):
    acc = get_owned_or_404(CloudAccount, account_id)
    name = acc.name
    db.session.delete(acc)
    db.session.commit()
    log_action("account_deleted", f"account={account_id}")
    flash(f"Removed {name} and its scan history.", "success")
    return redirect(url_for("cloud_accounts.index"))
