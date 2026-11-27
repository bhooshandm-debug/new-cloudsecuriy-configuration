import threading
import traceback
from datetime import timedelta

from flask import current_app

from models import db, utcnow
from models.scan import Scan
from providers import ProviderError
from services.authentication import log_action
from services.crypto import decrypt_json
from services.finding_processor import process_and_store
from services.prowler_service import demo_findings, prowler_available, run_prowler


def resolve_mode(requested_mode=None, provider_name=None):
    mode = current_app.config.get("SCAN_MODE", "auto")
    if mode == "demo":
        return "demo"
    if requested_mode == "quick" or (requested_mode is None and provider_name == "aws"):
        return "quick"
    if requested_mode == "full":
        if not prowler_available():
            raise ProviderError("Prowler is not installed. Install it or set SCAN_MODE=demo.")
        return "prowler"
    if mode == "auto":
        if not prowler_available():
            raise ProviderError(
                "Prowler is not installed. Install it with `uv tool install prowler --python 3.13`, "
                "put it on PATH or set PROWLER_EXECUTABLE, then restart the app. "
                "SCAN_MODE=demo uses sample data only."
            )
        return "prowler"
    if mode == "prowler" and not prowler_available():
        raise ProviderError("Prowler is not installed. Install it or set SCAN_MODE=demo.")
    return mode


def start_scan(account, user_id, requested_mode=None):
    """Create a Scan and run it (in a background thread unless SCAN_SYNC is set)."""
    active = account.scans.filter(Scan.status.in_(("pending", "running"))).first()
    if active and active.status == "pending" and (utcnow() - active.created_at) > timedelta(minutes=2):
        active.status = "failed"
        active.error = "The scan worker did not start. Retry the scan."
        active.finished_at = utcnow()
        db.session.commit()
    elif active and active.status == "running" and active.started_at and (utcnow() - active.started_at) > timedelta(seconds=3900):
        active.status = "failed"
        active.error = "The scan timed out. Retry the scan."
        active.finished_at = utcnow()
        db.session.commit()
    elif active:
        raise ProviderError("A scan is already running for this account.")

    scan = Scan(account_id=account.id, user_id=user_id, status="pending",
                mode=resolve_mode(requested_mode, account.provider))
    db.session.add(scan)
    db.session.commit()
    log_action("scan_started", f"scan={scan.id} account={account.id} mode={scan.mode}")

    app = current_app._get_current_object()
    if app.config.get("SCAN_SYNC"):
        run_scan(app, scan.id)
    else:
        threading.Thread(target=run_scan, args=(app, scan.id), daemon=True).start()
    return scan


def run_scan(app, scan_id):
    with app.app_context():
        scan = None
        try:
            scan = db.session.get(Scan, scan_id)
            if scan is None:
                return
            scan.status, scan.started_at = "running", utcnow()
            db.session.commit()
            account = scan.account
            if scan.mode == "demo":
                raw = demo_findings(account.provider)
            elif scan.mode == "quick":
                from services.fast_scanner import audit_aws_account
                creds = decrypt_json(account.encrypted_credentials)
                raw = audit_aws_account(creds, time_budget=45)
            else:
                creds = decrypt_json(account.encrypted_credentials)
                raw = run_prowler(account.provider, creds, app.config["SCAN_TIMEOUT"])
            process_and_store(scan, raw)
            scan.status = "completed"
        except Exception as exc:  # record any failure on the scan instead of losing it
            try:
                db.session.rollback()
                scan = db.session.get(Scan, scan_id)
            except Exception:
                app.logger.exception("Cannot re-fetch scan %s after failure.", scan_id)
                return
            if scan is None:
                app.logger.error("Scan %s failed before its record could be loaded (%s).",
                                 scan_id, type(exc).__name__)
                return
            scan.status = "failed"
            # Exception strings from cloud SDKs or subprocesses may carry secrets.
            scan.error = "Scan failed. Check server logs."
            app.logger.error(
                "Scan %s failed; executable=%s python=%s error_type=%s error=%s\n%s",
                scan_id, app.config.get("PROWLER_EXECUTABLE") or "auto-detect",
                __import__("sys").executable, type(exc).__name__, str(exc),
                traceback.format_exc(),
            )
        finally:
            try:
                if scan is not None:
                    if scan.finished_at is None:
                        scan.finished_at = utcnow()
                    db.session.commit()
            except Exception:
                app.logger.exception("Could not commit final state for scan %s.", scan_id)
