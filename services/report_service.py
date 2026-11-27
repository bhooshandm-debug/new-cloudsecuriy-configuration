import csv
import html
import json
import os

from flask import current_app

from models import utcnow

FORMATS = ("csv", "json", "html")
COLUMNS = ("severity", "status", "service", "region", "resource", "check_id", "title", "remediation")


def _safe_cell(value):
    """Neutralise spreadsheet formula injection."""
    value = "" if value is None else str(value)
    return "'" + value if value[:1] in ("=", "+", "-", "@", "\t", "\r") else value


def generate_report(scan, fmt):
    if fmt not in FORMATS:
        raise ValueError("Unsupported report format.")
    findings = [f.to_dict() for f in scan.findings.order_by(None).all()]
    findings.sort(key=lambda f: ("FAIL" != f["status"], -["informational", "low", "medium", "high", "critical"].index(f["severity"])))

    folder = os.path.abspath(current_app.config["REPORTS_DIR"])
    os.makedirs(folder, exist_ok=True)
    filename = f"scan_{int(scan.id)}_{utcnow():%Y%m%d_%H%M%S}.{fmt}"  # no user-controlled input
    path = os.path.join(folder, filename)

    if fmt == "csv":
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(COLUMNS)
            for f in findings:
                writer.writerow([_safe_cell(f[c]) for c in COLUMNS])
    elif fmt == "json":
        meta = {"scan_id": scan.id, "account": scan.account.name, "provider": scan.account.provider,
                "status": scan.status, "total": scan.total_findings, "failed": scan.failed_findings}
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"scan": meta, "findings": findings}, fh, indent=2)
    else:
        rows = "".join(
            "<tr>" + "".join(f"<td>{html.escape(str(f[c]))}</td>" for c in COLUMNS) + "</tr>"
            for f in findings)
        head = "".join(f"<th>{c}</th>" for c in COLUMNS)
        doc = (f"<!doctype html><meta charset='utf-8'><title>Scan {scan.id}</title>"
               "<style>body{font:14px system-ui;margin:2rem}table{border-collapse:collapse}"
               "td,th{border:1px solid #ccc;padding:4px 8px;text-align:left}</style>"
               f"<h1>Audit report: {html.escape(scan.account.name)}</h1>"
               f"<p>{scan.failed_findings} failed of {scan.total_findings} checks.</p>"
               f"<table><tr>{head}</tr>{rows}</table>")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(doc)
    return path
