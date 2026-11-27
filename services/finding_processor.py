from models import db
from models.finding import Finding
from services.authentication import visible_accounts

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
SEVERITY_ALIASES = {"info": "informational", "informative": "informational"}
STATUSES = {"PASS", "FAIL", "MANUAL"}


def _get(data, *path, default=""):
    """Walk nested dicts; if a list is met, use its first element (OCSF 'resources')."""
    for key in path:
        if isinstance(data, list):
            data = data[0] if data else None
        if not isinstance(data, dict):
            return default
        data = data.get(key)
        if data is None:
            return default
    if isinstance(data, list):
        data = data[0] if data else default
    return data


def normalize(raw):
    """Map a Prowler OCSF / legacy JSON record, or our demo record, to Finding fields."""
    check_id = (raw.get("check_id") or _get(raw, "metadata", "event_code")
                or raw.get("CheckID") or _get(raw, "finding_info", "uid"))
    severity = str(raw.get("severity") or raw.get("Severity") or "").lower()
    severity = SEVERITY_ALIASES.get(severity, severity)
    if severity not in SEVERITY_RANK:
        severity = "informational"

    status = str(raw.get("status") or raw.get("status_code") or raw.get("Status") or "").upper()
    if status not in STATUSES:
        status = "UNKNOWN"

    return {
        "check_id": str(check_id or "")[:200],
        "title": str(raw.get("title") or _get(raw, "finding_info", "title")
                     or raw.get("CheckTitle") or check_id or "")[:300],
        "severity": severity,
        "severity_rank": SEVERITY_RANK[severity],
        "status": status,
        "service": str(raw.get("service") or _get(raw, "resources", "group", "name")
                       or raw.get("ServiceName") or "")[:80],
        "region": str(raw.get("region") or _get(raw, "resources", "region")
                      or _get(raw, "cloud", "region") or raw.get("Region") or "")[:60],
        "resource": str(raw.get("resource") or _get(raw, "resources", "uid")
                        or raw.get("ResourceId") or "")[:500],
        "detail": str(raw.get("detail") or raw.get("status_detail") or raw.get("StatusExtended")
                      or raw.get("message") or ""),
        "remediation": str(raw.get("remediation") if isinstance(raw.get("remediation"), str)
                           else _get(raw, "remediation", "desc")
                           or _get(raw, "Remediation", "Recommendation", "Text")),
    }


def process_and_store(scan, raw_findings):
    seen = set()
    for raw in raw_findings:
        data = normalize(raw)
        key = (data["check_id"], data["resource"], data["region"])
        if key in seen:
            continue
        seen.add(key)
        db.session.add(Finding(scan_id=scan.id, **data))
    db.session.flush()

    counts = dict(db.session.query(Finding.status, db.func.count())
                  .filter(Finding.scan_id == scan.id).group_by(Finding.status).all())
    scan.total_findings = sum(counts.values())
    scan.passed_findings = counts.get("PASS", 0)
    scan.failed_findings = counts.get("FAIL", 0)


def dashboard_stats(user):
    """Failed-finding counts by severity, using each account's latest completed scan."""
    from models.scan import Scan

    accounts = visible_accounts(user).all()
    providers = {name: {"accounts": 0, "scanned_accounts": 0, "failed_total": 0}
                 for name in ("aws", "azure", "gcp")}
    severities = {name: 0 for name in SEVERITY_RANK}
    latest_ids = []
    for acc in accounts:
        if acc.provider in providers:
            providers[acc.provider]["accounts"] += 1
        latest = (acc.scans.filter_by(status="completed").order_by(Scan.id.desc()).first())
        if latest:
            latest_ids.append(latest.id)
            if acc.provider in providers:
                providers[acc.provider]["scanned_accounts"] += 1
    if latest_ids:
        rows = (db.session.query(Finding.severity, db.func.count())
                .filter(Finding.scan_id.in_(latest_ids), Finding.status == "FAIL")
                .group_by(Finding.severity).all())
        for sev, n in rows:
            severities[sev] = n
        provider_rows = (db.session.query(Scan.account_id, db.func.count(Finding.id))
                         .join(Finding, Finding.scan_id == Scan.id)
                         .filter(Scan.id.in_(latest_ids), Finding.status == "FAIL")
                         .group_by(Scan.account_id).all())
        account_provider = {acc.id: acc.provider for acc in accounts}
        for account_id, count in provider_rows:
            provider = account_provider.get(account_id)
            if provider in providers:
                providers[provider]["failed_total"] += count
    return {"accounts": len(accounts), "scanned_accounts": len(latest_ids),
            "failed_total": sum(severities.values()), "severities": severities,
            "providers": providers}


def _key(f):
    return (f["check_id"], f["resource"], f["region"])


def diff_findings(old, new):
    """Compare two lists of finding dicts. Only FAIL findings count as open issues.

    new_issues:  failing now, but not failing in the older scan
    resolved:    failing in the older scan, passing now ('PASS') or not reported now ('gone')
    persisting:  failing in both scans
    """
    old_fail = {_key(f): f for f in old if f["status"] == "FAIL"}
    new_fail = {_key(f): f for f in new if f["status"] == "FAIL"}
    new_status = {_key(f): f["status"] for f in new}

    by_severity = lambda f: (-SEVERITY_RANK.get(f["severity"], 0), f["title"])
    new_issues = sorted((f for k, f in new_fail.items() if k not in old_fail), key=by_severity)
    resolved = sorted(({**f, "now": "Passing" if new_status.get(k) == "PASS" else "No longer reported"}
                       for k, f in old_fail.items() if k not in new_fail), key=by_severity)
    persisting = sorted((f for k, f in new_fail.items() if k in old_fail), key=by_severity)
    return {"new_issues": new_issues, "resolved": resolved, "persisting": persisting}


def compare_scans(base, target):
    """Diff two scans of the same account (base = older, target = newer)."""
    load = lambda scan: [f.to_dict() for f in Finding.query.filter_by(scan_id=scan.id).all()]
    return diff_findings(load(base), load(target))
