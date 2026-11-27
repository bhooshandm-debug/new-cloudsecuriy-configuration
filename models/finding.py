from models import db


class Finding(db.Model):
    __tablename__ = "findings"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False, index=True)
    check_id = db.Column(db.String(200), nullable=False, default="")
    title = db.Column(db.String(300), nullable=False, default="")
    severity = db.Column(db.String(15), nullable=False, default="informational", index=True)
    severity_rank = db.Column(db.Integer, nullable=False, default=0)  # for sorting
    status = db.Column(db.String(10), nullable=False, default="UNKNOWN", index=True)  # PASS|FAIL|MANUAL|UNKNOWN
    service = db.Column(db.String(80), default="")
    region = db.Column(db.String(60), default="")
    resource = db.Column(db.String(500), default="")
    detail = db.Column(db.Text, default="")
    remediation = db.Column(db.Text, default="")

    def to_dict(self):
        return {
            "id": self.id, "scan_id": self.scan_id, "check_id": self.check_id,
            "title": self.title, "severity": self.severity, "status": self.status,
            "service": self.service, "region": self.region, "resource": self.resource,
            "detail": self.detail, "remediation": self.remediation,
        }
