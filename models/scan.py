from models import db, utcnow


class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    account_id = db.Column(db.Integer, db.ForeignKey("cloud_accounts.id"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    status = db.Column(db.String(12), nullable=False, default="pending")  # pending|running|completed|failed
    mode = db.Column(db.String(10), nullable=False, default="prowler")  # prowler | demo
    error = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    started_at = db.Column(db.DateTime)
    finished_at = db.Column(db.DateTime)
    total_findings = db.Column(db.Integer, default=0)
    passed_findings = db.Column(db.Integer, default=0)
    failed_findings = db.Column(db.Integer, default=0)

    findings = db.relationship("Finding", backref="scan", lazy="dynamic",
                               cascade="all, delete-orphan")

    @property
    def active(self):
        return self.status in ("pending", "running")
