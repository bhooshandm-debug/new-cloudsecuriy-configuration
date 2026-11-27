from models import db, utcnow


class CloudAccount(db.Model):
    __tablename__ = "cloud_accounts"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    provider = db.Column(db.String(10), nullable=False)  # aws | azure | gcp
    name = db.Column(db.String(80), nullable=False)
    identifier = db.Column(db.String(120), nullable=False, default="")  # account/sub/project id
    encrypted_credentials = db.Column(db.Text, nullable=False)  # Fernet token, never plaintext
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    scans = db.relationship("Scan", backref="account", lazy="dynamic",
                            cascade="all, delete-orphan")
