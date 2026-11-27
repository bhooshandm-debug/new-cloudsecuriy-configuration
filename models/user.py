from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from models import db, utcnow


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(10), nullable=False, default="user")  # user | admin
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    accounts = db.relationship("CloudAccount", backref="owner", lazy="dynamic",
                               cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method="scrypt:32768:8:1")

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self):
        return self.role == "admin"
