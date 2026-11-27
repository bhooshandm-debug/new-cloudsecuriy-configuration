import os
from cryptography.fernet import Fernet

from flask import Flask
from flask_login import LoginManager, current_user
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect

from config import Config
from models import db

login_manager = LoginManager()
migrate = Migrate()
csrf = CSRFProtect()


def create_app(config_object=Config):
    app = Flask(__name__)
    app.config.from_object(config_object)

    secret_key = app.config.get("SECRET_KEY")
    fernet_key = app.config.get("FERNET_KEY")
    if not secret_key or (len(secret_key) < 32 and not app.testing):
        raise RuntimeError("SECRET_KEY must be set to a random value of at least 32 characters (see .env).")
    try:
        Fernet(fernet_key.encode())
    except (AttributeError, TypeError, ValueError):
        raise RuntimeError("FERNET_KEY must be a valid Fernet key (see .env).") from None

    os.makedirs(app.config["REPORTS_DIR"], exist_ok=True)

    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message_category = "error"

    # Import models so tables are registered before create_all()
    from models.user import User
    from models import cloud_account, scan, finding, audit_log  # noqa: F401

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    from routes import auth, dashboard, cloud_accounts, scans, findings, reports, admin, assistant, seo

    for module in (auth, dashboard, cloud_accounts, scans, findings, reports, admin, assistant, seo):
        app.register_blueprint(module.bp)

    from flask import render_template
    from flask_wtf.csrf import CSRFError

    @app.errorhandler(404)
    def handle_not_found(e):
        return render_template("errors/404.html"), 404

    @app.errorhandler(403)
    def handle_forbidden(e):
        return render_template("errors/403.html"), 403

    @app.errorhandler(500)
    def handle_server_error(e):
        return render_template("errors/500.html"), 500

    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        return render_template("errors/csrf.html", reason=getattr(e, "description", "CSRF token validation failed")), 400

    @app.after_request
    def security_headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        resp.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        resp.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; base-uri 'self'; form-action 'self'; object-src 'none'; "
            "style-src 'self'; script-src 'self'; frame-ancestors 'none'",
        )
        if app.config.get("SESSION_COOKIE_SECURE"):
            resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        if current_user and current_user.is_authenticated:
            resp.headers.setdefault("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0, private")
            resp.headers.setdefault("Pragma", "no-cache")
        return resp

    with app.app_context():
        db.create_all()

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000,
                     debug=False)
