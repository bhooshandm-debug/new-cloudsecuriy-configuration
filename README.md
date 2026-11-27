# Cloud Security Configuration Audit

Flask app that connects AWS / Azure / GCP accounts (read-only credentials), runs
[Prowler](https://github.com/prowler-cloud/prowler) configuration scans, and shows
findings, dashboards and downloadable reports.

## Run it
```bash
python -m venv venv && source venv/bin/activate     # Windows: venv\Scripts\activate
pip install -r requirements-dev.txt
uv tool install prowler --python 3.13                # optional; required for full real cloud scans
python app.py                                         # http://127.0.0.1:5000
pytest                                                # run the tests
```
`SCAN_MODE=auto` requires Prowler and will report an installation error if it is missing. Set
`SCAN_MODE=demo` only when you explicitly want sample findings. Prowler supports Python 3.10–3.13;
the app can find it on `PATH` or via `PROWLER_EXECUTABLE` in `.env`.
The first account you register becomes the administrator.

For AWS accounts, **Quick scan (~1 min)** runs a focused baseline check with a 45-second check
budget (IAM, S3, security groups, EBS encryption, and CloudTrail in `us-east-1`). It is designed for
fast feedback and may stop before checking every resource in a large account. Use **Full scan** to
run Prowler's broader audit. Quick scans are currently available for AWS only.

## CloudSec AI Assistant
Install the pinned-compatible Google GenAI SDK with `pip install -r requirements.txt`. Add a Gemini API key to the root `.env` file (create a key in Google AI Studio):

```dotenv
GEMINI_API_KEY=your_real_key_here
GEMINI_MODEL=gemini-3.6-flash
```

Restart the Flask app, sign in, then open `http://127.0.0.1:5000/assistant/`. The assistant also appears on the dashboard. Its API key stays on the server. Each request includes up to 60 failed findings from the latest completed scan per visible account, scoped using this app's existing account visibility rules. Gemini receives finding details, including affected resource identifiers, to explain what is wrong and suggest a fix; cloud credentials are never included. Chat history is held in the browser's local storage. Clear it from the assistant page or dashboard. The app does not make cloud changes.

Gemini replies require an internet connection and a configured API key; provider quota, model availability, and billing are controlled by Google. General security guidance is also sent to Gemini. Do not include secrets in chat messages.

## Before real use
- Regenerate the keys in `.env` (they are only for local development):
  - `python -c "import secrets;print(secrets.token_hex(32))"` -> `SECRET_KEY`
  - `python -c "from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())"` -> `FERNET_KEY`
  - Losing `FERNET_KEY` makes stored cloud credentials unreadable.
- Serve behind HTTPS and set `SESSION_COOKIE_SECURE=true`. Use gunicorn, not the dev server.
- Use read-only cloud roles only: AWS `SecurityAudit`, Azure `Reader` + `Security Reader`, GCP `Viewer` + `Security Reviewer`.
- Only scan accounts you are authorised to audit.
- For production, swap SQLite for PostgreSQL (`DATABASE_URL`) and run scans in a worker queue (Celery/RQ) instead of threads.

## Layout
`routes/` HTTP handlers · `services/` business logic · `providers/` per-cloud credential handling ·
`models/` database tables · `templates/` + `static/` UI · `reports/` generated files · `tests/` pytest suite.
Extra files vs. your tree: `services/crypto.py`, `__init__.py` package files, `tests/conftest.py`, `pytest.ini`, `README.md`.
