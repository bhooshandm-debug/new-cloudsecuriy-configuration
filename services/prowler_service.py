import glob
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import logging

from flask import current_app, has_app_context
from providers import ProviderError, get_provider

# Prowler exits with 3 when it finishes but found failing checks.
OK_EXIT_CODES = (0, 3)
PASSTHROUGH_ENV = ("PATH", "HOME", "LANG", "LC_ALL", "SYSTEMROOT", "TEMP", "TMP")


def _resolve_executable(configured):
    """Resolve the prowler executable path, handling relative paths."""
    if not configured:
        return ""
    p = Path(configured)
    if p.is_file():
        return str(p.resolve())
    # Try relative to the project root (config.py's BASE_DIR)
    from config import BASE_DIR
    candidate = BASE_DIR / configured
    if candidate.is_file():
        return str(candidate.resolve())
    return ""


def prowler_available():
    configured = (current_app.config.get("PROWLER_EXECUTABLE", "")
                  if has_app_context() else os.getenv("PROWLER_EXECUTABLE", ""))
    if _resolve_executable(configured):
        return True
    try:
        import prowler  # noqa: F401
        return True
    except ImportError:
        return False


def _prowler_command():
    configured = (current_app.config.get("PROWLER_EXECUTABLE", "")
                  if has_app_context() else os.getenv("PROWLER_EXECUTABLE", ""))
    resolved = _resolve_executable(configured)
    if resolved:
        return [resolved]
    # Run via the active Flask Python interpreter (-m prowler) so Windows
    # Application Control does not block prowler.exe.
    return [sys.executable, "-m", "prowler"]


def run_prowler(provider_name, creds, timeout):
    """Run Prowler for one account and return its raw findings (list of dicts).

    Cloud credentials are passed only to the child process. The app's own secrets
    (SECRET_KEY, FERNET_KEY) are never forwarded.
    """
    provider = get_provider(provider_name)
    with tempfile.TemporaryDirectory(prefix="audit-") as workdir:
        os.chmod(workdir, 0o700)
        cmd = [*_prowler_command(), provider.name, *provider.prowler_args(creds, workdir),
               "--output-formats", "json-ocsf", "--output-directory", workdir,
               "--output-filename", "scan", "--no-banner", "--no-color",
               "--region", "us-east-1"]
        env = {k: os.environ[k] for k in PASSTHROUGH_ENV if k in os.environ}
        env.update(provider.prowler_env(creds, workdir))
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUTF8"] = "1"

        # Prevent blank black console window popups on Windows
        creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0

        started = time.monotonic()
        try:
            # Only the structured result files are consumed. Never persist or
            # surface provider output, which can contain account details.
            proc = subprocess.run(cmd, env=env, cwd=workdir, capture_output=True,
                                  text=True, errors="replace", timeout=timeout,
                                  check=False, creationflags=creationflags)
        except FileNotFoundError as exc:
            logging.getLogger(__name__).exception("Prowler executable could not be started: %s; python=%s",
                                                  cmd[0], sys.executable)
            raise ProviderError(f"Prowler executable not found or could not start: {cmd[0]}") from exc
        except subprocess.TimeoutExpired as exc:
            logging.getLogger(__name__).error("Prowler timed out after %ss; executable=%s python=%s; stdout=%s; stderr=%s",
                                              timeout, cmd[0], sys.executable,
                                              _safe_output(exc.stdout), _safe_output(exc.stderr))
            raise ProviderError(f"Prowler scan timed out after {timeout} seconds.") from exc
        except OSError as exc:
            logging.getLogger(__name__).exception("Prowler launch OS error; executable=%s python=%s",
                                                  cmd[0], sys.executable)
            raise ProviderError(f"Prowler could not launch ({exc}). Check executable permissions and Python installation.") from exc
        duration = time.monotonic() - started
        logging.getLogger(__name__).info("Prowler finished executable=%s python=%s returncode=%s duration=%.2fs stdout=%s stderr=%s",
                                         cmd[0], sys.executable, proc.returncode, duration,
                                         _safe_output(proc.stdout), _safe_output(proc.stderr))
        if proc.returncode not in OK_EXIT_CODES:
            detail = (proc.stderr or proc.stdout or "").strip()[-1500:]
            raise ProviderError(f"Prowler exited with code {proc.returncode}. {detail}")

        raw = []
        for path in glob.glob(os.path.join(workdir, "*.json")):
            if os.path.basename(path) == "gcp-sa.json":
                continue  # never parse the credentials file
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            raw.extend(data if isinstance(data, list) else [data])
        return raw


def _safe_output(value):
    """Limit captured process output and redact common credential assignments."""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    value = str(value or "")[-4000:]
    return re.sub(r"(?i)(aws_(?:access_key_id|secret_access_key|session_token)|access_key|secret_key|session_token)(\s*[=:]\s*)[^\s,;]+",
                  r"\1\2[REDACTED]", value)


_DEMO = [
    ("iam_root_mfa_enabled", "Root account has MFA enabled", "critical", "FAIL", "iam", "Enable MFA on the root account."),
    ("storage_public_access", "Storage is not publicly accessible", "high", "FAIL", "storage", "Disable public access on buckets and containers."),
    ("network_ssh_open_world", "SSH is not open to 0.0.0.0/0", "high", "FAIL", "network", "Restrict SSH to known CIDR ranges."),
    ("encryption_at_rest", "Disks are encrypted at rest", "medium", "FAIL", "compute", "Enable encryption with a managed key."),
    ("logging_enabled", "Audit logging is enabled", "medium", "PASS", "logging", ""),
    ("password_policy_strong", "Password policy meets baseline", "low", "FAIL", "iam", "Require 14+ characters and rotation."),
    ("tls_min_version", "TLS 1.2+ enforced", "medium", "PASS", "network", ""),
    ("backup_retention", "Backups retained 30+ days", "low", "PASS", "database", ""),
    ("key_rotation", "Encryption keys rotate yearly", "informational", "MANUAL", "kms", "Verify the rotation schedule."),
]


def demo_findings(provider_name):
    """Deterministic sample data so the app can be explored without cloud access."""
    return [{"check_id": c, "title": t, "severity": s, "status": st, "service": svc,
             "region": "global", "resource": f"{provider_name}-demo/{c}",
             "detail": "Sample finding (demo mode).", "remediation": rem}
            for c, t, s, st, svc, rem in _DEMO]