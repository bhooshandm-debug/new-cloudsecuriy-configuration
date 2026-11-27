import json
import os

from providers import BaseProvider, ProviderError


class GCPProvider(BaseProvider):
    name = "gcp"
    label = "Google Cloud"
    fields = ("service_account_json",)

    def collect(self, form):
        raw = (form.get("gcp_service_account_json") or "").strip()
        try:
            data = json.loads(raw)
        except ValueError:
            raise ProviderError("Service account key must be valid JSON.")
        if not isinstance(data, dict):
            raise ProviderError("Service account key must be a JSON object.")
        return data

    def validate(self, creds):
        if creds.get("type") != "service_account":
            raise ProviderError('Key must have "type": "service_account".')
        for key in ("project_id", "private_key", "client_email"):
            if not creds.get(key):
                raise ProviderError(f'Service account key is missing "{key}".')

    def identifier(self, creds):
        return creds.get("project_id", "")

    def _key_path(self, creds, workdir):
        import json as _json
        path = os.path.join(workdir, "gcp-sa.json")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            _json.dump(creds, fh)
        return path

    def prowler_args(self, creds, workdir):
        return ["--credentials-file", self._key_path(creds, workdir),
                "--project-ids", creds["project_id"]]
