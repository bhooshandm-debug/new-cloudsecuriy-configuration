import json
import re


class ProviderError(Exception):
    """Raised when credentials are missing, malformed, or rejected."""


class BaseProvider:
    name = ""
    label = ""
    fields = ()  # field keys read from the form as "<name>_<key>"

    def collect(self, form):
        return {k: (form.get(f"{self.name}_{k}") or "").strip() for k in self.fields}

    def validate(self, creds):
        raise NotImplementedError

    def verify_live(self, creds):
        """Optional online check. Returns an account identifier or None."""
        return None

    def identifier(self, creds):
        return ""

    def prowler_args(self, creds, workdir):
        return []

    def prowler_env(self, creds, workdir):
        return {}


def get_provider(name):
    from providers.aws_provider import AWSProvider
    from providers.azure_provider import AzureProvider
    from providers.gcp_provider import GCPProvider

    registry = {p.name: p for p in (AWSProvider(), AzureProvider(), GCPProvider())}
    try:
        return registry[(name or "").lower()]
    except KeyError:
        raise ProviderError("Unsupported cloud provider.")


def supported_providers():
    return [("aws", "Amazon Web Services"), ("azure", "Microsoft Azure"),
            ("gcp", "Google Cloud")]


GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
