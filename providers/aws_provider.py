import re

from providers import BaseProvider, ProviderError

KEY_ID_RE = re.compile(r"^(AKIA|ASIA)[A-Z0-9]{16}$")
ROLE_RE = re.compile(r"^arn:aws[a-z-]*:iam::(\d{12}):role/[\w+=,.@/-]+$")


class AWSProvider(BaseProvider):
    name = "aws"
    label = "Amazon Web Services"
    fields = ("access_key_id", "secret_access_key", "session_token", "role_arn")

    def validate(self, creds):
        if not KEY_ID_RE.match(creds.get("access_key_id", "")):
            raise ProviderError("AWS access key ID looks invalid.")
        if len(creds.get("secret_access_key", "")) != 40:
            raise ProviderError("AWS secret access key must be 40 characters.")
        role = creds.get("role_arn", "")
        if role and not ROLE_RE.match(role):
            raise ProviderError("Role ARN looks invalid.")

    def identifier(self, creds):
        m = ROLE_RE.match(creds.get("role_arn", ""))
        return m.group(1) if m else ""

    def verify_live(self, creds):
        try:
            import boto3
            from botocore.exceptions import BotoCoreError, ClientError
        except ImportError:  # boto3 not installed
            return None
        try:
            kwargs = dict(aws_access_key_id=creds["access_key_id"],
                          aws_secret_access_key=creds["secret_access_key"])
            if creds.get("session_token"):
                kwargs["aws_session_token"] = creds["session_token"]
            return boto3.client("sts", **kwargs).get_caller_identity()["Account"]
        except (BotoCoreError, ClientError):
            raise ProviderError("AWS rejected these credentials.")

    def prowler_env(self, creds, workdir):
        env = {"AWS_ACCESS_KEY_ID": creds["access_key_id"],
               "AWS_SECRET_ACCESS_KEY": creds["secret_access_key"]}
        if creds.get("session_token"):
            env["AWS_SESSION_TOKEN"] = creds["session_token"]
        return env

    def prowler_args(self, creds, workdir):
        return ["-R", creds["role_arn"]] if creds.get("role_arn") else []
