from providers import GUID_RE, BaseProvider, ProviderError


class AzureProvider(BaseProvider):
    name = "azure"
    label = "Microsoft Azure"
    fields = ("tenant_id", "client_id", "client_secret", "subscription_id")

    def validate(self, creds):
        for key, label in (("tenant_id", "Tenant ID"), ("client_id", "Client ID"),
                           ("subscription_id", "Subscription ID")):
            if not GUID_RE.match(creds.get(key, "")):
                raise ProviderError(f"{label} must be a GUID.")
        if len(creds.get("client_secret", "")) < 8:
            raise ProviderError("Client secret is missing or too short.")

    def identifier(self, creds):
        return creds.get("subscription_id", "")

    def prowler_env(self, creds, workdir):
        return {"AZURE_TENANT_ID": creds["tenant_id"],
                "AZURE_CLIENT_ID": creds["client_id"],
                "AZURE_CLIENT_SECRET": creds["client_secret"]}

    def prowler_args(self, creds, workdir):
        return ["--sp-env-auth", "--subscription-ids", creds["subscription_id"]]
