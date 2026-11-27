import json

import pytest

from providers import ProviderError, get_provider

GUID = "12345678-1234-1234-1234-123456789abc"


def test_unknown_provider():
    with pytest.raises(ProviderError):
        get_provider("oracle")


def test_aws_validation():
    p = get_provider("aws")
    p.validate({"access_key_id": "AKIAABCDEFGHIJKLMNOP", "secret_access_key": "a" * 40})
    with pytest.raises(ProviderError):
        p.validate({"access_key_id": "nope", "secret_access_key": "a" * 40})
    with pytest.raises(ProviderError):
        p.validate({"access_key_id": "AKIAABCDEFGHIJKLMNOP", "secret_access_key": "short"})
    assert p.identifier({"role_arn": "arn:aws:iam::123456789012:role/Auditor"}) == "123456789012"


def test_azure_validation():
    p = get_provider("azure")
    good = {"tenant_id": GUID, "client_id": GUID, "client_secret": "s" * 12, "subscription_id": GUID}
    p.validate(good)
    with pytest.raises(ProviderError):
        p.validate({**good, "tenant_id": "not-a-guid"})
    assert "--sp-env-auth" in p.prowler_args(good, "/tmp")


def test_gcp_validation_and_key_file():
    p = get_provider("gcp")
    key = {"type": "service_account", "project_id": "proj", "private_key": "k", "client_email": "a@b.c"}
    creds = p.collect({"gcp_service_account_json": json.dumps(key)})
    p.validate(creds)
    from pathlib import Path
    workdir = Path("reports")
    args = p.prowler_args(creds, str(workdir))
    path = args[args.index("--credentials-file") + 1]
    import os
    if os.name != "nt":
        assert oct((workdir / "gcp-sa.json").stat().st_mode & 0o777) == "0o600"
    (workdir / "gcp-sa.json").unlink(missing_ok=True)
    assert path.endswith("gcp-sa.json")
    with pytest.raises(ProviderError):
        p.collect({"gcp_service_account_json": "{not json"})
