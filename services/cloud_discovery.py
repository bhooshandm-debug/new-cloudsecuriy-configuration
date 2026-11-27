from flask import current_app

from models import db
from models.cloud_account import CloudAccount
from providers import ProviderError, get_provider
from services.crypto import encrypt_json


def register_account(user, provider_name, display_name, form):
    """Validate credentials, optionally verify them live, and store them encrypted."""
    display_name = (display_name or "").strip()
    if not 1 <= len(display_name) <= 80:
        raise ProviderError("Give the account a name (up to 80 characters).")

    provider = get_provider(provider_name)
    creds = provider.collect(form)
    provider.validate(creds)

    identifier = provider.identifier(creds)
    if current_app.config.get("VERIFY_CREDENTIALS_LIVE"):
        identifier = provider.verify_live(creds) or identifier

    account = CloudAccount(user_id=user.id, provider=provider.name, name=display_name,
                           identifier=identifier or "", encrypted_credentials=encrypt_json(creds))
    db.session.add(account)
    db.session.commit()
    return account
