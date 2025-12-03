import secrets
import hashlib
import hmac
import uuid
from django.conf import settings
from django.utils import timezone
from datetime import timedelta


def generate_reset_token():
    return secrets.token_hex(32)


def hash_refresh_token(token_plain: str) -> str:
    secret = settings.REFRESH_TOKEN_HASH_SECRET.encode()
    return hmac.new(secret, token_plain.encode(), hashlib.sha256).hexdigest()


def generate_jti() -> str:
    return secrets.token_hex(16)


def default_refresh_expiry(now=None):
    now = now or timezone.now()
    return now + timedelta(days=14)