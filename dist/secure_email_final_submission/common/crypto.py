from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from common.utils import json_dumps


PASSWORD_HASHER = PasswordHasher(
    time_cost=2,
    memory_cost=19 * 1024,
    parallelism=1,
    hash_len=32,
    salt_len=16,
)


def hash_password(password: str) -> str:
    return PASSWORD_HASHER.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return PASSWORD_HASHER.verify(password_hash, password)
    except VerifyMismatchError:
        return False


def new_session_token() -> str:
    return secrets.token_urlsafe(32)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def mac_hex(secret: str, message: str) -> str:
    return hmac.new(secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def sign_payload(secret: str, payload: dict[str, Any]) -> str:
    raw = json_dumps(payload).encode("utf-8")
    signature = hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).digest()
    return f"{_b64encode(raw)}.{_b64encode(signature)}"


def verify_signed_payload(secret: str, token: str) -> dict[str, Any]:
    try:
        raw_part, sig_part = token.split(".", 1)
    except ValueError as exc:
        raise ValueError("Malformed token.") from exc
    raw = _b64decode(raw_part)
    signature = _b64decode(sig_part)
    expected = hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).digest()
    if not hmac.compare_digest(signature, expected):
        raise ValueError("Token signature mismatch.")
    import json

    return json.loads(raw)
