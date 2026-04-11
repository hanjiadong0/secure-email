from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.fernet import Fernet

from common.utils import json_dumps


ENCRYPTED_PREFIX = "enc:v1:"


def _derive_fernet_key(secret: str) -> bytes:
    digest = hashlib.sha256(secret.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


class DataProtector:
    def __init__(self, secret: str) -> None:
        self._fernet = Fernet(_derive_fernet_key(secret))

    def encrypt_text(self, value: str | None) -> str:
        raw = value or ""
        if raw.startswith(ENCRYPTED_PREFIX):
            return raw
        token = self._fernet.encrypt(raw.encode("utf-8")).decode("ascii")
        return f"{ENCRYPTED_PREFIX}{token}"

    def decrypt_text(self, value: str | None) -> str:
        if not value:
            return ""
        if not value.startswith(ENCRYPTED_PREFIX):
            return value
        token = value[len(ENCRYPTED_PREFIX) :].encode("ascii")
        return self._fernet.decrypt(token).decode("utf-8")

    def encrypt_json(self, value: Any) -> str:
        return self.encrypt_text(json_dumps(value))

    def decrypt_json(self, value: str | None) -> Any:
        raw = self.decrypt_text(value)
        if not raw:
            return None
        return json.loads(raw)
