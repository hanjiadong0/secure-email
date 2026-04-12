from __future__ import annotations

import base64
import json
import secrets
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


E2E_VERSION = "ecc-p256-aesgcm-v1"
E2E_ALGORITHM = "ECDH-P256-HKDF-SHA256-AESGCM"
E2E_CURVE = "P-256"
_WRAP_INFO = b"secure-email-e2e-wrap-v1"


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


@dataclass(slots=True)
class E2EIdentity:
    public_key: str
    private_key_pem: str


def generate_identity() -> E2EIdentity:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return E2EIdentity(public_key=_b64encode(public_key), private_key_pem=private_pem.decode("ascii"))


def _load_private_key(private_key_pem: str):
    return serialization.load_pem_private_key(private_key_pem.encode("ascii"), password=None)


def _load_public_key(public_key: str):
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), _b64decode(public_key))


def _derive_wrap_key(shared_secret: bytes, salt: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=_WRAP_INFO,
    ).derive(shared_secret)


def build_envelope(
    *,
    sender_public_key: str,
    sender_email: str,
    recipient_public_keys: dict[str, str],
    subject: str,
    body_text: str,
) -> dict[str, Any]:
    if sender_email not in recipient_public_keys:
        recipient_public_keys = {**recipient_public_keys, sender_email: sender_public_key}
    payload_key = secrets.token_bytes(32)
    payload_nonce = secrets.token_bytes(12)
    plaintext = json.dumps(
        {"subject": subject, "body_text": body_text},
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    payload_ciphertext = AESGCM(payload_key).encrypt(payload_nonce, plaintext, None)

    ephemeral_private = ec.generate_private_key(ec.SECP256R1())
    ephemeral_public = ephemeral_private.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    recipient_keys: dict[str, dict[str, str]] = {}
    for email, public_key in recipient_public_keys.items():
        shared_secret = ephemeral_private.exchange(ec.ECDH(), _load_public_key(public_key))
        salt = secrets.token_bytes(16)
        wrap_nonce = secrets.token_bytes(12)
        wrap_key = _derive_wrap_key(shared_secret, salt)
        wrapped_key = AESGCM(wrap_key).encrypt(wrap_nonce, payload_key, None)
        recipient_keys[email] = {
            "salt_b64": _b64encode(salt),
            "nonce_b64": _b64encode(wrap_nonce),
            "wrapped_key_b64": _b64encode(wrapped_key),
        }
    return {
        "version": E2E_VERSION,
        "algorithm": E2E_ALGORITHM,
        "curve": E2E_CURVE,
        "ephemeral_public_key": _b64encode(ephemeral_public),
        "payload_nonce_b64": _b64encode(payload_nonce),
        "payload_ciphertext_b64": _b64encode(payload_ciphertext),
        "recipient_keys": recipient_keys,
    }


def decrypt_envelope(*, private_key_pem: str, recipient_email: str, envelope: dict[str, Any]) -> dict[str, str]:
    if envelope.get("version") != E2E_VERSION:
        raise ValueError("Unsupported E2E envelope version.")
    recipient_keys = envelope.get("recipient_keys") or {}
    if recipient_email not in recipient_keys:
        raise ValueError("No wrapped E2E key for this recipient.")
    recipient_entry = recipient_keys[recipient_email]
    private_key = _load_private_key(private_key_pem)
    shared_secret = private_key.exchange(ec.ECDH(), _load_public_key(envelope["ephemeral_public_key"]))
    wrap_key = _derive_wrap_key(shared_secret, _b64decode(recipient_entry["salt_b64"]))
    payload_key = AESGCM(wrap_key).decrypt(
        _b64decode(recipient_entry["nonce_b64"]),
        _b64decode(recipient_entry["wrapped_key_b64"]),
        None,
    )
    plaintext = AESGCM(payload_key).decrypt(
        _b64decode(envelope["payload_nonce_b64"]),
        _b64decode(envelope["payload_ciphertext_b64"]),
        None,
    )
    data = json.loads(plaintext.decode("utf-8"))
    return {
        "subject": str(data.get("subject", "")),
        "body_text": str(data.get("body_text", "")),
    }
