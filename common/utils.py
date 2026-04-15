from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def isoformat_utc(value: datetime | None = None) -> str:
    current = (value or utcnow()).astimezone(timezone.utc).replace(microsecond=0)
    return current.isoformat()


def parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value)


def new_id() -> str:
    return str(uuid4())


def normalize_email(email: str) -> str:
    return email.strip().lower()


def is_valid_email(email: str) -> bool:
    normalized = normalize_email(email)
    return bool(EMAIL_PATTERN.fullmatch(normalized))


def email_domain(email: str) -> str:
    normalized = normalize_email(email)
    if not is_valid_email(normalized):
        raise ValueError(f"Invalid email address: {email}")
    return normalized.rsplit("@", 1)[1]


def json_dumps(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def ensure_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path
