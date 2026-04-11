from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from common.utils import ensure_directory


@dataclass(slots=True)
class DomainConfig:
    domain: str
    data_root: Path
    peer_domains: dict[str, str]
    host: str = "127.0.0.1"
    port: int = 8443
    session_ttl_minutes: int = 30
    recall_window_minutes: int = 5
    login_max_attempts: int = 5
    login_window_seconds: int = 300
    lockout_seconds: int = 300
    send_rate_limit_per_minute: int = 30
    upload_rate_limit_bytes_per_minute: int = 15 * 1024 * 1024
    max_attachment_bytes: int = 5 * 1024 * 1024
    action_secret: str = "change-me-for-demo"
    relay_secret: str = "change-me-relay-secret"
    data_encryption_key: str | None = None
    smart_backend: str = "heuristic"
    smart_local_only: bool = True
    smart_prompt_max_chars: int = 3200
    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_model: str | None = None
    ollama_vision_model: str | None = None
    ollama_timeout_seconds: float = 6.0
    hf_text_model: str | None = None
    hf_vision_model: str | None = None
    hf_device: str = "cpu"
    ssl_certfile: str | None = None
    ssl_keyfile: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, mapping: dict[str, Any]) -> "DomainConfig":
        data_root = Path(mapping["data_root"])
        if not data_root.is_absolute():
            data_root = (Path.cwd() / data_root).resolve()
        raw = dict(mapping)
        raw["data_root"] = data_root
        known = {
            "domain",
            "data_root",
            "peer_domains",
            "host",
            "port",
            "session_ttl_minutes",
            "recall_window_minutes",
            "login_max_attempts",
            "login_window_seconds",
            "lockout_seconds",
            "send_rate_limit_per_minute",
            "upload_rate_limit_bytes_per_minute",
            "max_attachment_bytes",
            "action_secret",
            "relay_secret",
            "data_encryption_key",
            "smart_backend",
            "smart_local_only",
            "smart_prompt_max_chars",
            "ollama_base_url",
            "ollama_model",
            "ollama_vision_model",
            "ollama_timeout_seconds",
            "hf_text_model",
            "hf_vision_model",
            "hf_device",
            "ssl_certfile",
            "ssl_keyfile",
        }
        extra = {key: value for key, value in raw.items() if key not in known}
        cfg = cls(
            domain=raw["domain"],
            data_root=raw["data_root"],
            peer_domains=dict(raw.get("peer_domains", {})),
            host=raw.get("host", "127.0.0.1"),
            port=int(raw.get("port", 8443)),
            session_ttl_minutes=int(raw.get("session_ttl_minutes", 30)),
            recall_window_minutes=int(raw.get("recall_window_minutes", 5)),
            login_max_attempts=int(raw.get("login_max_attempts", 5)),
            login_window_seconds=int(raw.get("login_window_seconds", 300)),
            lockout_seconds=int(raw.get("lockout_seconds", 300)),
            send_rate_limit_per_minute=int(raw.get("send_rate_limit_per_minute", 30)),
            upload_rate_limit_bytes_per_minute=int(
                raw.get("upload_rate_limit_bytes_per_minute", 15 * 1024 * 1024)
            ),
            max_attachment_bytes=int(raw.get("max_attachment_bytes", 5 * 1024 * 1024)),
            action_secret=str(raw.get("action_secret", "change-me-for-demo")),
            relay_secret=str(raw.get("relay_secret", "change-me-relay-secret")),
            data_encryption_key=raw.get("data_encryption_key"),
            smart_backend=str(raw.get("smart_backend", "heuristic")),
            smart_local_only=bool(raw.get("smart_local_only", True)),
            smart_prompt_max_chars=int(raw.get("smart_prompt_max_chars", 3200)),
            ollama_base_url=str(raw.get("ollama_base_url", "http://127.0.0.1:11434")),
            ollama_model=raw.get("ollama_model"),
            ollama_vision_model=raw.get("ollama_vision_model"),
            ollama_timeout_seconds=float(raw.get("ollama_timeout_seconds", 6.0)),
            hf_text_model=raw.get("hf_text_model"),
            hf_vision_model=raw.get("hf_vision_model"),
            hf_device=str(raw.get("hf_device", "cpu")),
            ssl_certfile=raw.get("ssl_certfile"),
            ssl_keyfile=raw.get("ssl_keyfile"),
            extra=extra,
        )
        cfg.ensure_layout()
        return cfg

    @classmethod
    def from_file(cls, path: str | Path) -> "DomainConfig":
        with Path(path).open("r", encoding="utf-8") as handle:
            content = yaml.safe_load(handle) or {}
        return cls.from_mapping(content)

    def ensure_layout(self) -> None:
        ensure_directory(self.data_root)
        ensure_directory(self.data_root / "users")
        ensure_directory(self.data_root / "mail")
        ensure_directory(self.data_root / "attachments" / "blobs")
        ensure_directory(self.data_root / "logs")
