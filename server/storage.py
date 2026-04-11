from __future__ import annotations

import asyncio
import json
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any, Awaitable, Callable

import httpx

from common.config import DomainConfig
from common.data_security import DataProtector
from common.crypto import mac_hex
from common.utils import isoformat_utc, json_dumps, new_id, utcnow


RelayDispatch = Callable[[str, str, dict[str, Any]], Awaitable[dict[str, Any]]]


SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    session_key TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    last_seq_no INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS rate_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bucket TEXT NOT NULL,
    amount INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS lockouts (
    bucket TEXT PRIMARY KEY,
    until_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS request_guards (
    session_token TEXT NOT NULL,
    request_id TEXT NOT NULL,
    nonce TEXT NOT NULL,
    seq_no INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(session_token, request_id),
    UNIQUE(session_token, nonce)
);

CREATE TABLE IF NOT EXISTS relay_guards (
    source_domain TEXT NOT NULL,
    nonce TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(source_domain, nonce)
);

CREATE TABLE IF NOT EXISTS attachment_blobs (
    blob_key TEXT PRIMARY KEY,
    path TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    ref_count INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS attachments (
    id TEXT PRIMARY KEY,
    blob_key TEXT NOT NULL,
    filename TEXT NOT NULL,
    content_type TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    analysis_json TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS mail_items (
    mailbox_item_id TEXT PRIMARY KEY,
    message_id TEXT NOT NULL,
    thread_id TEXT NOT NULL,
    owner_email TEXT NOT NULL,
    folder TEXT NOT NULL,
    delivery_state TEXT NOT NULL DEFAULT 'delivered',
    from_email TEXT NOT NULL,
    to_json TEXT NOT NULL,
    cc_json TEXT NOT NULL,
    subject TEXT NOT NULL,
    body_text TEXT NOT NULL,
    attachments_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    security_flags_json TEXT NOT NULL,
    actions_json TEXT NOT NULL,
    quick_replies_json TEXT NOT NULL,
    keywords_json TEXT NOT NULL,
    classification TEXT NOT NULL,
    recalled INTEGER NOT NULL DEFAULT 0,
    recall_status TEXT,
    is_read INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_mail_items_owner_folder ON mail_items(owner_email, folder, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_mail_items_owner_message ON mail_items(owner_email, message_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_mail_items_owner_folder_message ON mail_items(owner_email, folder, message_id);

CREATE TABLE IF NOT EXISTS mail_attachment_links (
    mailbox_item_id TEXT NOT NULL,
    owner_email TEXT NOT NULL,
    attachment_id TEXT NOT NULL,
    PRIMARY KEY(mailbox_item_id, attachment_id)
);

CREATE TABLE IF NOT EXISTS groups_store (
    name TEXT NOT NULL,
    owner_email TEXT NOT NULL,
    members_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(name, owner_email)
);

CREATE TABLE IF NOT EXISTS todos (
    id TEXT PRIMARY KEY,
    owner_email TEXT NOT NULL,
    message_id TEXT NOT NULL,
    title TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS contacts (
    owner_email TEXT NOT NULL,
    contact_email TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    source TEXT NOT NULL,
    PRIMARY KEY(owner_email, contact_email)
);

CREATE TABLE IF NOT EXISTS job_queue (
    job_id TEXT PRIMARY KEY,
    job_type TEXT NOT NULL,
    message_id TEXT,
    owner_email TEXT,
    status TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    available_at TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_job_queue_status_type_available
    ON job_queue(status, job_type, available_at, created_at);
"""


@dataclass(slots=True)
class AppContext:
    config: DomainConfig
    relay_dispatch: RelayDispatch | None = None
    db_path: Path = field(init=False)
    log_path: Path = field(init=False)
    alert_path: Path = field(init=False)
    data_protector: DataProtector = field(init=False, repr=False)
    stop_event: threading.Event = field(init=False, repr=False)
    worker_threads: list[threading.Thread] = field(init=False, repr=False)
    workers_started: bool = field(init=False, default=False)

    def __post_init__(self) -> None:
        self.config.ensure_layout()
        self.db_path = self.config.data_root / "mail" / "mailstore.sqlite3"
        self.log_path = self.config.data_root / "logs" / "security.jsonl"
        self.alert_path = self.config.data_root / "logs" / "alerts.jsonl"
        data_secret = self.config.data_encryption_key or (
            f"{self.config.domain}:{self.config.action_secret}:{self.config.relay_secret}"
        )
        self.data_protector = DataProtector(data_secret)
        self.stop_event = threading.Event()
        self.worker_threads = []
        self._init_db()

    def _init_db(self) -> None:
        with self.connect() as conn:
            conn.executescript(SCHEMA)
            columns = {row["name"] for row in conn.execute("PRAGMA table_info(sessions)").fetchall()}
            if "session_key" not in columns:
                conn.execute("ALTER TABLE sessions ADD COLUMN session_key TEXT DEFAULT ''")
            if "last_seq_no" not in columns:
                conn.execute("ALTER TABLE sessions ADD COLUMN last_seq_no INTEGER NOT NULL DEFAULT 0")
            attachment_columns = {row["name"] for row in conn.execute("PRAGMA table_info(attachments)").fetchall()}
            if "analysis_json" not in attachment_columns:
                conn.execute("ALTER TABLE attachments ADD COLUMN analysis_json TEXT NOT NULL DEFAULT ''")
            mail_columns = {row["name"] for row in conn.execute("PRAGMA table_info(mail_items)").fetchall()}
            if "delivery_state" not in mail_columns:
                conn.execute("ALTER TABLE mail_items ADD COLUMN delivery_state TEXT NOT NULL DEFAULT 'delivered'")
            conn.execute(
                "UPDATE job_queue SET status = 'pending', updated_at = ? WHERE status = 'in_progress'",
                (isoformat_utc(),),
            )

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    @property
    def blobs_root(self) -> Path:
        return self.config.data_root / "attachments" / "blobs"

    def encrypt_text(self, value: str | None) -> str:
        return self.data_protector.encrypt_text(value)

    def decrypt_text(self, value: str | None) -> str:
        return self.data_protector.decrypt_text(value)

    def encrypt_json(self, value: Any) -> str:
        return self.data_protector.encrypt_json(value)

    def decrypt_json(self, value: str | None) -> Any:
        return self.data_protector.decrypt_json(value)

    def relay_post_sync(self, domain: str, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        if domain not in self.config.peer_domains:
            raise KeyError(f"Unknown peer domain: {domain}")
        if self.relay_dispatch is not None:
            return asyncio.run(self.relay_dispatch(domain, path, payload))
        base_url = self.config.peer_domains[domain].rstrip("/")
        timestamp = str(int(utcnow().timestamp()))
        nonce = new_id()
        canonical = json_dumps(
            {
                "method": "POST",
                "path": path,
                "source_domain": self.config.domain,
                "timestamp": timestamp,
                "nonce": nonce,
                "body": payload,
            }
        )
        with httpx.Client(base_url=base_url, timeout=20, verify=False) as client:
            response = client.post(
                path,
                json=payload,
                headers={
                    "X-Relay-Domain": self.config.domain,
                    "X-Relay-Timestamp": timestamp,
                    "X-Relay-Nonce": nonce,
                    "X-Relay-Mac": mac_hex(self.config.relay_secret, canonical),
                },
            )
            response.raise_for_status()
            if response.headers.get("content-type", "").startswith("application/json"):
                return response.json()
            return {"status": "ok"}

    async def relay_post(self, domain: str, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        if domain not in self.config.peer_domains:
            raise KeyError(f"Unknown peer domain: {domain}")
        if self.relay_dispatch is not None:
            return await self.relay_dispatch(domain, path, payload)
        base_url = self.config.peer_domains[domain].rstrip("/")
        timestamp = str(int(utcnow().timestamp()))
        nonce = new_id()
        canonical = json_dumps(
            {
                "method": "POST",
                "path": path,
                "source_domain": self.config.domain,
                "timestamp": timestamp,
                "nonce": nonce,
                "body": payload,
            }
        )
        async with httpx.AsyncClient(base_url=base_url, timeout=20, verify=False) as client:
            response = await client.post(
                path,
                json=payload,
                headers={
                    "X-Relay-Domain": self.config.domain,
                    "X-Relay-Timestamp": timestamp,
                    "X-Relay-Nonce": nonce,
                    "X-Relay-Mac": mac_hex(self.config.relay_secret, canonical),
                },
            )
            response.raise_for_status()
            if response.headers.get("content-type", "").startswith("application/json"):
                return response.json()
            return {"status": "ok"}

    def enqueue_job(
        self,
        job_type: str,
        payload: dict[str, Any],
        *,
        message_id: str | None = None,
        owner_email: str | None = None,
        available_at: str | None = None,
        max_attempts: int = 3,
    ) -> str:
        job_id = new_id()
        created_at = isoformat_utc()
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO job_queue(job_id, job_type, message_id, owner_email, status, payload_json, available_at, "
                "attempts, max_attempts, last_error, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, NULL, ?, ?)",
                (
                    job_id,
                    job_type,
                    message_id,
                    owner_email,
                    "pending",
                    self.encrypt_json(payload),
                    available_at or created_at,
                    max_attempts,
                    created_at,
                    created_at,
                ),
            )
        return job_id

    def claim_job(self, job_types: tuple[str, ...]) -> dict[str, Any] | None:
        if not job_types:
            return None
        placeholders = ",".join("?" for _ in job_types)
        now = isoformat_utc()
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                f"SELECT * FROM job_queue WHERE status = 'pending' AND available_at <= ? "
                f"AND job_type IN ({placeholders}) ORDER BY created_at ASC LIMIT 1",
                (now, *job_types),
            ).fetchone()
            if row is None:
                conn.commit()
                return None
            conn.execute(
                "UPDATE job_queue SET status = 'in_progress', updated_at = ? WHERE job_id = ?",
                (now, row["job_id"]),
            )
            conn.commit()
            return dict(row)

    def complete_job(self, job_id: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "UPDATE job_queue SET status = 'completed', updated_at = ?, last_error = NULL WHERE job_id = ?",
                (isoformat_utc(), job_id),
            )

    def fail_job(self, job: sqlite3.Row | dict[str, Any], error: str) -> dict[str, Any]:
        attempts = int(job["attempts"]) + 1
        max_attempts = int(job["max_attempts"])
        if attempts >= max_attempts:
            status = "failed"
            available_at = isoformat_utc()
        else:
            status = "pending"
            available_at = isoformat_utc(utcnow() + timedelta(seconds=min(2**attempts, 30)))
        with self.connect() as conn:
            conn.execute(
                "UPDATE job_queue SET status = ?, attempts = ?, last_error = ?, available_at = ?, updated_at = ? WHERE job_id = ?",
                (status, attempts, error[:500], available_at, isoformat_utc(), job["job_id"]),
            )
        updated = dict(job)
        updated["attempts"] = attempts
        updated["status"] = status
        updated["last_error"] = error[:500]
        updated["available_at"] = available_at
        return updated

    def pending_jobs(self, message_id: str | None = None) -> int:
        query = "SELECT COUNT(*) AS total FROM job_queue WHERE status IN ('pending', 'in_progress')"
        params: list[Any] = []
        if message_id is not None:
            query += " AND message_id = ?"
            params.append(message_id)
        with self.connect() as conn:
            row = conn.execute(query, params).fetchone()
        return int(row["total"]) if row else 0

    def wait_for_idle(self, message_id: str | None = None, timeout: float = 5.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.pending_jobs(message_id) == 0:
                return True
            time.sleep(0.05)
        return self.pending_jobs(message_id) == 0

    def audit(self, event_type: str, actor_email: str | None = None, details: dict[str, Any] | None = None) -> None:
        entry = {
            "event_type": event_type,
            "actor_email": actor_email,
            "details": details or {},
            "created_at": isoformat_utc(),
        }
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=True, sort_keys=True) + "\n")

    def alert(
        self,
        alert_type: str,
        *,
        actor_email: str | None = None,
        severity: str = "warning",
        details: dict[str, Any] | None = None,
    ) -> None:
        entry = {
            "alert_type": alert_type,
            "severity": severity,
            "actor_email": actor_email,
            "details": details or {},
            "created_at": isoformat_utc(),
        }
        with self.alert_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=True, sort_keys=True) + "\n")
