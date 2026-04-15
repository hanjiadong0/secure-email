from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import httpx

from common.crypto import mac_hex
from common.e2e import build_envelope, decrypt_envelope, generate_identity
from common.utils import json_dumps, new_id


SESSION_ROOT = Path(".client_state")
KEY_ROOT = SESSION_ROOT / "keys"


@dataclass
class SessionState:
    email: str
    base_url: str
    session_id: str
    session_token: str
    session_key: str
    seq_no: int = 0


@dataclass
class E2EIdentityState:
    email: str
    base_url: str
    public_key: str
    private_key_pem: str


class SessionStore:
    def __init__(self) -> None:
        SESSION_ROOT.mkdir(parents=True, exist_ok=True)
        KEY_ROOT.mkdir(parents=True, exist_ok=True)

    def _path(self, base_url: str, email: str) -> Path:
        safe = f"{base_url.replace('://', '_').replace('/', '_')}_{email.replace('@', '_at_')}".replace(":", "_")
        return SESSION_ROOT / f"{safe}.json"

    def load(self, base_url: str, email: str) -> SessionState:
        path = self._path(base_url, email)
        if not path.exists():
            raise FileNotFoundError(f"No saved session for {email} at {base_url}.")
        return SessionState(**json.loads(path.read_text(encoding="utf-8")))

    def save(self, session: SessionState) -> None:
        self._path(session.base_url, session.email).write_text(
            json.dumps(asdict(session), indent=2),
            encoding="utf-8",
        )

    def _key_path(self, base_url: str, email: str) -> Path:
        safe = f"{base_url.replace('://', '_').replace('/', '_')}_{email.replace('@', '_at_')}".replace(":", "_")
        return KEY_ROOT / f"{safe}.json"

    def load_identity(self, base_url: str, email: str) -> E2EIdentityState:
        path = self._key_path(base_url, email)
        if not path.exists():
            raise FileNotFoundError(f"No saved E2E identity for {email} at {base_url}.")
        return E2EIdentityState(**json.loads(path.read_text(encoding="utf-8")))

    def save_identity(self, identity: E2EIdentityState) -> None:
        self._key_path(identity.base_url, identity.email).write_text(
            json.dumps(asdict(identity), indent=2),
            encoding="utf-8",
        )


class ApiClient:
    def __init__(self, base_url: str, email: str | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.session_store = SessionStore()
        self.session = self.session_store.load(self.base_url, email) if email else None
        self.client = httpx.Client(base_url=self.base_url, timeout=20, verify=False)

    def close(self) -> None:
        self.client.close()

    def register(self, email: str, password: str, confirm_password: str | None = None) -> dict[str, Any]:
        response = self.client.post(
            "/v1/auth/register",
            json={"email": email, "password": password, "confirm_password": confirm_password or password},
        )
        response.raise_for_status()
        return response.json()

    def login(self, email: str, password: str) -> dict[str, Any]:
        response = self.client.post("/v1/auth/login", json={"email": email, "password": password})
        response.raise_for_status()
        data = response.json()
        self.session = SessionState(
            email=email,
            base_url=self.base_url,
            session_id=data["session_id"],
            session_token=data["session_token"],
            session_key=data["session_key"],
            seq_no=0,
        )
        self.session_store.save(self.session)
        return data

    def _auth_headers(self, path: str, body: dict[str, Any]) -> dict[str, str]:
        if self.session is None:
            raise RuntimeError("This command needs a saved session. Run login first.")
        next_seq = self.session.seq_no + 1
        request_id = new_id()
        nonce = new_id()
        timestamp = str(int(__import__("time").time()))
        canonical = json_dumps(
            {
                "method": "POST",
                "path": path,
                "request_id": request_id,
                "session_id": self.session.session_id,
                "seq_no": next_seq,
                "timestamp": int(timestamp),
                "nonce": nonce,
                "body": body,
            }
        )
        body_mac = mac_hex(self.session.session_key, canonical)
        headers = {
            "Authorization": f"Bearer {self.session.session_token}",
            "X-Request-Id": request_id,
            "X-Session-Id": self.session.session_id,
            "X-Seq-No": str(next_seq),
            "X-Timestamp": timestamp,
            "X-Nonce": nonce,
            "X-Body-Mac": body_mac,
        }
        self.session.seq_no = next_seq
        self.session_store.save(self.session)
        return headers

    def _get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        headers = {}
        if self.session is not None:
            headers["Authorization"] = f"Bearer {self.session.session_token}"
        response = self.client.get(path, params=params, headers=headers)
        response.raise_for_status()
        return response.json()

    def _post(self, path: str, body: dict[str, Any]) -> Any:
        headers = self._auth_headers(path, body)
        response = self.client.post(path, json=body, headers=headers)
        response.raise_for_status()
        return response.json()

    def upload_attachment(self, file_path: str) -> dict[str, Any]:
        raw = Path(file_path).read_bytes()
        import base64

        return self._post(
            "/v1/attachments/upload",
            {"filename": Path(file_path).name, "content_base64": base64.b64encode(raw).decode("ascii")},
        )

    def inbox(self) -> Any:
        return self._get("/v1/mail/inbox")

    def sent(self) -> Any:
        return self._get("/v1/mail/sent")

    def drafts(self) -> Any:
        return self._get("/v1/mail/drafts")

    def message(self, message_id: str) -> Any:
        return self._get(f"/v1/mail/message/{message_id}")

    def send_mail(self, to: list[str], subject: str, body_text: str, attachment_ids: list[str] | None = None, cc: list[str] | None = None, thread_id: str | None = None) -> Any:
        return self._post(
            "/v1/mail/send",
            {
                "to": to,
                "cc": cc or [],
                "subject": subject,
                "body_text": body_text,
                "attachment_ids": attachment_ids or [],
                "thread_id": thread_id,
            },
        )

    def ensure_e2e_identity(self) -> E2EIdentityState:
        if self.session is None:
            raise RuntimeError("Login first before using E2E.")
        try:
            identity = self.session_store.load_identity(self.base_url, self.session.email)
        except FileNotFoundError:
            generated = generate_identity()
            identity = E2EIdentityState(
                email=self.session.email,
                base_url=self.base_url,
                public_key=generated.public_key,
                private_key_pem=generated.private_key_pem,
            )
            self.session_store.save_identity(identity)
        self._post(
            "/v1/keys/publish",
            {
                "algorithm": "ECDH-P256-HKDF-SHA256-AESGCM",
                "curve": "P-256",
                "public_key": identity.public_key,
            },
        )
        return identity

    def my_e2e_key(self) -> Any:
        return self._get("/v1/keys/me")

    def resolve_e2e_keys(self, emails: list[str]) -> Any:
        return self._post("/v1/keys/resolve", {"emails": emails})

    def send_mail_e2e(
        self,
        *,
        to: list[str],
        subject: str,
        body_text: str,
        cc: list[str] | None = None,
        thread_id: str | None = None,
    ) -> Any:
        if self.session is None:
            raise RuntimeError("Login first before using E2E.")
        identity = self.ensure_e2e_identity()
        recipients = [*to, *(cc or [])]
        resolved = self.resolve_e2e_keys(recipients)
        missing = resolved.get("missing", [])
        if missing:
            raise RuntimeError(f"Missing E2E public keys for: {', '.join(missing)}")
        recipient_keys = {item["email"]: item["public_key"] for item in resolved.get("keys", [])}
        envelope = build_envelope(
            sender_public_key=identity.public_key,
            sender_email=self.session.email,
            recipient_public_keys=recipient_keys,
            subject=subject,
            body_text=body_text,
        )
        return self._post(
            "/v1/mail/send",
            {
                "to": to,
                "cc": cc or [],
                "subject": "[End-to-end encrypted message]",
                "body_text": "",
                "attachment_ids": [],
                "thread_id": thread_id,
                "e2e_envelope": envelope,
            },
        )

    def decrypt_message(self, message: dict[str, Any]) -> dict[str, str]:
        if self.session is None:
            raise RuntimeError("Login first before decrypting E2E messages.")
        if not message.get("e2e_encrypted"):
            return {"subject": message.get("subject", ""), "body_text": message.get("body_text", "")}
        identity = self.session_store.load_identity(self.base_url, self.session.email)
        return decrypt_envelope(
            private_key_pem=identity.private_key_pem,
            recipient_email=self.session.email,
            envelope=message["e2e_envelope"],
        )

    def save_draft(
        self,
        to: list[str],
        subject: str,
        body_text: str,
        attachment_ids: list[str] | None = None,
        cc: list[str] | None = None,
        message_id: str | None = None,
        send_now: bool = False,
    ) -> Any:
        return self._post(
            "/v1/mail/draft",
            {
                "message_id": message_id,
                "to": to,
                "cc": cc or [],
                "subject": subject,
                "body_text": body_text,
                "attachment_ids": attachment_ids or [],
                "send_now": send_now,
            },
        )

    def mark_read(self, message_id: str) -> Any:
        return self._post(f"/v1/mail/mark_read/{message_id}", {"message_id": message_id})

    def recall(self, message_id: str) -> Any:
        return self._post("/v1/mail/recall", {"message_id": message_id})

    def group_create(self, name: str, members: list[str]) -> Any:
        return self._post("/v1/groups/create", {"name": name, "members": members})

    def group_add_member(self, name: str, member_email: str) -> Any:
        return self._post("/v1/groups/add_member", {"name": name, "member_email": member_email})

    def send_group(self, group_name: str, subject: str, body_text: str, attachment_ids: list[str] | None = None) -> Any:
        return self._post(
            "/v1/mail/send_group",
            {
                "group_name": group_name,
                "subject": subject,
                "body_text": body_text,
                "attachment_ids": attachment_ids or [],
            },
        )

    def execute_action(self, token: str) -> Any:
        return self._post("/v1/actions/execute", {"token": token})

    def todos(self) -> Any:
        return self._get("/v1/todos")

    def calendar_events(self) -> Any:
        return self._get("/v1/calendar/events")

    def search(self, query: str) -> Any:
        return self._get("/v1/mail/search", params={"q": query})

    def autocomplete(self, query: str) -> Any:
        return self._get("/v1/contacts/autocomplete", params={"q": query})
