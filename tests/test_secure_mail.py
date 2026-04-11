from __future__ import annotations

import base64
import concurrent.futures
import shutil
import time
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from common.config import DomainConfig
from common.crypto import mac_hex
from common.utils import json_dumps, new_id
from server.main import create_app


PNG_BYTES = (
    b"\x89PNG\r\n\x1a\n"
    b"\x00\x00\x00\rIHDR"
    b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00"
    b"\x90wS\xde"
    b"\x00\x00\x00\nIDATx\x9cc`\x00\x00\x00\x02\x00\x01"
    b"\xe2!\xbc3"
    b"\x00\x00\x00\x00IEND\xaeB`\x82"
)


def _signed_headers(session: dict, path: str, body: dict) -> dict[str, str]:
    session["seq_no"] += 1
    request_id = new_id()
    nonce = new_id()
    timestamp = int(time.time())
    canonical = json_dumps(
        {
            "method": "POST",
            "path": path,
            "request_id": request_id,
            "session_id": session["session_id"],
            "seq_no": session["seq_no"],
            "timestamp": timestamp,
            "nonce": nonce,
            "body": body,
        }
    )
    return {
        "Authorization": f"Bearer {session['session_token']}",
        "X-Request-Id": request_id,
        "X-Session-Id": session["session_id"],
        "X-Seq-No": str(session["seq_no"]),
        "X-Timestamp": str(timestamp),
        "X-Nonce": nonce,
        "X-Body-Mac": mac_hex(session["session_key"], canonical),
    }


@pytest.fixture()
def app_pair():
    temp_root = Path("test_artifacts") / f"secure-email-tests-{uuid.uuid4().hex}"
    temp_root.mkdir(parents=True, exist_ok=True)
    config_a = DomainConfig.from_mapping(
        {
            "domain": "a.test",
            "data_root": str(temp_root / "domainA"),
            "peer_domains": {"b.test": "http://b.test"},
            "action_secret": "test-action-secret",
            "relay_secret": "test-relay-secret",
            "login_max_attempts": 3,
            "lockout_seconds": 60,
            "send_rate_limit_per_minute": 3,
        }
    )
    config_b = DomainConfig.from_mapping(
        {
            "domain": "b.test",
            "data_root": str(temp_root / "domainB"),
            "peer_domains": {"a.test": "http://a.test"},
            "action_secret": "test-action-secret",
            "relay_secret": "test-relay-secret",
            "login_max_attempts": 3,
            "lockout_seconds": 60,
            "send_rate_limit_per_minute": 3,
        }
    )

    clients: dict[str, TestClient] = {}

    async def relay_dispatch_a(domain: str, path: str, payload: dict):
        return _relay(clients[domain], "a.test", path, payload)

    async def relay_dispatch_b(domain: str, path: str, payload: dict):
        return _relay(clients[domain], "b.test", path, payload)

    app_a = create_app(config_a, relay_dispatch=relay_dispatch_a)
    app_b = create_app(config_b, relay_dispatch=relay_dispatch_b)
    with TestClient(app_a) as client_a, TestClient(app_b) as client_b:
        clients["a.test"] = client_a
        clients["b.test"] = client_b
        yield client_a, client_b
    try:
        clients.clear()
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


def _relay(client: TestClient, source_domain: str, path: str, payload: dict):
    timestamp = str(int(time.time()))
    nonce = new_id()
    canonical = json_dumps(
        {
            "method": "POST",
            "path": path,
            "source_domain": source_domain,
            "timestamp": timestamp,
            "nonce": nonce,
            "body": payload,
        }
    )
    response = client.post(
        path,
        json=payload,
        headers={
            "X-Relay-Domain": source_domain,
            "X-Relay-Timestamp": timestamp,
            "X-Relay-Nonce": nonce,
            "X-Relay-Mac": mac_hex("test-relay-secret", canonical),
        },
    )
    response.raise_for_status()
    return response.json()


def _register(client: TestClient, email: str, password: str = "demo123") -> None:
    response = client.post("/v1/auth/register", json={"email": email, "password": password})
    assert response.status_code == 201


def _login(client: TestClient, email: str, password: str = "demo123") -> dict:
    response = client.post("/v1/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200
    data = response.json()
    data["seq_no"] = 0
    return data


def _wait_for_message(client: TestClient, message_id: str, timeout: float = 5.0) -> None:
    assert client.app.state.ctx.wait_for_idle(message_id=message_id, timeout=timeout)


def test_login_lockout(app_pair):
    client_a, _ = app_pair
    _register(client_a, "alice@a.test")
    for _ in range(2):
        response = client_a.post("/v1/auth/login", json={"email": "alice@a.test", "password": "wrong"})
        assert response.status_code == 401
    locked = client_a.post("/v1/auth/login", json={"email": "alice@a.test", "password": "wrong"})
    assert locked.status_code == 429
    assert "Retry-After" in locked.headers


def test_register_requires_matching_confirmation(app_pair):
    client_a, _ = app_pair
    response = client_a.post(
        "/v1/auth/register",
        json={"email": "alice@a.test", "password": "demo123", "confirm_password": "different"},
    )
    assert response.status_code == 400
    assert "confirmation" in response.json()["detail"].lower()


def test_web_root_is_served(app_pair):
    client_a, _ = app_pair
    index = client_a.get("/")
    assert index.status_code == 200
    assert "text/html" in index.headers["content-type"]
    assert "Browser Mail Console" in index.text

    script = client_a.get("/static/app.js")
    assert script.status_code == 200
    assert "signedPost" in script.text


def test_cross_domain_send_attachment_recall_and_tamper(app_pair):
    client_a, client_b = app_pair
    _register(client_a, "alice@a.test")
    _register(client_b, "bob@b.test")
    alice = _login(client_a, "alice@a.test")
    bob = _login(client_b, "bob@b.test")

    upload_body = {
        "filename": "pixel.png",
        "content_base64": base64.b64encode(PNG_BYTES).decode("ascii"),
    }
    upload = client_a.post("/v1/attachments/upload", json=upload_body, headers=_signed_headers(alice, "/v1/attachments/upload", upload_body))
    assert upload.status_code == 200
    attachment_id = upload.json()["id"]

    send_body = {
        "to": ["bob@b.test"],
        "cc": [],
        "subject": "Meeting tomorrow?",
        "body_text": "Can we meet tomorrow? Thanks.",
        "attachment_ids": [attachment_id],
        "thread_id": None,
    }
    send = client_a.post("/v1/mail/send", json=send_body, headers=_signed_headers(alice, "/v1/mail/send", send_body))
    assert send.status_code == 200
    assert send.json()["status"] == "queued"
    message_id = send.json()["message_id"]
    _wait_for_message(client_a, message_id)
    _wait_for_message(client_b, message_id)

    sent = client_a.get("/v1/mail/sent", headers={"Authorization": f"Bearer {alice['session_token']}"})
    assert sent.status_code == 200
    assert sent.json()[0]["delivery_state"] == "delivered"

    inbox = client_b.get("/v1/mail/inbox", headers={"Authorization": f"Bearer {bob['session_token']}"})
    assert inbox.status_code == 200
    messages = inbox.json()
    assert len(messages) == 1
    assert messages[0]["message_id"] == message_id
    assert messages[0]["attachments"][0]["filename"] == "pixel.png"

    token = messages[0]["actions"][0]["token"]
    bad_body = {"token": token + "broken"}
    bad_action = client_b.post("/v1/actions/execute", json=bad_body, headers=_signed_headers(bob, "/v1/actions/execute", bad_body))
    assert bad_action.status_code == 400

    recall_body = {"message_id": message_id}
    recall = client_a.post("/v1/mail/recall", json=recall_body, headers=_signed_headers(alice, "/v1/mail/recall", recall_body))
    assert recall.status_code == 200
    assert recall.json()["statuses"]["bob@b.test"] == "recalled"

    inbox_after = client_b.get("/v1/mail/inbox", headers={"Authorization": f"Bearer {bob['session_token']}"})
    assert inbox_after.json()[0]["recalled"] is True


def test_phishing_sample_is_flagged(app_pair):
    client_a, client_b = app_pair
    _register(client_a, "alice@a.test")
    _register(client_b, "bob@b.test")
    alice = _login(client_a, "alice@a.test")
    bob = _login(client_b, "bob@b.test")

    send_body = {
        "to": ["bob@b.test"],
        "cc": [],
        "subject": "Urgent: verify your account and payment details",
        "body_text": (
            "Please verify your password immediately and click both links now: "
            "https://secure-check.example/reset and https://billing-check.example/pay"
        ),
        "attachment_ids": [],
        "thread_id": None,
    }
    send = client_a.post("/v1/mail/send", json=send_body, headers=_signed_headers(alice, "/v1/mail/send", send_body))
    assert send.status_code == 200
    message_id = send.json()["message_id"]
    _wait_for_message(client_a, message_id)
    _wait_for_message(client_b, message_id)

    inbox = client_b.get("/v1/mail/inbox", headers={"Authorization": f"Bearer {bob['session_token']}"})
    assert inbox.status_code == 200
    message = next(item for item in inbox.json() if item["message_id"] == message_id)
    assert message["security_flags"]["suspicious"] is True
    assert message["classification"] == "Suspicious"


def test_attachment_dedup_reuses_single_blob(app_pair):
    client_a, _ = app_pair
    _register(client_a, "alice@a.test")
    alice = _login(client_a, "alice@a.test")

    upload_body = {
        "filename": "pixel.png",
        "content_base64": base64.b64encode(PNG_BYTES).decode("ascii"),
    }
    first = client_a.post("/v1/attachments/upload", json=upload_body, headers=_signed_headers(alice, "/v1/attachments/upload", upload_body))
    assert first.status_code == 200
    second = client_a.post("/v1/attachments/upload", json=upload_body, headers=_signed_headers(alice, "/v1/attachments/upload", upload_body))
    assert second.status_code == 200
    assert first.json()["id"] != second.json()["id"]

    with client_a.app.state.ctx.connect() as conn:
        blobs = conn.execute("SELECT blob_key, ref_count FROM attachment_blobs").fetchall()
        attachments = conn.execute("SELECT COUNT(*) AS total FROM attachments").fetchone()
    assert len(blobs) == 1
    assert blobs[0]["ref_count"] == 2
    assert attachments["total"] == 2


def test_cc_recipients_are_delivered(app_pair):
    client_a, client_b = app_pair
    _register(client_a, "alice@a.test")
    _register(client_a, "carol@a.test")
    _register(client_b, "bob@b.test")
    alice = _login(client_a, "alice@a.test")
    bob = _login(client_b, "bob@b.test")
    carol = _login(client_a, "carol@a.test")

    send_body = {
        "to": ["bob@b.test"],
        "cc": ["carol@a.test"],
        "subject": "Cc check",
        "body_text": "This should reach both recipients.",
        "attachment_ids": [],
        "thread_id": None,
    }
    send = client_a.post("/v1/mail/send", json=send_body, headers=_signed_headers(alice, "/v1/mail/send", send_body))
    assert send.status_code == 200
    message_id = send.json()["message_id"]
    _wait_for_message(client_a, message_id)
    _wait_for_message(client_b, message_id)

    bob_inbox = client_b.get("/v1/mail/inbox", headers={"Authorization": f"Bearer {bob['session_token']}"})
    assert bob_inbox.status_code == 200
    assert bob_inbox.json()[0]["message_id"] == message_id

    carol_inbox = client_a.get("/v1/mail/inbox", headers={"Authorization": f"Bearer {carol['session_token']}"})
    assert carol_inbox.status_code == 200
    assert carol_inbox.json()[0]["message_id"] == message_id
    assert carol_inbox.json()[0]["cc"] == ["carol@a.test"]


def test_concurrent_multi_client_send_and_receive(app_pair):
    client_a, client_b = app_pair
    _register(client_b, "bob@b.test")
    bob = _login(client_b, "bob@b.test")
    bob_headers = {"Authorization": f"Bearer {bob['session_token']}"}
    sender_count = 8

    def sender_task(index: int) -> str:
        email = f"load{index}@a.test"
        _register(client_a, email)
        session = _login(client_a, email)
        body = {
            "to": ["bob@b.test"],
            "cc": [],
            "subject": f"Concurrent {index}",
            "body_text": f"Message {index}",
            "attachment_ids": [],
            "thread_id": None,
        }
        response = client_a.post("/v1/mail/send", json=body, headers=_signed_headers(session, "/v1/mail/send", body))
        assert response.status_code == 200
        return response.json()["message_id"]

    def inbox_poller() -> list[int]:
        counts: list[int] = []
        for _ in range(10):
            response = client_b.get("/v1/mail/inbox", headers=bob_headers)
            assert response.status_code == 200
            counts.append(len(response.json()))
            time.sleep(0.05)
        return counts

    with concurrent.futures.ThreadPoolExecutor(max_workers=sender_count + 1) as pool:
        poll_future = pool.submit(inbox_poller)
        sender_futures = [pool.submit(sender_task, index) for index in range(sender_count)]
        message_ids = [future.result() for future in sender_futures]
        poll_counts = poll_future.result()

    for message_id in message_ids:
        _wait_for_message(client_a, message_id)
        _wait_for_message(client_b, message_id)

    inbox = client_b.get("/v1/mail/inbox", headers=bob_headers)
    assert inbox.status_code == 200
    delivered_ids = {item["message_id"] for item in inbox.json()}
    assert set(message_ids).issubset(delivered_ids)
    assert max(poll_counts) >= 0


def test_replay_rejected(app_pair):
    client_a, _ = app_pair
    _register(client_a, "alice@a.test")
    alice = _login(client_a, "alice@a.test")
    body = {"name": "team", "members": []}
    headers = _signed_headers(alice, "/v1/groups/create", body)
    first = client_a.post("/v1/groups/create", json=body, headers=headers)
    assert first.status_code == 200
    replay = client_a.post("/v1/groups/create", json=body, headers=headers)
    assert replay.status_code == 409


def test_invalid_attachment_rejected(app_pair):
    client_a, _ = app_pair
    _register(client_a, "alice@a.test")
    alice = _login(client_a, "alice@a.test")
    body = {
        "filename": "evil.jpg",
        "content_base64": base64.b64encode(b"not-really-an-image").decode("ascii"),
    }
    response = client_a.post("/v1/attachments/upload", json=body, headers=_signed_headers(alice, "/v1/attachments/upload", body))
    assert response.status_code == 400


def test_send_rate_limit(app_pair):
    client_a, client_b = app_pair
    _register(client_a, "alice@a.test")
    _register(client_b, "bob@b.test")
    alice = _login(client_a, "alice@a.test")
    body = {
        "to": ["bob@b.test"],
        "cc": [],
        "subject": "Burst",
        "body_text": "Load",
        "attachment_ids": [],
        "thread_id": None,
    }
    for _ in range(3):
        response = client_a.post("/v1/mail/send", json=body, headers=_signed_headers(alice, "/v1/mail/send", body))
        assert response.status_code == 200
    limited = client_a.post("/v1/mail/send", json=body, headers=_signed_headers(alice, "/v1/mail/send", body))
    assert limited.status_code == 429
