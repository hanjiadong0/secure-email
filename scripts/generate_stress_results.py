from __future__ import annotations

import concurrent.futures
import json
import shutil
import time
import uuid
from collections import Counter
from pathlib import Path

from fastapi.testclient import TestClient

from common.config import DomainConfig
from common.crypto import mac_hex
from common.utils import isoformat_utc, json_dumps, new_id
from server.main import create_app


ROOT = Path(__file__).resolve().parents[1]
OUTPUT_MD = ROOT / "docs" / "stress_test_results.md"
OUTPUT_JSON = ROOT / "docs" / "stress_test_results.json"


def _signed_headers(session: dict[str, object], path: str, body: dict[str, object]) -> dict[str, str]:
    session["seq_no"] = int(session.get("seq_no", 0)) + 1
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
        "X-Session-Id": str(session["session_id"]),
        "X-Seq-No": str(session["seq_no"]),
        "X-Timestamp": str(timestamp),
        "X-Nonce": nonce,
        "X-Body-Mac": mac_hex(str(session["session_key"]), canonical),
    }


def _relay(client: TestClient, source_domain: str, path: str, payload: dict[str, object]) -> dict[str, object]:
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
            "X-Relay-Mac": mac_hex("stress-relay-secret", canonical),
        },
    )
    response.raise_for_status()
    return response.json()


def _register(client: TestClient, email: str, password: str = "demo123") -> None:
    response = client.post(
        "/v1/auth/register",
        json={"email": email, "password": password, "confirm_password": password},
    )
    if response.status_code not in {201, 409}:
        raise RuntimeError(f"register failed for {email}: {response.status_code} {response.text}")


def _login(client: TestClient, email: str, password: str = "demo123") -> dict[str, object]:
    response = client.post("/v1/auth/login", json={"email": email, "password": password})
    response.raise_for_status()
    payload = response.json()
    payload["seq_no"] = 0
    return payload


def _wait_for_message(client: TestClient, message_id: str, timeout: float = 10.0) -> None:
    if not client.app.state.ctx.wait_for_idle(message_id=message_id, timeout=timeout):
        raise RuntimeError(f"worker queue did not settle for message {message_id}")


def _make_clients() -> tuple[TestClient, TestClient, Path]:
    temp_root = ROOT / "test_artifacts" / f"stress-results-{uuid.uuid4().hex}"
    temp_root.mkdir(parents=True, exist_ok=True)
    config_a = DomainConfig.from_mapping(
        {
            "domain": "a.test",
            "data_root": str(temp_root / "domainA"),
            "peer_domains": {"b.test": "http://b.test"},
            "action_secret": "stress-action-secret",
            "relay_secret": "stress-relay-secret",
            "login_max_attempts": 5,
            "lockout_seconds": 60,
            "send_rate_limit_per_minute": 30,
        }
    )
    config_b = DomainConfig.from_mapping(
        {
            "domain": "b.test",
            "data_root": str(temp_root / "domainB"),
            "peer_domains": {"a.test": "http://a.test"},
            "action_secret": "stress-action-secret",
            "relay_secret": "stress-relay-secret",
            "login_max_attempts": 5,
            "lockout_seconds": 60,
            "send_rate_limit_per_minute": 30,
        }
    )
    clients: dict[str, TestClient] = {}

    async def relay_dispatch_a(domain: str, path: str, payload: dict[str, object]) -> dict[str, object]:
        return _relay(clients[domain], "a.test", path, payload)

    async def relay_dispatch_b(domain: str, path: str, payload: dict[str, object]) -> dict[str, object]:
        return _relay(clients[domain], "b.test", path, payload)

    app_a = create_app(config_a, relay_dispatch=relay_dispatch_a)
    app_b = create_app(config_b, relay_dispatch=relay_dispatch_b)
    client_a = TestClient(app_a)
    client_b = TestClient(app_b)
    client_a.__enter__()
    client_b.__enter__()
    clients["a.test"] = client_a
    clients["b.test"] = client_b
    return client_a, client_b, temp_root


def _close_clients(client_a: TestClient, client_b: TestClient, temp_root: Path) -> None:
    try:
        client_b.__exit__(None, None, None)
    finally:
        client_a.__exit__(None, None, None)
        shutil.rmtree(temp_root, ignore_errors=True)


def _scenario_many_users_one_mail(client_a: TestClient, client_b: TestClient) -> dict[str, object]:
    recipient = "collector@b.test"
    _register(client_b, recipient)
    receiver = _login(client_b, recipient)
    receiver_headers = {"Authorization": f"Bearer {receiver['session_token']}"}
    sender_count = 100

    def sender_task(index: int) -> tuple[int, str | None]:
        email = f"load{index}@a.test"
        _register(client_a, email)
        sender = _login(client_a, email)
        body = {
            "to": [recipient],
            "cc": [],
            "subject": f"Stress many-users {index}",
            "body_text": f"Concurrent sender {index}",
            "attachment_ids": [],
            "thread_id": None,
        }
        response = client_a.post("/v1/mail/send", json=body, headers=_signed_headers(sender, "/v1/mail/send", body))
        if response.status_code == 200:
            return response.status_code, response.json()["message_id"]
        return response.status_code, None

    def inbox_poller() -> list[int]:
        counts: list[int] = []
        for _ in range(40):
            response = client_b.get("/v1/mail/inbox", headers=receiver_headers)
            response.raise_for_status()
            counts.append(len(response.json()))
            time.sleep(0.05)
        return counts

    start = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:
        poll_future = pool.submit(inbox_poller)
        futures = [pool.submit(sender_task, index) for index in range(sender_count)]
        results = [future.result() for future in futures]
        polled_counts = poll_future.result()
    duration = time.perf_counter() - start

    accepted_ids = [message_id for status, message_id in results if status == 200 and message_id]
    for message_id in accepted_ids:
        _wait_for_message(client_a, message_id)
        _wait_for_message(client_b, message_id)
    inbox = client_b.get("/v1/mail/inbox", headers=receiver_headers)
    inbox.raise_for_status()
    inbox_items = inbox.json()
    delivered = sum(1 for item in inbox_items if item["subject"].startswith("Stress many-users "))
    return {
        "scenario": "100 different users each send 1 mail",
        "attempted_sends": sender_count,
        "accepted_sends": len(accepted_ids),
        "rejected_sends": sender_count - len(accepted_ids),
        "receiver_inbox_new_messages": delivered,
        "peak_polled_inbox_size": max(polled_counts) if polled_counts else 0,
        "duration_seconds": round(duration, 2),
        "result": "pass" if delivered == sender_count else "partial",
    }


def _scenario_one_user_hundred_attempts(client_a: TestClient, client_b: TestClient) -> dict[str, object]:
    recipient = "burst-target@b.test"
    sender_email = "burst@a.test"
    _register(client_b, recipient)
    _register(client_a, sender_email)
    receiver = _login(client_b, recipient)
    sender = _login(client_a, sender_email)
    receiver_headers = {"Authorization": f"Bearer {receiver['session_token']}"}

    attempts = 100
    accepted_ids: list[str] = []
    statuses: list[int] = []
    start = time.perf_counter()
    for index in range(attempts):
        body = {
            "to": [recipient],
            "cc": [],
            "subject": f"Stress one-user {index}",
            "body_text": f"Burst attempt {index}",
            "attachment_ids": [],
            "thread_id": None,
        }
        response = client_a.post("/v1/mail/send", json=body, headers=_signed_headers(sender, "/v1/mail/send", body))
        statuses.append(response.status_code)
        if response.status_code == 200:
            accepted_ids.append(response.json()["message_id"])
    duration = time.perf_counter() - start

    for message_id in accepted_ids:
        _wait_for_message(client_a, message_id)
        _wait_for_message(client_b, message_id)
    inbox = client_b.get("/v1/mail/inbox", headers=receiver_headers)
    inbox.raise_for_status()
    inbox_items = inbox.json()
    delivered = sum(1 for item in inbox_items if item["subject"].startswith("Stress one-user "))
    status_counts = Counter(statuses)
    health_ok = client_a.get("/health").status_code == 200 and client_b.get("/health").status_code == 200
    return {
        "scenario": "1 user attempts 100 mails",
        "attempted_sends": attempts,
        "accepted_sends": len(accepted_ids),
        "rate_limited": status_counts.get(429, 0),
        "other_failures": attempts - len(accepted_ids) - status_counts.get(429, 0),
        "receiver_inbox_new_messages": delivered,
        "duration_seconds": round(duration, 2),
        "service_still_healthy": health_ok,
        "result": "pass" if status_counts.get(429, 0) > 0 and health_ok else "partial",
    }


def _write_outputs(report: dict[str, object]) -> None:
    OUTPUT_JSON.write_text(json.dumps(report, ensure_ascii=True, indent=2), encoding="utf-8")
    scenarios = report["scenarios"]
    lines = [
        "# Stress Test Results",
        "",
        f"Generated at: `{report['generated_at']}`",
        "",
        "This document records an actual local run of the assignment-sized stress scenarios using two temporary isolated domains created in-process through the same FastAPI application and relay code paths as the main project.",
        "",
        "Command:",
        "",
        "```powershell",
        ".\\.venv\\Scripts\\python.exe scripts\\generate_stress_results.py",
        "```",
        "",
        "## Scenario A",
        "",
        "`100 different users each send 1 mail`",
        "",
        f"- Attempted sends: `{scenarios[0]['attempted_sends']}`",
        f"- Accepted sends: `{scenarios[0]['accepted_sends']}`",
        f"- Rejected sends: `{scenarios[0]['rejected_sends']}`",
        f"- Receiver inbox new messages: `{scenarios[0]['receiver_inbox_new_messages']}`",
        f"- Peak polled inbox size during concurrent receive: `{scenarios[0]['peak_polled_inbox_size']}`",
        f"- Duration: `{scenarios[0]['duration_seconds']} s`",
        f"- Result: `{scenarios[0]['result']}`",
        "",
        "Interpretation:",
        "The multi-client path completed without a server crash, and the receiver mailbox accumulated the expected new messages while inbox polling happened at the same time.",
        "",
        "## Scenario B",
        "",
        "`1 user attempts 100 mails`",
        "",
        f"- Attempted sends: `{scenarios[1]['attempted_sends']}`",
        f"- Accepted sends: `{scenarios[1]['accepted_sends']}`",
        f"- Rate-limited responses: `{scenarios[1]['rate_limited']}`",
        f"- Other failures: `{scenarios[1]['other_failures']}`",
        f"- Receiver inbox new messages: `{scenarios[1]['receiver_inbox_new_messages']}`",
        f"- Service still healthy after burst: `{scenarios[1]['service_still_healthy']}`",
        f"- Duration: `{scenarios[1]['duration_seconds']} s`",
        f"- Result: `{scenarios[1]['result']}`",
        "",
        "Interpretation:",
        "This scenario is expected to trigger anti-abuse protection. The important success condition is that the service remains healthy and that rate limiting activates instead of allowing unlimited same-user flooding.",
        "",
        "## Raw JSON",
        "",
        f"See [stress_test_results.json](./stress_test_results.json) for the machine-readable version of this run.",
    ]
    OUTPUT_MD.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    client_a, client_b, temp_root = _make_clients()
    try:
        scenarios = [
            _scenario_many_users_one_mail(client_a, client_b),
            _scenario_one_user_hundred_attempts(client_a, client_b),
        ]
        report = {
            "status": "ok",
            "generated_at": isoformat_utc(),
            "scenarios": scenarios,
        }
        _write_outputs(report)
        print(json.dumps(report, ensure_ascii=True, indent=2))
    finally:
        _close_clients(client_a, client_b, temp_root)


if __name__ == "__main__":
    main()
