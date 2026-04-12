from __future__ import annotations

import base64
import json
import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient
from PIL import Image, ImageDraw

from common.config import DomainConfig
from common.crypto import mac_hex
from common.utils import ensure_directory, isoformat_utc, json_dumps, new_id
from server import attachments, auth, e2e_keys, mailbox, relay
from server.storage import AppContext, RelayDispatch
from server.workers import start_workers, stop_workers


def _create_sim_app(config: DomainConfig, relay_dispatch: RelayDispatch | None = None) -> tuple[FastAPI, AppContext]:
    ctx = AppContext(config=config, relay_dispatch=relay_dispatch)
    app = FastAPI(title=f"Security Simulation - {config.domain}", version="1.0")
    app.state.ctx = ctx

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "domain": config.domain}

    auth.register_routes(app, ctx)
    e2e_keys.register_routes(app, ctx)
    attachments.register_routes(app, ctx)
    mailbox.register_routes(app, ctx)
    relay.register_routes(app, ctx)
    return app, ctx


def _relay(client: TestClient, source_domain: str, path: str, payload: dict[str, Any], relay_secret: str) -> dict[str, Any]:
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
            "X-Relay-Mac": mac_hex(relay_secret, canonical),
        },
    )
    response.raise_for_status()
    return response.json()


def _signed_headers(session: dict[str, Any], path: str, body: dict[str, Any]) -> dict[str, str]:
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


def _register(client: TestClient, email: str, password: str = "demo123") -> None:
    response = client.post(
        "/v1/auth/register",
        json={"email": email, "password": password, "confirm_password": password},
    )
    if response.status_code not in {201, 409}:
        raise RuntimeError(f"register failed for {email}: {response.status_code} {response.text}")


def _login(client: TestClient, email: str, password: str = "demo123") -> dict[str, Any]:
    response = client.post("/v1/auth/login", json={"email": email, "password": password})
    if response.status_code != 200:
        raise RuntimeError(f"login failed for {email}: {response.status_code} {response.text}")
    payload = response.json()
    payload["seq_no"] = 0
    return payload


def _wait_for_message(client: TestClient, message_id: str, timeout: float = 6.0) -> bool:
    return bool(client.app.state.ctx.wait_for_idle(message_id=message_id, timeout=timeout))


def _scenario_login_lockout(client_a: TestClient) -> dict[str, Any]:
    target = "victim-lock@sim-a.test"
    _register(client_a, target)
    attempts = 5
    blocked = 0
    for _ in range(attempts):
        response = client_a.post("/v1/auth/login", json={"email": target, "password": "wrong-password"})
        if response.status_code == 429:
            blocked += 1
    return {
        "scenario": "Brute-force login",
        "attempts": attempts,
        "blocked": blocked,
        "detected": 1 if blocked > 0 else 0,
        "attacker_success": 0 if blocked > 0 else 1,
        "notes": "Account lockout and Retry-After response should trigger.",
    }


def _scenario_replay_attack(client_a: TestClient) -> dict[str, Any]:
    attacker_email = "replay-attacker@sim-a.test"
    _register(client_a, attacker_email)
    attacker = _login(client_a, attacker_email)
    path = "/v1/groups/create"
    body = {"name": "incident-team", "members": []}
    headers = _signed_headers(attacker, path, body)
    first = client_a.post(path, json=body, headers=headers)
    replay = client_a.post(path, json=body, headers=headers)
    blocked = 1 if replay.status_code == 409 else 0
    return {
        "scenario": "Replay attack",
        "attempts": 1,
        "blocked": blocked,
        "detected": blocked,
        "attacker_success": 1 if replay.status_code < 400 else 0,
        "notes": f"Initial={first.status_code}, replay={replay.status_code}.",
    }


def _scenario_send_rate_limit(client_a: TestClient, client_b: TestClient) -> dict[str, Any]:
    sender_email = "spam-source@sim-a.test"
    recipient_email = "rate-target@sim-b.test"
    _register(client_a, sender_email)
    _register(client_b, recipient_email)
    sender = _login(client_a, sender_email)
    attempts = 6
    blocked = 0
    accepted = 0
    for index in range(attempts):
        payload = {
            "to": [recipient_email],
            "cc": [],
            "subject": f"Burst {index}",
            "body_text": "Burst traffic simulation",
            "attachment_ids": [],
            "thread_id": None,
        }
        response = client_a.post("/v1/mail/send", json=payload, headers=_signed_headers(sender, "/v1/mail/send", payload))
        if response.status_code == 429:
            blocked += 1
        if response.status_code == 200:
            accepted += 1
    # Accepted messages are expected up to the configured limit.
    attacker_success = max(0, accepted - 3)
    return {
        "scenario": "Mail flood / rate limit",
        "attempts": attempts,
        "blocked": blocked,
        "detected": 1 if blocked > 0 else 0,
        "attacker_success": attacker_success,
        "notes": "Server-side send throttling should block burst traffic.",
    }


def _scenario_phishing_detection(client_a: TestClient, client_b: TestClient) -> dict[str, Any]:
    sender_email = "phisher@sim-a.test"
    recipient_email = "victim@sim-b.test"
    _register(client_a, sender_email)
    _register(client_b, recipient_email)
    sender = _login(client_a, sender_email)
    receiver = _login(client_b, recipient_email)
    payload = {
        "to": [recipient_email],
        "cc": [],
        "subject": "Urgent account verification required",
        "body_text": (
            "Verify your password immediately and click now: "
            "https://secure-reset.example/check and https://billing-reset.example/pay"
        ),
        "attachment_ids": [],
        "thread_id": None,
    }
    response = client_a.post("/v1/mail/send", json=payload, headers=_signed_headers(sender, "/v1/mail/send", payload))
    if response.status_code != 200:
        return {
            "scenario": "Phishing signal detection",
            "attempts": 1,
            "blocked": 0,
            "detected": 0,
            "attacker_success": 1,
            "notes": f"Send failed unexpectedly with {response.status_code}.",
        }
    message_id = response.json()["message_id"]
    _wait_for_message(client_a, message_id)
    _wait_for_message(client_b, message_id)
    inbox = client_b.get("/v1/mail/inbox", headers={"Authorization": f"Bearer {receiver['session_token']}"})
    suspicious = False
    if inbox.status_code == 200:
        for item in inbox.json():
            if item["message_id"] == message_id:
                suspicious = bool(item.get("security_flags", {}).get("suspicious"))
                break
    return {
        "scenario": "Phishing signal detection",
        "attempts": 1,
        "blocked": 0,
        "detected": 1 if suspicious else 0,
        "attacker_success": 0 if suspicious else 1,
        "notes": "Suspicious language and links should be flagged.",
    }


def _scenario_invalid_attachment(client_a: TestClient) -> dict[str, Any]:
    sender_email = "attachment-attacker@sim-a.test"
    _register(client_a, sender_email)
    sender = _login(client_a, sender_email)
    upload_payload = {
        "filename": "fake.jpg",
        "content_base64": base64.b64encode(b"not-an-image").decode("ascii"),
    }
    upload_response = client_a.post(
        "/v1/attachments/upload",
        json=upload_payload,
        headers=_signed_headers(sender, "/v1/attachments/upload", upload_payload),
    )
    if upload_response.status_code != 200:
        return {
            "scenario": "Malicious attachment handling",
            "attempts": 1,
            "blocked": 1,
            "detected": 1,
            "attacker_success": 0,
            "notes": f"Upload rejected with {upload_response.status_code}.",
        }

    attachment_id = upload_response.json().get("id")
    transform_payload = {"mode": "anime"}
    transform_response = client_a.post(
        f"/v1/attachments/{attachment_id}/transform",
        json=transform_payload,
        headers=_signed_headers(sender, f"/v1/attachments/{attachment_id}/transform", transform_payload),
    )
    blocked = 1 if transform_response.status_code == 400 else 0
    return {
        "scenario": "Malicious attachment handling",
        "attempts": 2,
        "blocked": blocked,
        "detected": blocked,
        "attacker_success": 0 if blocked else 1,
        "notes": "Any file type can upload, but image-only transform on non-image should be rejected.",
    }


def _draw_attacker_defender_chart(results: list[dict[str, Any]], output_path: Path) -> None:
    width = 1320
    row_height = 94
    height = 180 + row_height * len(results)
    image = Image.new("RGB", (width, height), color=(246, 248, 252))
    draw = ImageDraw.Draw(image)
    draw.text((32, 24), "Attacker vs Defender Security Drill", fill=(21, 36, 64))
    draw.text((32, 54), "Green = defender blocked/detected | Red = attacker succeeded", fill=(75, 95, 128))

    bar_start = 520
    bar_width = 660
    for index, item in enumerate(results):
        y = 112 + index * row_height
        name = str(item["scenario"])
        attempts = max(1, int(item["attempts"]))
        blocked = int(item["blocked"])
        detected = int(item["detected"])
        attacker_success = int(item["attacker_success"])
        defender_score = max(blocked, detected)

        draw.text((32, y + 6), name, fill=(31, 41, 55))
        draw.text((32, y + 34), f"attempts={attempts} blocked={blocked} detected={detected} success={attacker_success}", fill=(83, 97, 122))
        draw.rectangle((bar_start, y + 8, bar_start + bar_width, y + 58), outline=(199, 209, 224), width=1)

        defender_ratio = min(1.0, defender_score / attempts)
        attacker_ratio = min(1.0, attacker_success / attempts)
        defender_pixels = int(bar_width * defender_ratio)
        attacker_pixels = int(bar_width * attacker_ratio)

        if defender_pixels > 0:
            draw.rectangle((bar_start + 2, y + 12, bar_start + defender_pixels, y + 33), fill=(34, 197, 94))
        if attacker_pixels > 0:
            draw.rectangle((bar_start + 2, y + 36, bar_start + attacker_pixels, y + 54), fill=(220, 38, 38))
    image.save(output_path, format="PNG")


def _draw_scenario_matrix(results: list[dict[str, Any]], output_path: Path) -> None:
    headers = ["Scenario", "Attempts", "Blocked", "Detected", "Attacker Success"]
    column_widths = [470, 130, 130, 130, 210]
    width = sum(column_widths) + 48
    row_height = 48
    height = 84 + row_height * (len(results) + 1)
    image = Image.new("RGB", (width, height), color=(255, 255, 255))
    draw = ImageDraw.Draw(image)
    draw.text((20, 14), "Security Simulation Matrix", fill=(31, 41, 55))

    x = 20
    y = 44
    for index, header in enumerate(headers):
        draw.rectangle((x, y, x + column_widths[index], y + row_height), fill=(239, 246, 255), outline=(209, 213, 219), width=1)
        draw.text((x + 8, y + 14), header, fill=(30, 64, 175))
        x += column_widths[index]

    for row_index, item in enumerate(results):
        y_row = y + row_height * (row_index + 1)
        values = [
            str(item["scenario"]),
            str(item["attempts"]),
            str(item["blocked"]),
            str(item["detected"]),
            str(item["attacker_success"]),
        ]
        x = 20
        for column_index, value in enumerate(values):
            fill = (248, 250, 252) if row_index % 2 == 0 else (255, 255, 255)
            draw.rectangle((x, y_row, x + column_widths[column_index], y_row + row_height), fill=fill, outline=(229, 231, 235), width=1)
            draw.text((x + 8, y_row + 14), value, fill=(31, 41, 55))
            x += column_widths[column_index]
    image.save(output_path, format="PNG")


def _build_recommendations(results: list[dict[str, Any]]) -> list[str]:
    recommendations = [
        "Keep TLS enabled in production configs and disable HTTP fallback outside local demos.",
        "Rotate action/relay/data-encryption secrets periodically and keep them outside static config files.",
        "Forward alerts.jsonl into centralized monitoring with paging for high-severity replay or MAC failures.",
        "Add account recovery and admin incident response flow for repeated login lockouts from shared source IPs.",
        "Extend phishing model coverage with local HF text classifier and periodic adversarial prompt tests.",
    ]
    if any(int(item["attacker_success"]) > 0 for item in results):
        recommendations.append("Tighten thresholds in the scenarios where attacker success remains non-zero.")
    return recommendations


def _build_metrics(results: list[dict[str, Any]]) -> dict[str, int]:
    attempts = sum(int(item["attempts"]) for item in results)
    blocked = sum(int(item["blocked"]) for item in results)
    detected = sum(int(item["detected"]) for item in results)
    attacker_success = sum(int(item["attacker_success"]) for item in results)
    defender_success_rate = int(round((blocked + detected) * 100 / max(1, attempts)))
    return {
        "total_attempts": attempts,
        "blocked": blocked,
        "detected": detected,
        "attacker_success": attacker_success,
        "defender_success_rate_percent": defender_success_rate,
    }


def _images_payload() -> dict[str, dict[str, str]]:
    return {
        "attacker_vs_defender": {
            "name": "attacker_vs_defender.png",
            "url": "/v1/security/evidence/attacker_vs_defender.png",
        },
        "scenario_matrix": {
            "name": "scenario_matrix.png",
            "url": "/v1/security/evidence/scenario_matrix.png",
        },
    }


def run_attack_defense_simulation(base_config: DomainConfig, evidence_root: Path) -> dict[str, Any]:
    ensure_directory(evidence_root)
    sim_root = ensure_directory(evidence_root / f"sim-{new_id()}")
    relay_secret = base_config.relay_secret
    action_secret = base_config.action_secret

    config_a = DomainConfig.from_mapping(
        {
            "domain": "sim-a.test",
            "data_root": str(sim_root / "domainA"),
            "peer_domains": {"sim-b.test": "http://sim-b.test"},
            "action_secret": action_secret,
            "relay_secret": relay_secret,
            "login_max_attempts": 3,
            "login_ip_max_attempts": 30,
            "lockout_seconds": 120,
            "send_rate_limit_per_minute": 3,
            "smart_backend": "heuristic",
        }
    )
    config_b = DomainConfig.from_mapping(
        {
            "domain": "sim-b.test",
            "data_root": str(sim_root / "domainB"),
            "peer_domains": {"sim-a.test": "http://sim-a.test"},
            "action_secret": action_secret,
            "relay_secret": relay_secret,
            "login_max_attempts": 3,
            "login_ip_max_attempts": 30,
            "lockout_seconds": 120,
            "send_rate_limit_per_minute": 3,
            "smart_backend": "heuristic",
        }
    )

    clients: dict[str, TestClient] = {}

    async def relay_dispatch_a(domain: str, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        return _relay(clients[domain], "sim-a.test", path, payload, relay_secret)

    async def relay_dispatch_b(domain: str, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        return _relay(clients[domain], "sim-b.test", path, payload, relay_secret)

    app_a, ctx_a = _create_sim_app(config_a, relay_dispatch=relay_dispatch_a)
    app_b, ctx_b = _create_sim_app(config_b, relay_dispatch=relay_dispatch_b)
    start_workers(ctx_a)
    start_workers(ctx_b)

    try:
        with TestClient(app_a) as client_a, TestClient(app_b) as client_b:
            clients["sim-a.test"] = client_a
            clients["sim-b.test"] = client_b
            results = [
                _scenario_login_lockout(client_a),
                _scenario_replay_attack(client_a),
                _scenario_send_rate_limit(client_a, client_b),
                _scenario_phishing_detection(client_a, client_b),
                _scenario_invalid_attachment(client_a),
            ]
    finally:
        stop_workers(ctx_a)
        stop_workers(ctx_b)

    metrics = _build_metrics(results)
    recommendations = _build_recommendations(results)
    generated_at = isoformat_utc()
    images = _images_payload()
    attacker_png = evidence_root / images["attacker_vs_defender"]["name"]
    matrix_png = evidence_root / images["scenario_matrix"]["name"]
    _draw_attacker_defender_chart(results, attacker_png)
    _draw_scenario_matrix(results, matrix_png)

    report = {
        "status": "ok",
        "generated_at": generated_at,
        "metrics": metrics,
        "scenarios": results,
        "recommendations": recommendations,
        "images": images,
    }
    (evidence_root / "security_report.json").write_text(json.dumps(report, ensure_ascii=True, indent=2), encoding="utf-8")
    return report
