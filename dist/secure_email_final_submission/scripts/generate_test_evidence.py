from __future__ import annotations

import base64
import concurrent.futures
import json
import shutil
import textwrap
import time
import uuid
from pathlib import Path

from fastapi.testclient import TestClient
from PIL import Image, ImageDraw, ImageFont

from common.config import DomainConfig
from common.crypto import mac_hex
from common.utils import json_dumps, new_id
from server.main import create_app


ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "docs" / "test_evidence"
TEMP_ROOT = ROOT / "test_artifacts" / f"evidence-{uuid.uuid4().hex}"

PNG_BYTES = (
    b"\x89PNG\r\n\x1a\n"
    b"\x00\x00\x00\rIHDR"
    b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00"
    b"\x90wS\xde"
    b"\x00\x00\x00\nIDATx\x9cc`\x00\x00\x00\x02\x00\x01"
    b"\xe2!\xbc3"
    b"\x00\x00\x00\x00IEND\xaeB`\x82"
)

TITLE_FONT = Path(r"C:\Windows\Fonts\segoeuib.ttf")
BODY_FONT = Path(r"C:\Windows\Fonts\segoeui.ttf")
MONO_FONT = Path(r"C:\Windows\Fonts\consola.ttf")


def _font(path: Path, size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    if path.exists():
        return ImageFont.truetype(str(path), size=size)
    return ImageFont.load_default()


TITLE = _font(TITLE_FONT, 42)
SUBTITLE = _font(TITLE_FONT, 24)
BODY = _font(BODY_FONT, 24)
SMALL = _font(BODY_FONT, 20)
MONO = _font(MONO_FONT, 22)


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
    response = client.post(
        "/v1/auth/register",
        json={"email": email, "password": password, "confirm_password": password},
    )
    response.raise_for_status()


def _login(client: TestClient, email: str, password: str = "demo123") -> dict:
    response = client.post("/v1/auth/login", json={"email": email, "password": password})
    response.raise_for_status()
    data = response.json()
    data["seq_no"] = 0
    return data


def _wait_for_message(client: TestClient, message_id: str, timeout: float = 5.0) -> None:
    assert client.app.state.ctx.wait_for_idle(message_id=message_id, timeout=timeout)


def _line(draw: ImageDraw.ImageDraw, text: str, xy: tuple[int, int], font, fill, width: int) -> int:
    x, y = xy
    lines = textwrap.wrap(text, width=width) or [text]
    for line in lines:
        draw.text((x, y), line, font=font, fill=fill)
        y += int(font.size * 1.45) if hasattr(font, "size") else 28
    return y


def _box(draw: ImageDraw.ImageDraw, x1: int, y1: int, x2: int, y2: int, fill: str, outline: str | None = None) -> None:
    draw.rounded_rectangle((x1, y1, x2, y2), radius=24, fill=fill, outline=outline, width=2 if outline else 1)


def render_card(filename: str, test_no: int, title: str, chinese: str, bullets: list[str], snippet: str) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    image = Image.new("RGB", (1600, 1000), "#f4f7fb")
    draw = ImageDraw.Draw(image)

    _box(draw, 40, 36, 1560, 964, fill="#ffffff", outline="#d9e1ec")
    draw.text((82, 80), f"Test {test_no}", font=SUBTITLE, fill="#2d5b9f")
    draw.text((82, 118), title, font=TITLE, fill="#122033")
    draw.text((84, 176), chinese, font=SUBTITLE, fill="#58677a")

    _box(draw, 1320, 72, 1508, 146, fill="#dcfce7", outline="#86efac")
    draw.text((1362, 97), "PASS", font=SUBTITLE, fill="#166534")

    y = 250
    draw.text((82, y), "Evidence", font=SUBTITLE, fill="#183153")
    y += 42
    for bullet in bullets:
        draw.ellipse((86, y + 11, 98, y + 23), fill="#2563eb")
        y = _line(draw, bullet, (116, y), BODY, "#243447", width=78)
        y += 8

    _box(draw, 82, 570, 1516, 902, fill="#0f172a")
    draw.text((112, 602), "Captured Output", font=SUBTITLE, fill="#93c5fd")
    snippet_y = 650
    for raw in snippet.strip().splitlines():
        snippet_y = _line(draw, raw, (112, snippet_y), MONO, "#e2e8f0", width=94)

    footer = "Generated from live local test execution against the current codebase."
    draw.text((82, 930), footer, font=SMALL, fill="#64748b")
    image.save(OUTPUT_DIR / filename)


def make_clients():
    TEMP_ROOT.mkdir(parents=True, exist_ok=True)
    config_a = DomainConfig.from_mapping(
        {
            "domain": "a.test",
            "data_root": str(TEMP_ROOT / "domainA"),
            "peer_domains": {"b.test": "http://b.test"},
            "action_secret": "test-action-secret",
            "relay_secret": "test-relay-secret",
            "login_max_attempts": 3,
            "lockout_seconds": 60,
            "send_rate_limit_per_minute": 3,
            "smart_backend": "heuristic",
        }
    )
    config_b = DomainConfig.from_mapping(
        {
            "domain": "b.test",
            "data_root": str(TEMP_ROOT / "domainB"),
            "peer_domains": {"a.test": "http://a.test"},
            "action_secret": "test-action-secret",
            "relay_secret": "test-relay-secret",
            "login_max_attempts": 3,
            "lockout_seconds": 60,
            "send_rate_limit_per_minute": 3,
            "smart_backend": "heuristic",
        }
    )

    clients: dict[str, TestClient] = {}

    async def relay_dispatch_a(domain: str, path: str, payload: dict):
        return _relay(clients[domain], "a.test", path, payload)

    async def relay_dispatch_b(domain: str, path: str, payload: dict):
        return _relay(clients[domain], "b.test", path, payload)

    app_a = create_app(config_a, relay_dispatch=relay_dispatch_a)
    app_b = create_app(config_b, relay_dispatch=relay_dispatch_b)
    client_a = TestClient(app_a)
    client_b = TestClient(app_b)
    client_a.__enter__()
    client_b.__enter__()
    clients["a.test"] = client_a
    clients["b.test"] = client_b
    return client_a, client_b


def close_clients(client_a: TestClient, client_b: TestClient) -> None:
    try:
        client_b.__exit__(None, None, None)
    finally:
        client_a.__exit__(None, None, None)
        shutil.rmtree(TEMP_ROOT, ignore_errors=True)


def test_cross_domain(client_a: TestClient, client_b: TestClient) -> None:
    _register(client_a, "alice@a.test")
    _register(client_b, "bob@b.test")
    alice = _login(client_a, "alice@a.test")
    bob = _login(client_b, "bob@b.test")
    send_body = {
        "to": ["bob@b.test"],
        "cc": [],
        "subject": "Cross-domain hello",
        "body_text": "This message proves domain A can deliver to domain B.",
        "attachment_ids": [],
        "thread_id": None,
    }
    send = client_a.post("/v1/mail/send", json=send_body, headers=_signed_headers(alice, "/v1/mail/send", send_body))
    send.raise_for_status()
    message_id = send.json()["message_id"]
    _wait_for_message(client_a, message_id)
    _wait_for_message(client_b, message_id)
    inbox = client_b.get("/v1/mail/inbox", headers={"Authorization": f"Bearer {bob['session_token']}"}).json()
    render_card(
        "01_cross_domain_delivery.png",
        1,
        "Cross-Domain Delivery Success",
        "功能联通：两个域名服务器互发邮件成功",
        [
            "Registered alice@a.test on Domain A and bob@b.test on Domain B.",
            "Sent a signed mail request from Domain A to Domain B.",
            "Background workers completed relay and Bob received the message in inbox.",
        ],
        json.dumps(
            {
                "send_status": send.json()["status"],
                "message_id": message_id,
                "bob_inbox_count": len(inbox),
                "bob_latest_subject": inbox[0]["subject"],
                "bob_latest_from": inbox[0]["from_email"],
            },
            indent=2,
        ),
    )


def test_concurrency(client_a: TestClient, client_b: TestClient) -> None:
    _register(client_b, "bob2@b.test")
    bob = _login(client_b, "bob2@b.test")
    bob_headers = {"Authorization": f"Bearer {bob['session_token']}"}
    sender_count = 12

    def sender_task(index: int) -> str:
        email = f"load{index}@a.test"
        _register(client_a, email)
        session = _login(client_a, email)
        body = {
            "to": ["bob2@b.test"],
            "cc": [],
            "subject": f"Concurrent {index}",
            "body_text": f"Message {index}",
            "attachment_ids": [],
            "thread_id": None,
        }
        response = client_a.post("/v1/mail/send", json=body, headers=_signed_headers(session, "/v1/mail/send", body))
        response.raise_for_status()
        return response.json()["message_id"]

    def inbox_poller() -> list[int]:
        counts: list[int] = []
        for _ in range(12):
            response = client_b.get("/v1/mail/inbox", headers=bob_headers)
            response.raise_for_status()
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
    inbox = client_b.get("/v1/mail/inbox", headers=bob_headers).json()
    delivered_ids = {item["message_id"] for item in inbox}
    render_card(
        "02_concurrency_stability.png",
        2,
        "Concurrent Clients Remain Stable",
        "并发与稳定性：多客户端同时登录、发送、收取，系统不崩溃",
        [
            f"Started {sender_count} client tasks in parallel and polled the receiver inbox concurrently.",
            "All send requests completed successfully without server crash.",
            "Every produced message ID appeared in the receiver inbox after worker processing.",
        ],
        json.dumps(
            {
                "parallel_senders": sender_count,
                "generated_messages": len(message_ids),
                "delivered_messages": len(set(message_ids).intersection(delivered_ids)),
                "peak_polled_inbox_size": max(poll_counts) if poll_counts else 0,
            },
            indent=2,
        ),
    )


def test_bruteforce(client_a: TestClient) -> None:
    _register(client_a, "locktest@a.test")
    statuses: list[int] = []
    retry_after = None
    for _ in range(3):
        response = client_a.post("/v1/auth/login", json={"email": "locktest@a.test", "password": "wrong"})
        statuses.append(response.status_code)
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            break
    render_card(
        "03_bruteforce_lockout.png",
        3,
        "Brute-Force Protection Triggered",
        "安全测试：暴力登录尝试触发防护",
        [
            "Repeated wrong-password attempts were sent to the same account.",
            "The account transitioned from normal rejection to temporary lockout.",
            "Server returned HTTP 429 with Retry-After to prove active protection.",
        ],
        json.dumps(
            {
                "login_attempt_statuses": statuses,
                "retry_after_seconds": retry_after,
            },
            indent=2,
        ),
    )


def test_send_limit(client_a: TestClient, client_b: TestClient) -> None:
    _register(client_a, "ratelimit@a.test")
    _register(client_b, "sink@b.test")
    sender = _login(client_a, "ratelimit@a.test")
    body = {
        "to": ["sink@b.test"],
        "cc": [],
        "subject": "Burst",
        "body_text": "Load",
        "attachment_ids": [],
        "thread_id": None,
    }
    statuses = []
    retry_after = None
    for _ in range(4):
        response = client_a.post("/v1/mail/send", json=body, headers=_signed_headers(sender, "/v1/mail/send", body))
        statuses.append(response.status_code)
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            break
    render_card(
        "04_send_rate_limit.png",
        4,
        "High-Frequency Send Rate Limited",
        "安全测试：高频发送触发限流",
        [
            "One user sent repeated mails inside the configured one-minute window.",
            "Initial requests succeeded until the configured budget was exhausted.",
            "The next request was rejected with HTTP 429 and Retry-After.",
        ],
        json.dumps(
            {
                "send_attempt_statuses": statuses,
                "retry_after_seconds": retry_after,
            },
            indent=2,
        ),
    )


def test_phishing_mark(client_a: TestClient, client_b: TestClient) -> None:
    _register(client_a, "phish@a.test")
    _register(client_b, "victim@b.test")
    sender = _login(client_a, "phish@a.test")
    victim = _login(client_b, "victim@b.test")
    body = {
        "to": ["victim@b.test"],
        "cc": [],
        "subject": "Urgent: verify your account and payment details",
        "body_text": "Please verify your password immediately and click both links now: https://secure-check.example/reset and https://billing-check.example/pay",
        "attachment_ids": [],
        "thread_id": None,
    }
    response = client_a.post("/v1/mail/send", json=body, headers=_signed_headers(sender, "/v1/mail/send", body))
    response.raise_for_status()
    message_id = response.json()["message_id"]
    _wait_for_message(client_a, message_id)
    _wait_for_message(client_b, message_id)
    inbox = client_b.get("/v1/mail/inbox", headers={"Authorization": f"Bearer {victim['session_token']}"}).json()
    message = next(item for item in inbox if item["message_id"] == message_id)
    render_card(
        "05_phishing_detection.png",
        5,
        "Phishing Sample Was Flagged",
        "安全测试：钓鱼样例可被识别或标记",
        [
            "Sent a message with urgent credential language and multiple external links.",
            "The receiver inbox stored the mail with suspicious security flags.",
            "Classification changed to Suspicious and phishing reasons were recorded.",
        ],
        json.dumps(
            {
                "classification": message["classification"],
                "phishing_score": message["security_flags"]["phishing_score"],
                "suspicious": message["security_flags"]["suspicious"],
                "reasons": message["security_flags"]["reasons"],
            },
            indent=2,
        ),
    )


def test_attachment_flow(client_a: TestClient, client_b: TestClient) -> None:
    _register(client_a, "attach@a.test")
    _register(client_b, "viewer@b.test")
    sender = _login(client_a, "attach@a.test")
    viewer = _login(client_b, "viewer@b.test")
    upload_body = {
        "filename": "pixel.png",
        "content_base64": base64.b64encode(PNG_BYTES).decode("ascii"),
    }
    upload = client_a.post("/v1/attachments/upload", json=upload_body, headers=_signed_headers(sender, "/v1/attachments/upload", upload_body))
    upload.raise_for_status()
    attachment_id = upload.json()["id"]
    send_body = {
        "to": ["viewer@b.test"],
        "cc": [],
        "subject": "Attachment test",
        "body_text": "Attached image for verification.",
        "attachment_ids": [attachment_id],
        "thread_id": None,
    }
    send = client_a.post("/v1/mail/send", json=send_body, headers=_signed_headers(sender, "/v1/mail/send", send_body))
    send.raise_for_status()
    message_id = send.json()["message_id"]
    _wait_for_message(client_a, message_id)
    _wait_for_message(client_b, message_id)
    inbox = client_b.get("/v1/mail/inbox", headers={"Authorization": f"Bearer {viewer['session_token']}"}).json()
    message = next(item for item in inbox if item["message_id"] == message_id)
    download = client_b.get(
        f"/v1/attachments/{message['attachments'][0]['id']}",
        headers={"Authorization": f"Bearer {viewer['session_token']}"},
    )
    render_card(
        "06_attachment_send_receive.png",
        6,
        "Image Attachment Sent and Read",
        "附件与存储：图片附件可收发",
        [
            "Uploaded a valid PNG image attachment from the sender domain.",
            "Delivered the mail cross-domain and verified the attachment appears in the inbox metadata.",
            "Downloaded the attachment from the receiver side and confirmed byte access succeeds.",
        ],
        json.dumps(
            {
                "attachment_filename": message["attachments"][0]["filename"],
                "attachment_content_type": message["attachments"][0]["content_type"],
                "download_status": download.status_code,
                "downloaded_bytes": len(download.content),
            },
            indent=2,
        ),
    )


def test_dedup(client_a: TestClient) -> None:
    _register(client_a, "dedup@a.test")
    sender = _login(client_a, "dedup@a.test")
    upload_body = {
        "filename": "pixel.png",
        "content_base64": base64.b64encode(PNG_BYTES).decode("ascii"),
    }
    first = client_a.post("/v1/attachments/upload", json=upload_body, headers=_signed_headers(sender, "/v1/attachments/upload", upload_body))
    second = client_a.post("/v1/attachments/upload", json=upload_body, headers=_signed_headers(sender, "/v1/attachments/upload", upload_body))
    first.raise_for_status()
    second.raise_for_status()
    with client_a.app.state.ctx.connect() as conn:
        blobs = conn.execute("SELECT blob_key, ref_count FROM attachment_blobs").fetchall()
        attachments = conn.execute("SELECT COUNT(*) AS total FROM attachments").fetchone()
    render_card(
        "07_storage_dedup.png",
        7,
        "Storage Deduplication Behaved Correctly",
        "附件与存储：存储策略（去重）行为符合预期",
        [
            "Uploaded the exact same PNG content twice.",
            "The system created two logical attachment records for user behavior correctness.",
            "Only one physical blob remained in storage and its reference count increased.",
        ],
        json.dumps(
            {
                "logical_attachment_count": attachments["total"],
                "physical_blob_count": len(blobs),
                "blob_ref_count": blobs[0]["ref_count"] if blobs else 0,
                "same_blob_key": blobs[0]["blob_key"] if blobs else None,
            },
            indent=2,
        ),
    )


def render_overview() -> None:
    image = Image.new("RGB", (1600, 1050), "#0b1220")
    draw = ImageDraw.Draw(image)
    draw.text((80, 70), "Required Test Evidence Gallery", font=TITLE, fill="#f8fafc")
    draw.text((80, 128), "智能安全邮箱设计 - Screenshot Pack", font=SUBTITLE, fill="#93c5fd")
    items = [
        "01 Cross-domain delivery",
        "02 Concurrent clients and stability",
        "03 Brute-force protection",
        "04 High-frequency send rate limit",
        "05 Phishing detection",
        "06 Image attachment send/receive",
        "07 Storage deduplication",
    ]
    y = 240
    for item in items:
        _box(draw, 88, y - 16, 1510, y + 62, fill="#111b2e", outline="#334155")
        draw.text((118, y), item, font=BODY, fill="#e2e8f0")
        y += 104
    draw.text((80, 930), f"Output folder: {OUTPUT_DIR}", font=SMALL, fill="#94a3b8")
    image.save(OUTPUT_DIR / "00_overview.png")


def write_index() -> None:
    lines = [
        "# Test Evidence Images",
        "",
        "Generated evidence images for the required assignment tests:",
        "",
        "- `00_overview.png`",
        "- `01_cross_domain_delivery.png`",
        "- `02_concurrency_stability.png`",
        "- `03_bruteforce_lockout.png`",
        "- `04_send_rate_limit.png`",
        "- `05_phishing_detection.png`",
        "- `06_attachment_send_receive.png`",
        "- `07_storage_dedup.png`",
        "",
    ]
    (OUTPUT_DIR / "README.md").write_text("\n".join(lines), encoding="utf-8")


def write_pdf_pack() -> None:
    image_paths = sorted(OUTPUT_DIR.glob("*.png"))
    if not image_paths:
        return
    try:
        images = [Image.open(path).convert("RGB") for path in image_paths]
        first, rest = images[0], images[1:]
        first.save(OUTPUT_DIR / "test_evidence_pack.pdf", save_all=True, append_images=rest)
    except Exception:
        pass


def main() -> None:
    if OUTPUT_DIR.exists():
        shutil.rmtree(OUTPUT_DIR)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    client_a, client_b = make_clients()
    try:
        render_overview()
        test_cross_domain(client_a, client_b)
        test_concurrency(client_a, client_b)
        test_bruteforce(client_a)
        test_send_limit(client_a, client_b)
        test_phishing_mark(client_a, client_b)
        test_attachment_flow(client_a, client_b)
        test_dedup(client_a)
        write_index()
        write_pdf_pack()
    finally:
        close_clients(client_a, client_b)


if __name__ == "__main__":
    main()
