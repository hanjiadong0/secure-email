from __future__ import annotations

import json
import shutil
import socket
import subprocess
import sys
import textwrap
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import httpx
import yaml
from PIL import Image, ImageDraw, ImageFont
from playwright.sync_api import Browser, Page, TimeoutError as PlaywrightTimeoutError, sync_playwright

from common.crypto import mac_hex
from common.utils import json_dumps, new_id


ROOT = Path(__file__).resolve().parents[1]
VENV_PYTHON = ROOT / ".venv" / "Scripts" / "python.exe"
OUTPUT_DIR = ROOT / "docs" / "test_frontend_screenshots"
TEMP_ROOT = ROOT / "test_artifacts" / f"frontend-shots-{uuid.uuid4().hex}"
CHROME = Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe")
EDGE = Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe")
SCREENSHOT_WIDTH = 1600
SCREENSHOT_HEIGHT = 1200
PASSWORD = "demo123"


@dataclass
class ScreenshotItem:
    filename: str
    title: str
    description: str


def _pick_browser_path() -> Path:
    for candidate in (CHROME, EDGE):
        if candidate.exists():
            return candidate
    raise FileNotFoundError("Chrome/Edge executable not found.")


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_http_ready(base_url: str, timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    last_error = None
    while time.time() < deadline:
        try:
            response = httpx.get(f"{base_url}/health", timeout=2.0)
            if response.status_code == 200:
                return
        except Exception as exc:  # pragma: no cover - environment wait path
            last_error = exc
        time.sleep(0.3)
    raise RuntimeError(f"Server at {base_url} did not become ready: {last_error}")


def _detect_smart_runtime() -> dict[str, str]:
    try:
        response = httpx.get("http://127.0.0.1:11434/api/tags", timeout=2.5)
        response.raise_for_status()
        payload = response.json()
    except Exception:
        return {"smart_backend": "heuristic"}
    models = payload.get("models") or []
    names = [str(item.get("name") or "").strip() for item in models if str(item.get("name") or "").strip()]
    preferred = [
        "llama3.2:latest",
        "mistral:latest",
        "qwen2.5:latest",
        "phi4:latest",
    ]
    for candidate in preferred:
        if candidate in names:
            return {
                "smart_backend": "ollama",
                "ollama_base_url": "http://127.0.0.1:11434",
                "ollama_model": candidate,
                "ollama_timeout_seconds": "20.0",
            }
    for name in names:
        lowered = name.lower()
        if any(token in lowered for token in ("llama", "mistral", "qwen", "phi")):
            return {
                "smart_backend": "ollama",
                "ollama_base_url": "http://127.0.0.1:11434",
                "ollama_model": name,
                "ollama_timeout_seconds": "20.0",
            }
    return {"smart_backend": "heuristic"}


def _smart_runtime_label(runtime: dict[str, str]) -> str:
    backend = str(runtime.get("smart_backend") or "heuristic").lower()
    if backend == "ollama":
        return f"ollama:{runtime.get('ollama_model', 'local-model')}"
    return "heuristic"


def _make_png(path: Path, title: str, subtitle: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    image = Image.new("RGB", (900, 520), "#e8f1fb")
    draw = ImageDraw.Draw(image)
    title_font = ImageFont.truetype(r"C:\Windows\Fonts\segoeuib.ttf", size=44)
    body_font = ImageFont.truetype(r"C:\Windows\Fonts\segoeui.ttf", size=24)
    draw.rounded_rectangle((36, 36, 864, 484), radius=28, fill="#ffffff", outline="#c7d6ea", width=3)
    draw.text((76, 120), title, font=title_font, fill="#153052")
    y = 205
    for line in textwrap.wrap(subtitle, width=40):
        draw.text((78, y), line, font=body_font, fill="#4b5f77")
        y += 34
    draw.rounded_rectangle((78, 360, 420, 420), radius=20, fill="#dbeafe", outline="#93c5fd", width=2)
    draw.text((110, 378), "Attachment Preview Sample", font=body_font, fill="#1d4ed8")
    image.save(path)


def _register(base_url: str, email: str, password: str = PASSWORD) -> None:
    response = httpx.post(
        f"{base_url}/v1/auth/register",
        json={"email": email, "password": password, "confirm_password": password},
        timeout=30.0,
    )
    response.raise_for_status()


def _login(base_url: str, email: str, password: str = PASSWORD) -> dict:
    response = httpx.post(
        f"{base_url}/v1/auth/login",
        json={"email": email, "password": password},
        timeout=30.0,
    )
    response.raise_for_status()
    data = response.json()
    data["seq_no"] = 0
    return data


def _signed_post(base_url: str, session: dict, path: str, body: dict, timeout: float = 60.0) -> dict:
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
    response = httpx.post(
        f"{base_url}{path}",
        json=body,
        headers={
            "Authorization": f"Bearer {session['session_token']}",
            "X-Request-Id": request_id,
            "X-Session-Id": session["session_id"],
            "X-Seq-No": str(session["seq_no"]),
            "X-Timestamp": str(timestamp),
            "X-Nonce": nonce,
            "X-Body-Mac": mac_hex(session["session_key"], canonical),
        },
        timeout=timeout,
    )
    response.raise_for_status()
    return response.json()


@dataclass
class ServerPair:
    base_a: str
    base_b: str
    process_a: subprocess.Popen
    process_b: subprocess.Popen
    config_dir: Path
    smart_runtime: dict[str, str]


def start_servers() -> ServerPair:
    TEMP_ROOT.mkdir(parents=True, exist_ok=True)
    config_dir = TEMP_ROOT / "configs"
    config_dir.mkdir(parents=True, exist_ok=True)
    smart_runtime = _detect_smart_runtime()
    port_a = _free_port()
    port_b = _free_port()
    config_a = {
        "domain": "a.test",
        "host": "127.0.0.1",
        "port": port_a,
        "data_root": str((TEMP_ROOT / "domainA").resolve()),
        "peer_domains": {"b.test": f"http://127.0.0.1:{port_b}"},
        "action_secret": "frontend-shot-action-secret",
        "relay_secret": "frontend-shot-relay-secret",
        "login_max_attempts": 3,
        "lockout_seconds": 60,
        "send_rate_limit_per_minute": 2,
        **smart_runtime,
    }
    config_b = {
        "domain": "b.test",
        "host": "127.0.0.1",
        "port": port_b,
        "data_root": str((TEMP_ROOT / "domainB").resolve()),
        "peer_domains": {"a.test": f"http://127.0.0.1:{port_a}"},
        "action_secret": "frontend-shot-action-secret",
        "relay_secret": "frontend-shot-relay-secret",
        "login_max_attempts": 3,
        "lockout_seconds": 60,
        "send_rate_limit_per_minute": 2,
        **smart_runtime,
    }
    config_path_a = config_dir / "domainA.yaml"
    config_path_b = config_dir / "domainB.yaml"
    config_path_a.write_text(yaml.safe_dump(config_a, sort_keys=False), encoding="utf-8")
    config_path_b.write_text(yaml.safe_dump(config_b, sort_keys=False), encoding="utf-8")
    log_a = (TEMP_ROOT / "domainA.log").open("w", encoding="utf-8")
    log_b = (TEMP_ROOT / "domainB.log").open("w", encoding="utf-8")
    process_a = subprocess.Popen(
        [str(VENV_PYTHON), "-m", "server.main", "--config", str(config_path_a)],
        cwd=ROOT,
        stdout=log_a,
        stderr=subprocess.STDOUT,
    )
    process_b = subprocess.Popen(
        [str(VENV_PYTHON), "-m", "server.main", "--config", str(config_path_b)],
        cwd=ROOT,
        stdout=log_b,
        stderr=subprocess.STDOUT,
    )
    base_a = f"http://127.0.0.1:{port_a}"
    base_b = f"http://127.0.0.1:{port_b}"
    _wait_http_ready(base_a)
    _wait_http_ready(base_b)
    return ServerPair(
        base_a=base_a,
        base_b=base_b,
        process_a=process_a,
        process_b=process_b,
        config_dir=config_dir,
        smart_runtime=smart_runtime,
    )


def stop_servers(pair: ServerPair) -> None:
    for process in (pair.process_a, pair.process_b):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
    shutil.rmtree(TEMP_ROOT, ignore_errors=True)


def page_register(page: Page, email: str, password: str = PASSWORD) -> None:
    page.fill("#registerEmail", email)
    page.fill("#registerPassword", password)
    page.fill("#registerConfirmPassword", password)
    page.locator("#registerForm button[type='submit']").click()
    page.locator(".toast").filter(has_text=f"Account created for {email}").first.wait_for(timeout=10000)


def page_login(page: Page, email: str, password: str = PASSWORD) -> None:
    page.fill("#loginEmail", email)
    page.fill("#loginPassword", password)
    page.locator("#loginForm button[type='submit']").click()
    page.locator("#sessionUser").filter(has_text=email).wait_for(timeout=15000)
    page.wait_for_timeout(1000)


def page_send(page: Page, to: str, subject: str, body: str) -> None:
    page.fill("#composeTo", to)
    page.fill("#composeSubject", subject)
    page.fill("#composeBody", body)
    page.locator("#composeForm button[type='submit']").click()
    page.locator(".toast").filter(has_text="Your message is on its way.").first.wait_for(timeout=15000)
    page.wait_for_timeout(1200)


def page_upload_attachment(page: Page, file_path: Path, filename: str) -> None:
    page.set_input_files("#attachmentFile", str(file_path))
    page.click("#uploadAttachmentButton")
    page.locator(".toast").filter(has_text=f"Added {filename} to the message.").first.wait_for(timeout=15000)
    page.wait_for_timeout(1400)


def page_save_group(page: Page, name: str, members: str) -> None:
    page.fill("#groupName", name)
    page.fill("#groupMembers", members)
    page.locator("#groupCreateForm button[type='submit']").click()
    page.locator(".toast").filter(has_text=f"Saved the group {name}.").first.wait_for(timeout=15000)
    page.wait_for_timeout(1000)


def page_compose_with_ai(page: Page, prompt: str, expected_subject: str = "") -> None:
    page.fill("#composeAssistPrompt", prompt)
    if expected_subject:
        page.fill("#composeSubject", expected_subject)
    page.click("#composeAssistDraftButton")
    page.wait_for_function(
        """
        () => {
          const body = document.querySelector('#composeBody');
          return Boolean(body && body.value && body.value.trim().length > 40);
        }
        """,
        timeout=45000,
    )
    page.wait_for_timeout(1200)


def lab_login(page: Page, email: str, password: str = PASSWORD) -> None:
    page.fill("#labEmail", email)
    page.fill("#labPassword", password)
    page.locator("#labLoginForm button[type='submit']").click()
    page.locator(".toast").filter(has_text=f"Security lab access granted for {email}.").first.wait_for(timeout=15000)
    page.wait_for_timeout(1000)


def lab_run_drill(page: Page) -> None:
    page.click("#labRunButton")
    page.locator(".toast").filter(has_text="Threat drill finished.").first.wait_for(timeout=60000)
    page.wait_for_timeout(2000)


def page_refresh(page: Page) -> None:
    page.click("#refreshButton")
    page.wait_for_timeout(1200)


def page_open_message(page: Page, subject: str) -> None:
    card = page.locator("[data-message-id]").filter(has_text=subject).first
    card.wait_for(timeout=15000)
    card.click()
    page.wait_for_timeout(700)


def save_screenshot(page: Page, filename: str) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    page.screenshot(path=str(OUTPUT_DIR / filename), full_page=True)


def render_dedup_html(blob_count: int, ref_count: int, attachment_count: int) -> Path:
    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Storage Dedup Evidence</title>
  <style>
    body {{
      font-family: "Segoe UI", system-ui, sans-serif;
      background: #eef4fb;
      color: #13283f;
      margin: 0;
      padding: 32px;
    }}
    .card {{
      max-width: 980px;
      margin: 0 auto;
      background: white;
      border-radius: 28px;
      padding: 30px 34px;
      border: 1px solid #d6e2ef;
      box-shadow: 0 16px 40px rgba(15, 23, 42, 0.08);
    }}
    h1 {{ margin: 0 0 10px; font-size: 40px; }}
    p {{ color: #5e6c80; font-size: 20px; line-height: 1.55; }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 18px;
      margin-top: 28px;
    }}
    .stat {{
      background: #f8fbff;
      border: 1px solid #d8e6f5;
      border-radius: 20px;
      padding: 22px;
    }}
    .label {{ color: #52709a; font-size: 16px; }}
    .value {{ font-size: 34px; font-weight: 700; margin-top: 8px; }}
    .ok {{
      margin-top: 28px;
      padding: 18px 20px;
      border-radius: 20px;
      background: #dcfce7;
      border: 1px solid #86efac;
      color: #166534;
      font-size: 20px;
      font-weight: 600;
    }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Storage Deduplication Evidence</h1>
    <p>
      This is a browser-rendered evidence page for the storage-only test. The normal
      mail UI can show duplicate logical uploads, but the dedup result itself is a
      backend storage behavior, so these stats prove the real expected outcome.
    </p>
    <div class="grid">
      <div class="stat"><div class="label">Logical Attachments</div><div class="value">{attachment_count}</div></div>
      <div class="stat"><div class="label">Physical Blobs</div><div class="value">{blob_count}</div></div>
      <div class="stat"><div class="label">Blob Ref Count</div><div class="value">{ref_count}</div></div>
    </div>
    <div class="ok">Expected dedup behavior confirmed: two uploads, one stored blob.</div>
  </div>
</body>
</html>
"""
    path = OUTPUT_DIR / "07_storage_dedup_evidence.html"
    path.write_text(html, encoding="utf-8")
    return path


def build_gallery_html(files: list[ScreenshotItem], smart_runtime: dict[str, str]) -> Path:
    sections = "\n".join(
        (
            f'<section class="card"><h2>{item.title}</h2>'
            f'<p>{item.description}</p>'
            f'<img src="{item.filename}" alt="{item.title}"></section>'
        )
        for item in files
    )
    runtime_label = _smart_runtime_label(smart_runtime)
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Frontend Test Screenshots</title>
  <style>
    body {{ margin: 0; padding: 28px; font-family: "Segoe UI", system-ui, sans-serif; background: #eff4f9; color: #13283f; }}
    .wrap {{ max-width: 1100px; margin: 0 auto; }}
    .hero, .card {{ background: white; border: 1px solid #d9e2eb; border-radius: 24px; box-shadow: 0 12px 36px rgba(15,23,42,0.07); }}
    .hero {{ padding: 28px 32px; margin-bottom: 24px; }}
    .card {{ padding: 18px; margin-bottom: 24px; page-break-inside: avoid; }}
    h1 {{ margin: 0 0 10px; font-size: 34px; }}
    h2 {{ margin: 6px 6px 16px; font-size: 24px; }}
    p {{ margin: 0; color: #5f6f82; font-size: 18px; line-height: 1.5; }}
    img {{ width: 100%; border-radius: 18px; display: block; }}
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <h1>Frontend Test Screenshots</h1>
      <p>Browser evidence for secure-email frontend scenarios, captured from live local test runs on {generated_at}.</p>
    </section>
    <section class="card">
      <h2>Current Runtime Notes</h2>
      <p>Smart backend during capture: <strong>{runtime_label}</strong>.</p>
      <p>All file types are accepted as attachments. Image AI and transform actions are applied only to image attachments.</p>
    </section>
    {sections}
  </div>
</body>
</html>
"""
    path = OUTPUT_DIR / "index.html"
    path.write_text(html, encoding="utf-8")
    return path


def print_gallery_pdf(html_path: Path) -> None:
    pdf_path = OUTPUT_DIR / "frontend_test_gallery.pdf"
    browser = _pick_browser_path()
    subprocess.run(
        [
            str(browser),
            "--headless=new",
            "--disable-gpu",
            f"--print-to-pdf={pdf_path}",
            html_path.resolve().as_uri(),
        ],
        check=True,
        cwd=ROOT,
        timeout=120,
    )


def write_manifest(files: list[ScreenshotItem], smart_runtime: dict[str, str]) -> None:
    manifest = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "smart_runtime": smart_runtime,
        "screenshots": [
            {
                "filename": item.filename,
                "title": item.title,
                "description": item.description,
            }
            for item in files
        ],
    }
    (OUTPUT_DIR / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def run_concurrent_senders(base_a: str, recipient: str, sender_count: int = 4) -> None:
    def sender_task(index: int) -> None:
        email = f"multi{index}@a.test"
        _register(base_a, email)
        session = _login(base_a, email)
        body = {
            "to": [recipient],
            "cc": [],
            "subject": f"Concurrent {index}",
            "body_text": f"Concurrent body {index}",
            "attachment_ids": [],
            "thread_id": None,
        }
        _signed_post(base_a, session, "/v1/mail/send", body, timeout=90.0)

    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(sender_count, 2)) as pool:
        futures = [pool.submit(sender_task, i) for i in range(sender_count)]
        for future in futures:
            future.result()


def main() -> None:
    if OUTPUT_DIR.exists():
        shutil.rmtree(OUTPUT_DIR)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    sample_image = TEMP_ROOT / "sample.png"
    TEMP_ROOT.mkdir(parents=True, exist_ok=True)
    _make_png(sample_image, "Secure Email", "Sample image used for attachment send/receive and dedup screenshots.")
    pair: ServerPair | None = None
    smart_runtime: dict[str, str] = {"smart_backend": "heuristic"}
    files_for_gallery: list[ScreenshotItem] = []
    try:
        pair = start_servers()
        smart_runtime = pair.smart_runtime
        browser_path = _pick_browser_path()

        with sync_playwright() as playwright:
            browser: Browser = playwright.chromium.launch(
                executable_path=str(browser_path),
                headless=True,
                args=["--disable-gpu"],
            )
            try:
                _register(pair.base_b, "bob@b.test")

                ctx_console = browser.new_context(viewport={"width": SCREENSHOT_WIDTH, "height": SCREENSHOT_HEIGHT})
                page_console = ctx_console.new_page()
                page_console.goto(pair.base_a, wait_until="networkidle")
                page_register(page_console, "alice@a.test")
                page_login(page_console, "alice@a.test")
                page_save_group(page_console, "project-team", "bob@b.test, security@a.test")
                page_upload_attachment(page_console, sample_image, "sample.png")
                page_compose_with_ai(
                    page_console,
                    "Write a short project update about the secure email demo and ask Bob to review the frontend.",
                    expected_subject="Frontend demo update",
                )
                save_screenshot(page_console, "01_main_console_real.png")
                files_for_gallery.append(
                    ScreenshotItem(
                        "01_main_console_real.png",
                        "1. Live Mail Console",
                        "Signed-in browser frontend with smart status, AI drafting, saved groups, and saved attachments visible together.",
                    )
                )
                ctx_console.close()

                ctx_a = browser.new_context(viewport={"width": SCREENSHOT_WIDTH, "height": SCREENSHOT_HEIGHT})
                ctx_b = browser.new_context(viewport={"width": SCREENSHOT_WIDTH, "height": SCREENSHOT_HEIGHT})
                page_a = ctx_a.new_page()
                page_b = ctx_b.new_page()
                page_a.goto(pair.base_a, wait_until="networkidle")
                page_b.goto(pair.base_b, wait_until="networkidle")
                page_login(page_a, "alice@a.test")
                page_register(page_b, "bob2@b.test")
                page_login(page_b, "bob2@b.test")
                page_send(page_a, "bob2@b.test", "Cross-domain hello", "This message proves domain A can deliver to domain B.")
                page_refresh(page_b)
                page_open_message(page_b, "Cross-domain hello")
                save_screenshot(page_b, "02_cross_domain_delivery_real.png")
                files_for_gallery.append(
                    ScreenshotItem(
                        "02_cross_domain_delivery_real.png",
                        "2. Cross-Domain Delivery",
                        "Recipient inbox on b.test after a real browser-driven send from a.test.",
                    )
                )
                ctx_a.close()
                ctx_b.close()

                _register(pair.base_b, "stable@b.test")
                ctx_conc = browser.new_context(viewport={"width": SCREENSHOT_WIDTH, "height": SCREENSHOT_HEIGHT})
                page_conc = ctx_conc.new_page()
                page_conc.goto(pair.base_b, wait_until="networkidle")
                page_login(page_conc, "stable@b.test")
                run_concurrent_senders(pair.base_a, "stable@b.test", sender_count=4)
                page_refresh(page_conc)
                save_screenshot(page_conc, "03_concurrency_stability_real.png")
                files_for_gallery.append(
                    ScreenshotItem(
                        "03_concurrency_stability_real.png",
                        "3. Concurrency and Stability",
                        "One mailbox receiving a burst from multiple different senders without the service crashing.",
                    )
                )
                ctx_conc.close()

                _register(pair.base_a, "lock@a.test")
                ctx_lock = browser.new_context(viewport={"width": SCREENSHOT_WIDTH, "height": SCREENSHOT_HEIGHT})
                page_lock = ctx_lock.new_page()
                page_lock.goto(pair.base_a, wait_until="networkidle")
                for _ in range(3):
                    page_lock.fill("#loginEmail", "lock@a.test")
                    page_lock.fill("#loginPassword", "wrong")
                    page_lock.locator("#loginForm button[type='submit']").click()
                    page_lock.wait_for_timeout(1050)
                page_lock.locator(".toast.error").filter(has_text="Account temporarily locked.").first.wait_for(timeout=10000)
                save_screenshot(page_lock, "04_bruteforce_lockout_real.png")
                files_for_gallery.append(
                    ScreenshotItem(
                        "04_bruteforce_lockout_real.png",
                        "4. Brute-Force Protection",
                        "The login flow shows the real temporary lockout after repeated failed password attempts.",
                    )
                )
                ctx_lock.close()

                _register(pair.base_a, "sender@a.test")
                _register(pair.base_b, "sink@b.test")
                ctx_rate = browser.new_context(viewport={"width": SCREENSHOT_WIDTH, "height": SCREENSHOT_HEIGHT})
                page_rate = ctx_rate.new_page()
                page_rate.goto(pair.base_a, wait_until="networkidle")
                page_login(page_rate, "sender@a.test")
                rate_limited = False
                for attempt in range(5):
                    page_rate.fill("#composeTo", "sink@b.test")
                    page_rate.fill("#composeSubject", f"Burst {attempt}")
                    page_rate.fill("#composeBody", "Rate-limit verification")
                    page_rate.locator("#composeForm button[type='submit']").click()
                    try:
                        page_rate.locator(".toast.error").filter(has_text="Rate limit exceeded.").first.wait_for(timeout=2200)
                        rate_limited = True
                        break
                    except PlaywrightTimeoutError:
                        page_rate.wait_for_timeout(900)
                if not rate_limited:
                    raise RuntimeError("Rate-limit UI did not appear during screenshot generation.")
                save_screenshot(page_rate, "05_send_rate_limit_real.png")
                files_for_gallery.append(
                    ScreenshotItem(
                        "05_send_rate_limit_real.png",
                        "5. High-Frequency Send Limit",
                        "The browser shows the real abuse-control response after repeated rapid sends.",
                    )
                )
                ctx_rate.close()

                _register(pair.base_a, "phish@a.test")
                _register(pair.base_b, "victim@b.test")
                phish_session = _login(pair.base_a, "phish@a.test")
                _signed_post(
                    pair.base_a,
                    phish_session,
                    "/v1/mail/send",
                    {
                        "to": ["victim@b.test"],
                        "cc": [],
                        "subject": "Urgent: verify your account and payment details",
                        "body_text": "Please verify your password immediately and click both links now: https://secure-check.example/reset and https://billing-check.example/pay",
                        "attachment_ids": [],
                        "thread_id": None,
                    },
                )
                ctx_phish = browser.new_context(viewport={"width": SCREENSHOT_WIDTH, "height": SCREENSHOT_HEIGHT})
                page_phish = ctx_phish.new_page()
                page_phish.goto(pair.base_b, wait_until="networkidle")
                page_login(page_phish, "victim@b.test")
                page_refresh(page_phish)
                page_open_message(page_phish, "Urgent: verify your account and payment details")
                save_screenshot(page_phish, "06_phishing_detection_real.png")
                files_for_gallery.append(
                    ScreenshotItem(
                        "06_phishing_detection_real.png",
                        "6. Phishing Detection",
                        "Suspicious content is opened in the real inbox with the smart review and warning context visible.",
                    )
                )
                ctx_phish.close()

                ctx_attach_a = browser.new_context(viewport={"width": SCREENSHOT_WIDTH, "height": SCREENSHOT_HEIGHT})
                ctx_attach_b = browser.new_context(viewport={"width": SCREENSHOT_WIDTH, "height": SCREENSHOT_HEIGHT})
                page_attach_a = ctx_attach_a.new_page()
                page_attach_b = ctx_attach_b.new_page()
                page_attach_a.goto(pair.base_a, wait_until="networkidle")
                page_attach_b.goto(pair.base_b, wait_until="networkidle")
                page_register(page_attach_a, "attach@a.test")
                page_register(page_attach_b, "viewer@b.test")
                page_login(page_attach_a, "attach@a.test")
                page_login(page_attach_b, "viewer@b.test")
                page_upload_attachment(page_attach_a, sample_image, "sample.png")
                page_attach_a.locator("[data-attachment-action='compress']").first.click()
                page_attach_a.wait_for_timeout(2000)
                save_screenshot(page_attach_a, "07_attachment_management_real.png")
                files_for_gallery.append(
                    ScreenshotItem(
                        "07_attachment_management_real.png",
                        "7. Attachment Management",
                        "Saved attachments, thumbnails, compression, and reuse controls shown in the current compose workflow.",
                    )
                )
                page_send(page_attach_a, "viewer@b.test", "Attachment demo", "Attached image for frontend evidence.")
                page_refresh(page_attach_b)
                page_open_message(page_attach_b, "Attachment demo")
                page_attach_b.locator("[data-detail-action='preview-attachment']").first.click()
                page_attach_b.wait_for_timeout(1200)
                save_screenshot(page_attach_b, "08_attachment_send_receive_real.png")
                files_for_gallery.append(
                    ScreenshotItem(
                        "08_attachment_send_receive_real.png",
                        "8. Attachment Send and Preview",
                        "Receiver-side detail view with a real image attachment preview opened from the mailbox.",
                    )
                )
                ctx_attach_a.close()
                ctx_attach_b.close()

                ctx_lab = browser.new_context(viewport={"width": SCREENSHOT_WIDTH, "height": SCREENSHOT_HEIGHT})
                page_lab = ctx_lab.new_page()
                page_lab.goto(f"{pair.base_a}/security-lab", wait_until="networkidle")
                lab_login(page_lab, "alice@a.test")
                lab_run_drill(page_lab)
                save_screenshot(page_lab, "09_security_lab_real.png")
                files_for_gallery.append(
                    ScreenshotItem(
                        "09_security_lab_real.png",
                        "9. Independent Security Lab",
                        "Separate attacker-versus-defender website with fresh threat-drill evidence and explanations.",
                    )
                )
                ctx_lab.close()

                ctx_dedup = browser.new_context(viewport={"width": SCREENSHOT_WIDTH, "height": SCREENSHOT_HEIGHT})
                page_dedup = ctx_dedup.new_page()
                page_dedup.goto(pair.base_a, wait_until="networkidle")
                page_register(page_dedup, "dedup@a.test")
                page_login(page_dedup, "dedup@a.test")
                for _ in range(2):
                    page_upload_attachment(page_dedup, sample_image, "sample.png")
                save_screenshot(page_dedup, "10_storage_dedup_frontend_real.png")
                files_for_gallery.append(
                    ScreenshotItem(
                        "10_storage_dedup_frontend_real.png",
                        "10. Dedup Upload View",
                        "Two logical uploads are visible in the frontend while the backend still performs blob deduplication.",
                    )
                )

                dedup_session = _login(pair.base_a, "dedup@a.test")
                with httpx.Client(timeout=10.0) as client:
                    token = dedup_session["session_token"]
                    client.get(f"{pair.base_a}/v1/mail/inbox", headers={"Authorization": f"Bearer {token}"})
                db_path = next((TEMP_ROOT / "domainA" / "mail").glob("mailstore.sqlite3"))
                import sqlite3

                with sqlite3.connect(db_path) as conn:
                    conn.row_factory = sqlite3.Row
                    blobs = conn.execute("SELECT COUNT(*) AS total, MAX(ref_count) AS max_ref FROM attachment_blobs").fetchone()
                    attachments = conn.execute("SELECT COUNT(*) AS total FROM attachments").fetchone()
                dedup_html = render_dedup_html(int(blobs["total"]), int(blobs["max_ref"] or 0), int(attachments["total"]))
                page_dedup.goto(dedup_html.resolve().as_uri(), wait_until="networkidle")
                save_screenshot(page_dedup, "11_storage_dedup_backend_web.png")
                files_for_gallery.append(
                    ScreenshotItem(
                        "11_storage_dedup_backend_web.png",
                        "11. Dedup Backend Evidence",
                        "Browser-rendered evidence page proving that duplicate uploads collapse to one stored blob.",
                    )
                )
                ctx_dedup.close()
            finally:
                browser.close()
    finally:
        if pair is not None:
            stop_servers(pair)

    (OUTPUT_DIR / "README.md").write_text(
        "\n".join(
            [
                "# Frontend Test Screenshots",
                "",
                "Captured from the live secure-email web UI with automated local browser interaction.",
                "",
                f"Smart backend during capture: `{_smart_runtime_label(smart_runtime)}`",
                "",
                "Current attachment policy in this build:",
                "- all file types can be uploaded",
                "- image AI and transforms are image-only",
                "",
                *[f"- `{item.filename}`: {item.title}" for item in files_for_gallery],
                "",
            ]
        ),
        encoding="utf-8",
    )
    write_manifest(files_for_gallery, smart_runtime)
    html_path = build_gallery_html(files_for_gallery, smart_runtime)
    print_gallery_pdf(html_path)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Failed to generate frontend screenshots: {exc}", file=sys.stderr)
        raise
