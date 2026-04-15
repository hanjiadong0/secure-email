from __future__ import annotations
from collections import defaultdict
from datetime import timedelta
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request

from common.crypto import sign_payload, verify_signed_payload
from common.schemas import (
    ActionExecutionRequest,
    AttachmentMeta,
    CalendarEvent,
    ContactSuggestion,
    DraftRequest,
    GroupSummary,
    GroupCreateRequest,
    GroupMemberRequest,
    GroupSendRequest,
    MailboxDashboardResponse,
    MailSummary,
    RecallRequest,
    SearchResponse,
    SendMailRequest,
    TodoItem,
)
from common.text_features import fuzzy_score
from common.utils import email_domain, is_valid_email, isoformat_utc, new_id, normalize_email, parse_timestamp, utcnow
from server.attachments import export_attachment_payloads, load_attachment_metas
from server.auth import get_current_user, verify_authenticated_request
from server.logging import log_event
from server.rate_limit import enforce_send_limits
from server.smart import analyze_message_features
from server.storage import AppContext


E2E_SUBJECT_PLACEHOLDER = "[End-to-end encrypted message]"
E2E_BODY_PLACEHOLDER = (
    "This message is end-to-end encrypted. Open it in a compatible client with your private key to decrypt it."
)
ACTION_TOKEN_TTL_HOURS = 72
ACTION_TOKEN_MAX_LIFETIME_HOURS = 14 * 24


def _client_ip(request: Request) -> str:
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


async def _signed_payload_from_request(request: Request) -> dict[str, Any]:
    try:
        payload = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Request body must be valid JSON.") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Request body must be a JSON object.")
    return payload


def _touch_contacts(conn, owner_email: str, contacts: list[str], source: str) -> None:
    timestamp = isoformat_utc()
    for contact in {normalize_email(item) for item in contacts if item and normalize_email(item) != owner_email}:
        conn.execute(
            "INSERT INTO contacts(owner_email, contact_email, last_seen_at, source) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(owner_email, contact_email) DO UPDATE SET last_seen_at = excluded.last_seen_at, source = excluded.source",
            (owner_email, contact, timestamp, source),
        )    


def _dedupe_emails(items: list[str]) -> list[str]:
    seen: set[str] = set()
    normalized_items: list[str] = []
    for item in items:
        normalized = normalize_email(item)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        normalized_items.append(normalized)
    return normalized_items


def _validated_email_list(items: list[str], field_name: str) -> list[str]:
    normalized_items = _dedupe_emails(items)
    invalid = [item for item in normalized_items if not is_valid_email(item)]
    if invalid:
        raise HTTPException(status_code=400, detail=f"Invalid email address in {field_name}: {', '.join(invalid)}")
    return normalized_items


def _validated_group_name(name: str) -> str:
    normalized = (name or "").strip()
    if not normalized:
        raise HTTPException(status_code=400, detail="Group name is required.")
    return normalized[:80]


def _calendar_title_from_subject(subject: str) -> str:
    normalized_subject = (subject or "").strip()
    if not normalized_subject:
        normalized_subject = "Message follow-up"
    return f"Mail follow-up: {normalized_subject[:64]}"


def _infer_calendar_start(subject: str, body_text: str) -> str:
    text = f"{subject} {body_text}".lower()
    now = utcnow().replace(second=0, microsecond=0)
    if "tomorrow" in text:
        return isoformat_utc((now + timedelta(days=1)).replace(hour=9, minute=0))
    if "today" in text:
        return isoformat_utc((now + timedelta(hours=1)).replace(minute=0))
    if any(token in text for token in {"meeting", "call", "deadline", "appointment", "review"}):
        return isoformat_utc((now + timedelta(hours=2)).replace(minute=0))
    return isoformat_utc((now + timedelta(days=1)).replace(hour=10, minute=0))


def _build_actions(
    ctx: AppContext,
    message_id: str,
    recipient_email: str,
    subject: str,
    body_text: str,
    suspicious: bool = False,
) -> list[dict[str, str]]:
    normalized_subject = (subject or "").strip() or "Message"
    todo_title = f"Follow up: {normalized_subject[:48]}"
    actions = [
        {"action": "add_todo", "label": "Add Follow-Up", "title": todo_title},
        {
            "action": "add_calendar_event",
            "label": "Add To Calendar",
            "title": _calendar_title_from_subject(subject),
        },
        {"action": "acknowledge", "label": "Mark As Read", "title": "Acknowledge message"},
        {
            "action": "report_phishing",
            "label": "Report Phishing" if suspicious else "Report Suspicious",
            "title": "User-reported suspicious message",
        },
    ]
    issued_at = isoformat_utc()
    expires_at = isoformat_utc(utcnow() + timedelta(hours=ACTION_TOKEN_TTL_HOURS))
    signed: list[dict[str, str]] = []
    for action in actions:
        payload = {
            "message_id": message_id,
            "recipient": recipient_email,
            "action": action["action"],
            "title": action["title"],
            "issued_at": issued_at,
            "expires_at": expires_at,
            "nonce": new_id(),
        }
        signed.append(
            {
                "action": action["action"],
                "label": action["label"],
                "token": sign_payload(ctx.config.action_secret, payload),
            }
        )
    return signed


def _mail_row_to_summary(ctx: AppContext, row) -> MailSummary:
    to = ctx.decrypt_json(row["to_json"]) or []
    cc = ctx.decrypt_json(row["cc_json"]) or []
    attachments = [AttachmentMeta(**item) for item in (ctx.decrypt_json(row["attachments_json"]) or [])]
    security_flags = ctx.decrypt_json(row["security_flags_json"]) or {}
    keywords = ctx.decrypt_json(row["keywords_json"]) or []
    quick_replies = ctx.decrypt_json(row["quick_replies_json"]) or []
    actions = ctx.decrypt_json(row["actions_json"]) or []
    e2e_envelope = ctx.decrypt_json(row["e2e_envelope_json"]) or {}
    return MailSummary(
        message_id=row["message_id"],
        thread_id=row["thread_id"],
        folder=row["folder"],
        delivery_state=row["delivery_state"],
        from_email=ctx.decrypt_text(row["from_email"]),
        to=to,
        cc=cc,
        subject=ctx.decrypt_text(row["subject"]),
        body_text=ctx.decrypt_text(row["body_text"]),
        created_at=row["created_at"],
        attachments=attachments,
        security_flags=security_flags,
        keywords=keywords,
        classification=ctx.decrypt_text(row["classification"]) or "General",
        quick_replies=quick_replies,
        actions=actions,
        recalled=bool(row["recalled"]),
        recall_status=row["recall_status"],
        is_read=bool(row["is_read"]),
        e2e_encrypted=bool(e2e_envelope),
        e2e_envelope=e2e_envelope,
    )


def _todo_row_to_item(ctx: AppContext, row) -> TodoItem:
    return TodoItem(
        id=row["id"],
        owner_email=row["owner_email"],
        message_id=row["message_id"],
        title=ctx.decrypt_text(row["title"]),
        created_at=row["created_at"],
    )


def _calendar_row_to_item(ctx: AppContext, row) -> CalendarEvent:
    return CalendarEvent(
        id=row["id"],
        owner_email=row["owner_email"],
        message_id=row["message_id"],
        title=ctx.decrypt_text(row["title"]),
        starts_at=row["starts_at"],
        duration_minutes=row["duration_minutes"],
        created_at=row["created_at"],
        source_action=row["source_action"],
    )


def _group_row_to_summary(ctx: AppContext, row) -> GroupSummary:
    return GroupSummary(
        name=row["name"],
        members=ctx.decrypt_json(row["members_json"]) or [],
        created_at=row["created_at"],
    )


def recipient_exists(ctx: AppContext, recipient_email: str) -> bool:
    email = normalize_email(recipient_email)
    email_hash = ctx.stable_hash(email)
    with ctx.connect() as conn:
        row = conn.execute("SELECT 1 FROM users WHERE email_hash = ?", (email_hash,)).fetchone()
    return row is not None


def store_mail_copy(
    ctx: AppContext,
    owner_email: str,
    folder: str,
    message_id: str,
    thread_id: str,
    from_email: str,
    to: list[str],
    cc: list[str],
    subject: str,
    body_text: str,
    attachments: list[AttachmentMeta | dict[str, Any]],
    created_at: str,
    delivery_state: str | None = None,
    is_read: bool = False,
    recalled: bool = False,
    recall_status: str | None = None,
    e2e_envelope: dict[str, Any] | None = None,
) -> MailSummary:
    normalized_attachments = [
        item if isinstance(item, dict) else item.model_dump()
        for item in attachments
    ]
    resolved_delivery_state = delivery_state or {"draft": "draft", "sent": "delivered"}.get(folder, "delivered")
    normalized_e2e_envelope = e2e_envelope or {}
    with ctx.connect() as conn:
        if normalized_e2e_envelope:
            stored_subject = E2E_SUBJECT_PLACEHOLDER
            stored_body_text = E2E_BODY_PLACEHOLDER
            keywords = []
            classification = "Encrypted"
            security_flags = {
                "e2e_encrypted": True,
                "server_content_visibility": "ciphertext_only",
            }
            quick_replies = []
            actions = []
        else:
            stored_subject = subject
            stored_body_text = body_text
            corpus_rows = conn.execute(
                "SELECT subject, body_text FROM mail_items WHERE owner_email = ? ORDER BY created_at DESC LIMIT 50",
                (owner_email,),
            ).fetchall()
            corpus = [f"{ctx.decrypt_text(row['subject'])} {ctx.decrypt_text(row['body_text'])}" for row in corpus_rows]
            smart = analyze_message_features(
                config=ctx.config,
                sender_email=from_email,
                subject=subject,
                body_text=body_text,
                corpus=corpus,
                openai_api_key=ctx.get_secret("openai_api_key") or ctx.config.openai_api_key,
            )
            keywords = smart["keywords"]
            classification = smart["classification"]
            security_flags = smart["security_flags"]
            if security_flags.get("suspicious"):
                classification = "Suspicious"
                if folder == "inbox":
                    log_event(
                        ctx,
                        "suspicious_mail_detected",
                        actor_email=from_email,
                        owner_email=owner_email,
                        message_id=message_id,
                        score=security_flags.get("phishing_score", 0),
                        reasons=security_flags.get("reasons", []),
                    )
            quick_replies = smart["quick_replies"] if folder == "inbox" else []
            actions = (
                _build_actions(
                    ctx,
                    message_id,
                    owner_email,
                    subject,
                    body_text,
                    suspicious=bool(security_flags.get("suspicious")),
                )
                if folder == "inbox" and not recalled
                else []
            )
        existing = conn.execute(
            "SELECT mailbox_item_id FROM mail_items WHERE owner_email = ? AND folder = ? AND message_id = ?",
            (owner_email, folder, message_id),
        ).fetchone()
        mailbox_item_id = existing["mailbox_item_id"] if existing else new_id()
        if existing is None:
            conn.execute(
                "INSERT INTO mail_items(mailbox_item_id, message_id, thread_id, owner_email, folder, delivery_state, from_email, to_json, cc_json, "
                "subject, body_text, attachments_json, created_at, security_flags_json, actions_json, quick_replies_json, "
                "keywords_json, classification, e2e_envelope_json, recalled, recall_status, is_read) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    mailbox_item_id,
                    message_id,
                    thread_id,
                    owner_email,
                    folder,
                    resolved_delivery_state,
                    ctx.encrypt_text(from_email),
                    ctx.encrypt_json(to),
                    ctx.encrypt_json(cc),
                    ctx.encrypt_text(stored_subject),
                    ctx.encrypt_text(stored_body_text),
                    ctx.encrypt_json(normalized_attachments),
                    created_at,
                    ctx.encrypt_json(security_flags),
                    ctx.encrypt_json(actions),
                    ctx.encrypt_json(quick_replies),
                    ctx.encrypt_json(keywords),
                    ctx.encrypt_text(classification),
                    ctx.encrypt_json(normalized_e2e_envelope),
                    int(recalled),
                    recall_status,
                    int(is_read),
                ),
            )
        else:
            conn.execute(
                "UPDATE mail_items SET thread_id = ?, delivery_state = ?, from_email = ?, to_json = ?, cc_json = ?, subject = ?, body_text = ?, "
                "attachments_json = ?, created_at = ?, security_flags_json = ?, actions_json = ?, quick_replies_json = ?, keywords_json = ?, "
                "classification = ?, e2e_envelope_json = ?, recalled = ?, recall_status = ?, is_read = ? WHERE mailbox_item_id = ?",
                (
                    thread_id,
                    resolved_delivery_state,
                    ctx.encrypt_text(from_email),
                    ctx.encrypt_json(to),
                    ctx.encrypt_json(cc),
                    ctx.encrypt_text(stored_subject),
                    ctx.encrypt_text(stored_body_text),
                    ctx.encrypt_json(normalized_attachments),
                    created_at,
                    ctx.encrypt_json(security_flags),
                    ctx.encrypt_json(actions),
                    ctx.encrypt_json(quick_replies),
                    ctx.encrypt_json(keywords),
                    ctx.encrypt_text(classification),
                    ctx.encrypt_json(normalized_e2e_envelope),
                    int(recalled),
                    recall_status,
                    int(is_read),
                    mailbox_item_id,
                ),
            )
            conn.execute("DELETE FROM mail_attachment_links WHERE mailbox_item_id = ?", (mailbox_item_id,))
        for attachment in normalized_attachments:
            conn.execute(
                "INSERT OR IGNORE INTO mail_attachment_links(mailbox_item_id, owner_email, attachment_id) VALUES (?, ?, ?)",
                (mailbox_item_id, owner_email, attachment["id"]),
            )
        _touch_contacts(conn, owner_email, [from_email, *to, *cc], source=f"mail:{folder}")
        row = conn.execute(
            "SELECT * FROM mail_items WHERE mailbox_item_id = ?",
            (mailbox_item_id,),
        ).fetchone()
    return _mail_row_to_summary(ctx, row)


def _list_folder(ctx: AppContext, owner_email: str, folder: str) -> list[MailSummary]:
    with ctx.connect() as conn:
        rows = conn.execute(
            "SELECT * FROM mail_items WHERE owner_email = ? AND folder = ? ORDER BY created_at DESC",
            (owner_email, folder),
        ).fetchall()
    return [_mail_row_to_summary(ctx, row) for row in rows]


def _get_message(ctx: AppContext, owner_email: str, message_id: str) -> MailSummary:
    with ctx.connect() as conn:
        row = conn.execute(
            "SELECT * FROM mail_items WHERE owner_email = ? AND message_id = ? ORDER BY created_at DESC LIMIT 1",
            (owner_email, message_id),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Message not found.")
    return _mail_row_to_summary(ctx, row)


def _list_todos(ctx: AppContext, owner_email: str) -> list[TodoItem]:
    with ctx.connect() as conn:
        rows = conn.execute(
            "SELECT id, owner_email, message_id, title, created_at FROM todos WHERE owner_email = ? ORDER BY created_at DESC",
            (owner_email,),
        ).fetchall()
    return [_todo_row_to_item(ctx, row) for row in rows]


def _list_calendar_events(ctx: AppContext, owner_email: str) -> list[CalendarEvent]:
    with ctx.connect() as conn:
        rows = conn.execute(
            "SELECT id, owner_email, message_id, title, starts_at, duration_minutes, created_at, source_action "
            "FROM calendar_events WHERE owner_email = ? ORDER BY starts_at DESC",
            (owner_email,),
        ).fetchall()
    return [_calendar_row_to_item(ctx, row) for row in rows]


def _list_groups(ctx: AppContext, owner_email: str) -> list[GroupSummary]:
    with ctx.connect() as conn:
        rows = conn.execute(
            "SELECT name, members_json, created_at FROM groups_store WHERE owner_email = ? ORDER BY created_at DESC, name ASC",
            (owner_email,),
        ).fetchall()
    return [_group_row_to_summary(ctx, row) for row in rows]


def refresh_sent_delivery_state(ctx: AppContext, owner_email: str, message_id: str) -> str:
    with ctx.connect() as conn:
        rows = conn.execute(
            "SELECT status FROM job_queue WHERE owner_email = ? AND message_id = ? AND job_type IN ('local_delivery', 'remote_delivery')",
            (owner_email, message_id),
        ).fetchall()
        statuses = [row["status"] for row in rows]
        if not statuses:
            delivery_state = "delivered"
        elif all(status == "cancelled" for status in statuses):
            delivery_state = "recalled"
        elif any(status in {"pending", "in_progress"} for status in statuses):
            delivery_state = "queued"
        elif all(status == "completed" for status in statuses):
            delivery_state = "delivered"
        elif any(status == "completed" for status in statuses):
            delivery_state = "partial"
        else:
            delivery_state = "failed"
        conn.execute(
            "UPDATE mail_items SET delivery_state = ? WHERE owner_email = ? AND folder = 'sent' AND message_id = ?",
            (delivery_state, owner_email, message_id),
        )
    return delivery_state


def cancel_pending_delivery_jobs(
    ctx: AppContext,
    message_id: str,
    recipients: list[str],
    job_types: tuple[str, ...],
) -> dict[str, str]:
    cancelled: dict[str, str] = {}
    if not recipients or not job_types:
        return cancelled
    recipient_set = set(recipients)
    placeholders = ",".join("?" for _ in job_types)
    with ctx.connect() as conn:
        rows = conn.execute(
            f"SELECT job_id, payload_json FROM job_queue WHERE message_id = ? AND status = 'pending' "
            f"AND job_type IN ({placeholders})",
            (message_id, *job_types),
        ).fetchall()
        for row in rows:
            payload = ctx.decrypt_json(row["payload_json"]) or {}
            job_recipients = [item for item in payload.get("recipients", []) if item in recipient_set]
            if not job_recipients:
                continue
            remaining = [item for item in payload.get("recipients", []) if item not in recipient_set]
            if remaining:
                payload["recipients"] = remaining
                conn.execute(
                    "UPDATE job_queue SET payload_json = ?, updated_at = ? WHERE job_id = ?",
                    (ctx.encrypt_json(payload), isoformat_utc(), row["job_id"]),
                )
            else:
                conn.execute(
                    "UPDATE job_queue SET status = 'cancelled', last_error = ?, updated_at = ? WHERE job_id = ?",
                    ("cancelled_by_recall", isoformat_utc(), row["job_id"]),
                )
            for recipient in job_recipients:
                cancelled[recipient] = "recalled"
    return cancelled


def apply_recall(ctx: AppContext, message_id: str, recipients: list[str]) -> dict[str, str]:
    statuses: dict[str, str] = {}
    if not recipients:
        return statuses
    with ctx.connect() as conn:
        placeholders = ",".join("?" for _ in recipients)
        rows = conn.execute(
            f"SELECT mailbox_item_id, owner_email, is_read, recalled, created_at FROM mail_items "
            f"WHERE message_id = ? AND folder = 'inbox' AND owner_email IN ({placeholders})",
            [message_id, *recipients],
        ).fetchall()
        for row in rows:
            if row["recalled"]:
                statuses[row["owner_email"]] = "already_recalled"
                continue
            if row["is_read"]:
                statuses[row["owner_email"]] = "already_read"
                continue
            if utcnow() > parse_timestamp(row["created_at"]) + timedelta(minutes=ctx.config.recall_window_minutes):
                statuses[row["owner_email"]] = "window_expired"
                continue
            conn.execute(
                "UPDATE mail_items SET recalled = 1, recall_status = ?, actions_json = ? WHERE mailbox_item_id = ?",
                ("recalled", ctx.encrypt_json([]), row["mailbox_item_id"]),
                )
            statuses[row["owner_email"]] = "recalled"
    for recipient in recipients:
        statuses.setdefault(recipient, "not_found")
    return statuses


async def dispatch_message(ctx: AppContext, sender_email: str, payload: SendMailRequest) -> dict[str, Any]:
    recipients = _validated_email_list(payload.to, "to")
    cc = _validated_email_list(payload.cc, "cc")
    delivery_recipients = _dedupe_emails([*recipients, *cc])
    if not delivery_recipients:
        raise HTTPException(status_code=400, detail="At least one recipient is required.")
    if payload.e2e_envelope and payload.attachment_ids:
        raise HTTPException(status_code=400, detail="E2E encryption currently supports text-only messages.")
    attachment_metas, relay_attachments = export_attachment_payloads(ctx, payload.attachment_ids, sender_email)
    created_at = isoformat_utc()
    message_id = new_id()
    thread_id = payload.thread_id or new_id()

    local_recipients = [item for item in delivery_recipients if email_domain(item) == ctx.config.domain]
    remote_recipients: dict[str, list[str]] = defaultdict(list)
    for recipient in delivery_recipients:
        if email_domain(recipient) != ctx.config.domain:
            remote_recipients[email_domain(recipient)].append(recipient)
    unknown_domains = [domain for domain in remote_recipients if domain not in ctx.config.peer_domains]
    if unknown_domains:
        raise HTTPException(status_code=404, detail=f"Unknown peer domain(s): {', '.join(sorted(unknown_domains))}")

    missing_local = [recipient for recipient in local_recipients if not recipient_exists(ctx, recipient)]
    if missing_local:
        raise HTTPException(status_code=404, detail=f"Unknown local recipient(s): {', '.join(missing_local)}")

    sent_copy = store_mail_copy(
        ctx,
        owner_email=sender_email,
        folder="sent",
        message_id=message_id,
        thread_id=thread_id,
        from_email=sender_email,
        to=recipients,
        cc=cc,
        subject=payload.subject,
        body_text=payload.body_text,
        attachments=attachment_metas,
        created_at=created_at,
        delivery_state="queued" if (local_recipients or remote_recipients) else "delivered",
        is_read=True,
        e2e_envelope=payload.e2e_envelope,
    )

    queued_jobs = 0
    if local_recipients:
        ctx.enqueue_job(
            "local_delivery",
            {
                "sender_email": sender_email,
                "recipients": local_recipients,
                "to": recipients,
                "cc": cc,
                "message_id": message_id,
                "thread_id": thread_id,
                "subject": payload.subject,
                "body_text": payload.body_text,
                "created_at": created_at,
                "attachments": [item.model_dump() for item in attachment_metas],
                "e2e_envelope": payload.e2e_envelope,
            },
            message_id=message_id,
            owner_email=sender_email,
        )
        queued_jobs += 1

    for domain, recipient_group in remote_recipients.items():
        ctx.enqueue_job(
            "remote_delivery",
            {
                "domain": domain,
                "source_domain": ctx.config.domain,
                "source_email": sender_email,
                "to": recipients,
                "recipients": recipient_group,
                "cc": cc,
                "message_id": message_id,
                "thread_id": thread_id,
                "subject": payload.subject,
                "body_text": payload.body_text,
                "created_at": created_at,
                "attachments": relay_attachments,
                "e2e_envelope": payload.e2e_envelope,
            },
            message_id=message_id,
            owner_email=sender_email,
        )
        queued_jobs += 1

    log_event(
        ctx,
        "mail_sent",
        actor_email=sender_email,
        message_id=message_id,
        recipients=delivery_recipients,
        attachment_count=len(attachment_metas),
        queued_jobs=queued_jobs,
    )
    return {
        "status": "queued",
        "message_id": message_id,
        "thread_id": thread_id,
        "queued_jobs": queued_jobs,
        "sent_copy": sent_copy.model_dump(),
    }


def register_routes(app: FastAPI, ctx: AppContext) -> None:
    @app.get("/v1/mail/dashboard", response_model=MailboxDashboardResponse)
    def dashboard(authorization: str | None = Header(default=None)) -> MailboxDashboardResponse:
        user = get_current_user(ctx, authorization)
        with ctx.connect() as conn:
            inbox_rows = conn.execute(
                "SELECT * FROM mail_items WHERE owner_email = ? AND folder = ? ORDER BY created_at DESC",
                (user["email"], "inbox"),
            ).fetchall()
            sent_rows = conn.execute(
                "SELECT * FROM mail_items WHERE owner_email = ? AND folder = ? ORDER BY created_at DESC",
                (user["email"], "sent"),
            ).fetchall()
            draft_rows = conn.execute(
                "SELECT * FROM mail_items WHERE owner_email = ? AND folder = ? ORDER BY created_at DESC",
                (user["email"], "draft"),
            ).fetchall()
            todo_rows = conn.execute(
                "SELECT id, owner_email, message_id, title, created_at FROM todos WHERE owner_email = ? ORDER BY created_at DESC",
                (user["email"],),
            ).fetchall()
            calendar_rows = conn.execute(
                "SELECT id, owner_email, message_id, title, starts_at, duration_minutes, created_at, source_action "
                "FROM calendar_events WHERE owner_email = ? ORDER BY starts_at DESC",
                (user["email"],),
            ).fetchall()
            group_rows = conn.execute(
                "SELECT name, members_json, created_at FROM groups_store WHERE owner_email = ? ORDER BY created_at DESC, name ASC",
                (user["email"],),
            ).fetchall()
        return MailboxDashboardResponse(
            inbox=[_mail_row_to_summary(ctx, row) for row in inbox_rows],
            sent=[_mail_row_to_summary(ctx, row) for row in sent_rows],
            drafts=[_mail_row_to_summary(ctx, row) for row in draft_rows],
            todos=[_todo_row_to_item(ctx, row) for row in todo_rows],
            calendar_events=[_calendar_row_to_item(ctx, row) for row in calendar_rows],
            groups=[_group_row_to_summary(ctx, row) for row in group_rows],
        )

    @app.get("/v1/mail/inbox", response_model=list[MailSummary])
    def inbox(authorization: str | None = Header(default=None)) -> list[MailSummary]:
        user = get_current_user(ctx, authorization)
        return _list_folder(ctx, user["email"], "inbox")

    @app.get("/v1/mail/sent", response_model=list[MailSummary])
    def sent(authorization: str | None = Header(default=None)) -> list[MailSummary]:
        user = get_current_user(ctx, authorization)
        return _list_folder(ctx, user["email"], "sent")

    @app.get("/v1/mail/drafts", response_model=list[MailSummary])
    def drafts(authorization: str | None = Header(default=None)) -> list[MailSummary]:
        user = get_current_user(ctx, authorization)
        return _list_folder(ctx, user["email"], "draft")

    @app.get("/v1/mail/message/{message_id}", response_model=MailSummary)
    def message(message_id: str, authorization: str | None = Header(default=None)) -> MailSummary:
        user = get_current_user(ctx, authorization)
        return _get_message(ctx, user["email"], message_id)

    @app.post("/v1/mail/mark_read/{message_id}")
    def mark_read(message_id: str, request: Request, authorization: str | None = Header(default=None)) -> dict[str, str]:
        user = verify_authenticated_request(ctx, request, authorization, {"message_id": message_id})
        with ctx.connect() as conn:
            updated = conn.execute(
                "UPDATE mail_items SET is_read = 1 WHERE owner_email = ? AND message_id = ?",
                (user["email"], message_id),
            )
        if updated.rowcount == 0:
            raise HTTPException(status_code=404, detail="Message not found.")
        return {"status": "marked_read", "message_id": message_id}

    @app.post("/v1/mail/send")
    async def send(payload: SendMailRequest, request: Request, authorization: str | None = Header(default=None)) -> dict[str, Any]:
        payload_data = await _signed_payload_from_request(request)
        user = verify_authenticated_request(ctx, request, authorization, payload_data)
        enforce_send_limits(ctx, user["email"], _client_ip(request))
        return await dispatch_message(ctx, user["email"], payload)

    @app.post("/v1/mail/draft")
    async def draft(payload: DraftRequest, request: Request, authorization: str | None = Header(default=None)) -> dict[str, Any]:
        user = verify_authenticated_request(ctx, request, authorization, await _signed_payload_from_request(request))
        if payload.send_now:
            enforce_send_limits(ctx, user["email"], _client_ip(request))
            if payload.message_id:
                with ctx.connect() as conn:
                    conn.execute(
                        "DELETE FROM mail_items WHERE owner_email = ? AND message_id = ? AND folder = 'draft'",
                        (user["email"], payload.message_id),
                    )
            result = await dispatch_message(
                ctx,
                user["email"],
                SendMailRequest(
                    to=payload.to,
                    cc=payload.cc,
                    subject=payload.subject,
                    body_text=payload.body_text,
                    attachment_ids=payload.attachment_ids,
                    thread_id=payload.thread_id,
                ),
            )
            return {"status": "sent_from_draft", **result}

        attachment_metas = load_attachment_metas(ctx, payload.attachment_ids, user["email"])
        message_id = payload.message_id or new_id()
        with ctx.connect() as conn:
            existing = conn.execute(
                "SELECT mailbox_item_id, thread_id FROM mail_items WHERE owner_email = ? AND message_id = ? AND folder = 'draft'",
                (user["email"], message_id),
            ).fetchone()
            draft_thread_id = payload.thread_id or (existing["thread_id"] if existing is not None else new_id())
            if existing is None:
                store_mail_copy(
                    ctx,
                    owner_email=user["email"],
                    folder="draft",
                    message_id=message_id,
                    thread_id=draft_thread_id,
                    from_email=user["email"],
                    to=payload.to,
                    cc=payload.cc,
                    subject=payload.subject,
                    body_text=payload.body_text,
                    attachments=attachment_metas,
                    created_at=isoformat_utc(),
                    is_read=True,
                )
            else:
                conn.execute(
                    "UPDATE mail_items SET thread_id = ?, to_json = ?, cc_json = ?, subject = ?, body_text = ?, attachments_json = ? "
                    "WHERE owner_email = ? AND message_id = ? AND folder = 'draft'",
                    (
                        draft_thread_id,
                        ctx.encrypt_json(payload.to),
                        ctx.encrypt_json(payload.cc),
                        ctx.encrypt_text(payload.subject),
                        ctx.encrypt_text(payload.body_text),
                        ctx.encrypt_json([item.model_dump() for item in attachment_metas]),
                        user["email"],
                        message_id,
                    ),
                )
        log_event(ctx, "draft_saved", actor_email=user["email"], message_id=message_id)
        return {"status": "draft_saved", "message_id": message_id}

    @app.post("/v1/mail/recall")
    async def recall(payload: RecallRequest, request: Request, authorization: str | None = Header(default=None)) -> dict[str, Any]:
        user = verify_authenticated_request(ctx, request, authorization, payload.model_dump())
        sent_message = _get_message(ctx, user["email"], payload.message_id)
        if sent_message.folder != "sent":
            raise HTTPException(status_code=400, detail="Only sent messages can be recalled.")
        age_seconds = (utcnow() - parse_timestamp(sent_message.created_at)).total_seconds()
        if age_seconds > ctx.config.recall_window_minutes * 60:
            raise HTTPException(status_code=400, detail="Recall window expired.")
        all_recipients = _dedupe_emails([*sent_message.to, *sent_message.cc])
        local = [recipient for recipient in all_recipients if email_domain(recipient) == ctx.config.domain]
        remote: dict[str, list[str]] = defaultdict(list)
        for recipient in all_recipients:
            if email_domain(recipient) != ctx.config.domain:
                remote[email_domain(recipient)].append(recipient)
        statuses = cancel_pending_delivery_jobs(ctx, payload.message_id, local, ("local_delivery",))
        remaining_local = [recipient for recipient in local if recipient not in statuses]
        statuses.update(apply_recall(ctx, payload.message_id, remaining_local))
        remote_cancelled = cancel_pending_delivery_jobs(
            ctx,
            payload.message_id,
            [recipient for recipients in remote.values() for recipient in recipients],
            ("remote_delivery",),
        )
        statuses.update(remote_cancelled)
        for domain, recipients in remote.items():
            remaining_remote = [recipient for recipient in recipients if recipient not in remote_cancelled]
            if not remaining_remote:
                continue
            response = await ctx.relay_post(
                domain,
                "/v1/relay/recall",
                {
                    "source_domain": ctx.config.domain,
                    "source_email": user["email"],
                    "message_id": payload.message_id,
                    "recipients": remaining_remote,
                    "requested_at": isoformat_utc(),
                },
            )
            statuses.update(response.get("statuses", {}))
        successful = {"recalled", "already_recalled"}
        recall_state = (
            "recalled"
            if statuses and all(status in successful for status in statuses.values())
            else "partial" if any(status in successful for status in statuses.values()) else "recall_failed"
        )
        with ctx.connect() as conn:
            conn.execute(
                "UPDATE mail_items SET recall_status = ? WHERE owner_email = ? AND folder = 'sent' AND message_id = ?",
                (recall_state, user["email"], payload.message_id),
            )
        refresh_sent_delivery_state(ctx, user["email"], payload.message_id)
        log_event(ctx, "recall_requested", actor_email=user["email"], message_id=payload.message_id, statuses=statuses)
        return {"status": "recall_processed", "statuses": statuses}

    @app.post("/v1/groups/create")
    def group_create(payload: GroupCreateRequest, request: Request, authorization: str | None = Header(default=None)) -> dict[str, Any]:
        user = verify_authenticated_request(ctx, request, authorization, payload.model_dump())
        group_name = _validated_group_name(payload.name)
        members = _validated_email_list(payload.members, "members")
        with ctx.connect() as conn:
            conn.execute(
                "INSERT INTO groups_store(name, owner_email, members_json, created_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(name, owner_email) DO UPDATE SET members_json = excluded.members_json, created_at = excluded.created_at",
                (group_name, user["email"], ctx.encrypt_json(sorted(set(members))), isoformat_utc()),
            )
        return {"status": "group_saved", "name": group_name, "members": sorted(set(members))}

    @app.post("/v1/groups/add_member")
    def group_add(payload: GroupMemberRequest, request: Request, authorization: str | None = Header(default=None)) -> dict[str, Any]:
        user = verify_authenticated_request(ctx, request, authorization, payload.model_dump())
        group_name = _validated_group_name(payload.name)
        with ctx.connect() as conn:
            row = conn.execute(
                "SELECT members_json FROM groups_store WHERE name = ? AND owner_email = ?",
                (group_name, user["email"]),
            ).fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="Group not found.")
            member_email = normalize_email(payload.member_email)
            if not is_valid_email(member_email):
                raise HTTPException(status_code=400, detail=f"Invalid email address in member_email: {member_email}")
            members = sorted(set((ctx.decrypt_json(row["members_json"]) or []) + [member_email]))
            conn.execute(
                "UPDATE groups_store SET members_json = ?, created_at = ? WHERE name = ? AND owner_email = ?",
                (ctx.encrypt_json(members), isoformat_utc(), group_name, user["email"]),
            )
        return {"status": "group_updated", "name": group_name, "members": members}

    @app.get("/v1/groups", response_model=list[GroupSummary])
    def groups(authorization: str | None = Header(default=None)) -> list[GroupSummary]:
        user = get_current_user(ctx, authorization)
        return _list_groups(ctx, user["email"])

    @app.post("/v1/mail/send_group")
    async def group_send(payload: GroupSendRequest, request: Request, authorization: str | None = Header(default=None)) -> dict[str, Any]:
        user = verify_authenticated_request(ctx, request, authorization, await _signed_payload_from_request(request))
        group_name = _validated_group_name(payload.group_name)
        with ctx.connect() as conn:
            row = conn.execute(
                "SELECT members_json FROM groups_store WHERE name = ? AND owner_email = ?",
                (group_name, user["email"]),
            ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Group not found.")
        members = ctx.decrypt_json(row["members_json"]) or []
        enforce_send_limits(ctx, user["email"], _client_ip(request))
        return await dispatch_message(
            ctx,
            user["email"],
            SendMailRequest(
                to=members,
                subject=payload.subject,
                body_text=payload.body_text,
                attachment_ids=payload.attachment_ids,
            ),
        )

    @app.post("/v1/actions/execute")
    def execute_action(payload: ActionExecutionRequest, request: Request, authorization: str | None = Header(default=None)) -> dict[str, str]:
        user = verify_authenticated_request(ctx, request, authorization, payload.model_dump())
        try:
            data = verify_signed_payload(ctx.config.action_secret, payload.token)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        required_fields = {"message_id", "recipient", "action", "issued_at", "expires_at", "nonce"}
        missing = [field for field in required_fields if not data.get(field)]
        if missing:
            raise HTTPException(status_code=400, detail=f"Action token missing fields: {', '.join(sorted(missing))}.")
        if data["recipient"] != user["email"]:
            raise HTTPException(status_code=403, detail="Action token does not belong to this user.")
        try:
            issued_at = parse_timestamp(data["issued_at"])
            expires_at = parse_timestamp(data["expires_at"])
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail="Action token time metadata is invalid.") from exc
        if expires_at <= issued_at:
            raise HTTPException(status_code=400, detail="Action token time window is invalid.")
        if expires_at - issued_at > timedelta(hours=ACTION_TOKEN_MAX_LIFETIME_HOURS):
            raise HTTPException(status_code=400, detail="Action token lifetime is too long.")
        now = utcnow()
        if issued_at - now > timedelta(minutes=5):
            raise HTTPException(status_code=400, detail="Action token issued time is invalid.")
        if now > expires_at:
            raise HTTPException(status_code=400, detail="Action token has expired.")
        action = str(data["action"])
        if action not in {"add_todo", "add_calendar_event", "acknowledge", "report_phishing"}:
            raise HTTPException(status_code=400, detail="Action not allowed.")
        token_hash = ctx.stable_hash(payload.token)
        with ctx.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            duplicate = conn.execute(
                "SELECT 1 FROM action_token_uses WHERE token_hash = ? LIMIT 1",
                (token_hash,),
            ).fetchone()
            if duplicate is not None:
                raise HTTPException(status_code=409, detail="Action token was already used.")
            message_row = conn.execute(
                "SELECT mailbox_item_id, subject, body_text, security_flags_json FROM mail_items "
                "WHERE owner_email = ? AND message_id = ? AND folder = 'inbox' ORDER BY created_at DESC LIMIT 1",
                (user["email"], data["message_id"]),
            ).fetchone()
            if message_row is None:
                raise HTTPException(status_code=404, detail="Message not found.")
            message_subject = ctx.decrypt_text(message_row["subject"])
            message_body = ctx.decrypt_text(message_row["body_text"])
            executed_status: dict[str, str]
            if action == "add_todo":
                todo = TodoItem(
                    id=new_id(),
                    owner_email=user["email"],
                    message_id=data["message_id"],
                    title=str(data.get("title") or f"Follow up: {(message_subject or 'Message')[:48]}"),
                    created_at=isoformat_utc(now),
                )
                conn.execute(
                    "INSERT INTO todos(id, owner_email, message_id, title, created_at) VALUES (?, ?, ?, ?, ?)",
                    (todo.id, todo.owner_email, todo.message_id, ctx.encrypt_text(todo.title), todo.created_at),
                )
                log_event(ctx, "action_add_todo", actor_email=user["email"], message_id=data["message_id"])
                executed_status = {"status": "todo_added", "todo_id": todo.id}
            elif action == "add_calendar_event":
                event = CalendarEvent(
                    id=new_id(),
                    owner_email=user["email"],
                    message_id=data["message_id"],
                    title=str(data.get("title") or _calendar_title_from_subject(message_subject)),
                    starts_at=_infer_calendar_start(message_subject, message_body),
                    duration_minutes=30,
                    created_at=isoformat_utc(now),
                    source_action="quick_action",
                )
                conn.execute(
                    "INSERT INTO calendar_events(id, owner_email, message_id, title, starts_at, duration_minutes, created_at, source_action) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        event.id,
                        event.owner_email,
                        event.message_id,
                        ctx.encrypt_text(event.title),
                        event.starts_at,
                        event.duration_minutes,
                        event.created_at,
                        event.source_action,
                    ),
                )
                log_event(ctx, "action_add_calendar_event", actor_email=user["email"], message_id=data["message_id"])
                executed_status = {"status": "calendar_event_added", "event_id": event.id}
            elif action == "report_phishing":
                current_flags = ctx.decrypt_json(message_row["security_flags_json"]) or {}
                existing_reasons = [
                    item
                    for item in current_flags.get("reasons", [])
                    if isinstance(item, str) and item.strip()
                ]
                reasons = list(dict.fromkeys([*existing_reasons, "user_reported_phishing"]))
                try:
                    current_score = int(current_flags.get("phishing_score", 0))
                except (TypeError, ValueError):
                    current_score = 0
                updated_flags = {
                    **current_flags,
                    "suspicious": True,
                    "phishing_score": max(current_score, 9),
                    "reasons": reasons,
                    "manual_review_requested": True,
                }
                conn.execute(
                    "UPDATE mail_items SET security_flags_json = ?, classification = ?, is_read = 1 WHERE mailbox_item_id = ?",
                    (
                        ctx.encrypt_json(updated_flags),
                        ctx.encrypt_text("Suspicious"),
                        message_row["mailbox_item_id"],
                    ),
                )
                log_event(
                    ctx,
                    "suspicious_mail_detected",
                    actor_email=user["email"],
                    owner_email=user["email"],
                    message_id=data["message_id"],
                    score=updated_flags["phishing_score"],
                    reasons=updated_flags["reasons"],
                    source="user_report",
                )
                executed_status = {"status": "phishing_reported", "message_id": data["message_id"]}
            else:
                conn.execute(
                    "UPDATE mail_items SET is_read = 1 WHERE mailbox_item_id = ?",
                    (message_row["mailbox_item_id"],),
                )
                log_event(ctx, "action_acknowledge", actor_email=user["email"], message_id=data["message_id"])
                executed_status = {"status": "acknowledged", "message_id": data["message_id"]}
            conn.execute(
                "INSERT INTO action_token_uses(token_hash, owner_email, message_id, action, used_at) VALUES (?, ?, ?, ?, ?)",
                (token_hash, user["email"], data["message_id"], action, isoformat_utc(now)),
            )
        return executed_status

    @app.get("/v1/todos", response_model=list[TodoItem])
    def todos(authorization: str | None = Header(default=None)) -> list[TodoItem]:
        user = get_current_user(ctx, authorization)
        return _list_todos(ctx, user["email"])

    @app.get("/v1/calendar/events", response_model=list[CalendarEvent])
    def calendar_events(authorization: str | None = Header(default=None)) -> list[CalendarEvent]:
        user = get_current_user(ctx, authorization)
        return _list_calendar_events(ctx, user["email"])

    @app.get("/v1/mail/search", response_model=SearchResponse)
    def search(q: str, authorization: str | None = Header(default=None)) -> SearchResponse:
        user = get_current_user(ctx, authorization)
        with ctx.connect() as conn:
            message_rows = conn.execute(
                "SELECT * FROM mail_items WHERE owner_email = ? ORDER BY created_at DESC LIMIT 200",
                (user["email"],),
            ).fetchall()
            contact_rows = conn.execute(
                "SELECT contact_email FROM contacts WHERE owner_email = ? ORDER BY last_seen_at DESC LIMIT 100",
                (user["email"],),
            ).fetchall()
        scored_messages: list[tuple[float, MailSummary]] = []
        for row in message_rows:
            summary = _mail_row_to_summary(ctx, row)
            candidate = " ".join(
                [
                    summary.subject,
                    summary.body_text,
                    summary.from_email,
                    " ".join(summary.to),
                    " ".join(summary.keywords),
                ]
            )
            score = fuzzy_score(q, candidate)
            if score >= 0.35:
                scored_messages.append((score, summary))
        scored_messages.sort(key=lambda item: item[0], reverse=True)
        contacts = [
            ContactSuggestion(email=row["contact_email"], score=fuzzy_score(q, row["contact_email"]))
            for row in contact_rows
            if fuzzy_score(q, row["contact_email"]) >= 0.35
        ]
        contacts.sort(key=lambda item: item.score, reverse=True)
        return SearchResponse(
            messages=[item for _, item in scored_messages[:20]],
            contacts=contacts[:10],
        )

    @app.get("/v1/contacts/autocomplete", response_model=list[ContactSuggestion])
    def autocomplete(q: str, authorization: str | None = Header(default=None)) -> list[ContactSuggestion]:
        user = get_current_user(ctx, authorization)
        with ctx.connect() as conn:
            rows = conn.execute(
                "SELECT contact_email FROM contacts WHERE owner_email = ? ORDER BY last_seen_at DESC LIMIT 100",
                (user["email"],),
            ).fetchall()
        scored = [
            ContactSuggestion(email=row["contact_email"], score=fuzzy_score(q, row["contact_email"]))
            for row in rows
        ]
        return sorted((item for item in scored if item.score >= 0.35), key=lambda item: item.score, reverse=True)[:10]
