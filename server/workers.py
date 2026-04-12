from __future__ import annotations
import threading
import time
from typing import Any

from server.attachments import store_relay_attachments
from server.logging import log_event
from server.mailbox import refresh_sent_delivery_state, store_mail_copy
from server.storage import AppContext


POLL_INTERVAL_SECONDS = 0.10


def start_workers(ctx: AppContext) -> None:
    if ctx.workers_started:
        return
    ctx.stop_event.clear()
    ctx.worker_threads = []
    specs = [
        ("delivery-worker-1", ("local_delivery", "remote_delivery")),
        ("delivery-worker-2", ("local_delivery", "remote_delivery")),
        ("inbound-worker-1", ("inbound_delivery",)),
    ]
    for label, job_types in specs:
        thread = threading.Thread(
            target=_worker_loop,
            args=(ctx, label, job_types),
            daemon=True,
            name=f"{ctx.config.domain}-{label}",
        )
        thread.start()
        ctx.worker_threads.append(thread)
    ctx.workers_started = True


def stop_workers(ctx: AppContext) -> None:
    if not ctx.workers_started:
        return
    ctx.stop_event.set()
    for thread in ctx.worker_threads:
        thread.join(timeout=2.0)
    ctx.worker_threads = []
    ctx.workers_started = False


def _worker_loop(ctx: AppContext, label: str, job_types: tuple[str, ...]) -> None:
    while not ctx.stop_event.is_set():
        try:
            job = ctx.claim_job(job_types)
        except Exception as exc:
            log_event(
                ctx,
                "job_claim_retry",
                actor_email=None,
                job_type=",".join(job_types),
                worker=label,
                error=str(exc)[:300],
            )
            time.sleep(POLL_INTERVAL_SECONDS)
            continue
        if job is None:
            time.sleep(POLL_INTERVAL_SECONDS)
            continue
        try:
            _process_job(ctx, job)
        except Exception as exc:
            updated = ctx.fail_job(job, str(exc))
            if job.get("owner_email") and job.get("message_id"):
                refresh_sent_delivery_state(ctx, job["owner_email"], job["message_id"])
            log_event(
                ctx,
                "job_retry_scheduled" if updated["status"] == "pending" else "job_failed",
                actor_email=job.get("owner_email"),
                message_id=job.get("message_id"),
                job_id=job["job_id"],
                job_type=job["job_type"],
                attempts=updated["attempts"],
                error=updated["last_error"],
                worker=label,
            )
            continue
        ctx.complete_job(job["job_id"])
        if job.get("owner_email") and job.get("message_id"):
            refresh_sent_delivery_state(ctx, job["owner_email"], job["message_id"])
        log_event(
            ctx,
            "job_completed",
            actor_email=job.get("owner_email"),
            message_id=job.get("message_id"),
            job_id=job["job_id"],
            job_type=job["job_type"],
            worker=label,
        )


def _process_job(ctx: AppContext, job: dict[str, Any]) -> None:
    payload = ctx.decrypt_json(job["payload_json"]) or {}
    job_type = job["job_type"]
    if job_type == "local_delivery":
        _process_local_delivery(ctx, payload)
        return
    if job_type == "remote_delivery":
        _process_remote_delivery(ctx, payload)
        return
    if job_type == "inbound_delivery":
        _process_inbound_delivery(ctx, payload)
        return
    raise ValueError(f"Unsupported job type: {job_type}")


def _process_local_delivery(ctx: AppContext, payload: dict[str, Any]) -> None:
    for recipient in payload["recipients"]:
        store_mail_copy(
            ctx,
            owner_email=recipient,
            folder="inbox",
            message_id=payload["message_id"],
            thread_id=payload["thread_id"],
            from_email=payload["sender_email"],
            to=payload["to"],
            cc=payload["cc"],
            subject=payload["subject"],
            body_text=payload["body_text"],
            attachments=payload["attachments"],
            created_at=payload["created_at"],
            e2e_envelope=payload.get("e2e_envelope"),
        )
    log_event(
        ctx,
        "local_delivery_completed",
        actor_email=payload["sender_email"],
        message_id=payload["message_id"],
        recipients=payload["recipients"],
    )


def _process_remote_delivery(ctx: AppContext, payload: dict[str, Any]) -> None:
    response = ctx.relay_post_sync(
        payload["domain"],
        "/v1/relay/incoming",
        {
            "source_domain": payload["source_domain"],
            "source_email": payload["source_email"],
            "to": payload["to"],
            "recipients": payload["recipients"],
            "cc": payload["cc"],
            "message_id": payload["message_id"],
            "thread_id": payload["thread_id"],
            "subject": payload["subject"],
            "body_text": payload["body_text"],
            "created_at": payload["created_at"],
            "attachments": payload["attachments"],
            "e2e_envelope": payload.get("e2e_envelope"),
        },
    )
    log_event(
        ctx,
        "remote_delivery_relayed",
        actor_email=payload["source_email"],
        message_id=payload["message_id"],
        recipients=payload["recipients"],
        relay_domain=payload["domain"],
        relay_status=response.get("status", "ok"),
    )


def _process_inbound_delivery(ctx: AppContext, payload: dict[str, Any]) -> None:
    attachments = store_relay_attachments(ctx, payload["source_email"], payload["attachments"])
    visible_to = payload.get("to") or payload["recipients"]
    for recipient in payload["recipients"]:
        store_mail_copy(
            ctx,
            owner_email=recipient,
            folder="inbox",
            message_id=payload["message_id"],
            thread_id=payload["thread_id"],
            from_email=payload["source_email"],
            to=visible_to,
            cc=payload["cc"],
            subject=payload["subject"],
            body_text=payload["body_text"],
            attachments=attachments,
            created_at=payload["created_at"],
            e2e_envelope=payload.get("e2e_envelope"),
        )
    log_event(
        ctx,
        "relay_inbox_inserted",
        actor_email=payload["source_email"],
        message_id=payload["message_id"],
        recipients=payload["recipients"],
    )
