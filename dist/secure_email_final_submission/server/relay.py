from __future__ import annotations

from fastapi import FastAPI, Header, HTTPException
from datetime import timedelta

from common.crypto import mac_hex
from common.schemas import RelayIncomingRequest, RelayRecallRequest
from common.utils import email_domain, is_valid_email, isoformat_utc, json_dumps, parse_timestamp, utcnow
from server.logging import log_event
from server.mailbox import apply_recall, cancel_pending_delivery_jobs, recipient_exists
from server.storage import AppContext


def _verify_relay_request(
    ctx: AppContext,
    path: str,
    source_domain: str,
    timestamp: str | None,
    nonce: str | None,
    relay_mac: str | None,
    payload: dict,
) -> None:
    if source_domain not in ctx.config.peer_domains:
        raise HTTPException(status_code=403, detail="Relay source domain not trusted.")
    if not timestamp or not nonce or not relay_mac:
        raise HTTPException(status_code=400, detail="Missing relay security headers.")
    try:
        relay_dt = utcnow().fromtimestamp(int(timestamp), tz=utcnow().tzinfo)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid relay timestamp.") from exc
    if abs((utcnow() - relay_dt).total_seconds()) > 300:
        raise HTTPException(status_code=401, detail="Relay timestamp is outside the replay window.")
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
    if mac_hex(ctx.config.relay_secret, canonical) != relay_mac:
        log_event(ctx, "relay_mac_failed", actor_email=source_domain, path=path)
        raise HTTPException(status_code=401, detail="Relay MAC validation failed.")
    with ctx.connect() as conn:
        cutoff = isoformat_utc(utcnow() - timedelta(hours=1))
        conn.execute("DELETE FROM relay_guards WHERE created_at < ?", (cutoff,))
        duplicate = conn.execute(
            "SELECT 1 FROM relay_guards WHERE source_domain = ? AND nonce = ?",
            (source_domain, nonce),
        ).fetchone()
        if duplicate is not None:
            log_event(ctx, "relay_replay_rejected", actor_email=source_domain, path=path, reason="duplicate_nonce")
            raise HTTPException(status_code=409, detail="Duplicate relay request detected.")
        conn.execute(
            "INSERT INTO relay_guards(source_domain, nonce, created_at) VALUES (?, ?, ?)",
            (source_domain, nonce, isoformat_utc()),
        )


def register_routes(app: FastAPI, ctx: AppContext) -> None:
    @app.post("/v1/relay/incoming")
    def relay_incoming(
        payload: RelayIncomingRequest,
        x_relay_domain: str | None = Header(default=None),
        x_relay_timestamp: str | None = Header(default=None),
        x_relay_nonce: str | None = Header(default=None),
        x_relay_mac: str | None = Header(default=None),
    ) -> dict[str, object]:
        claimed_domain = x_relay_domain or payload.source_domain
        if claimed_domain != payload.source_domain:
            raise HTTPException(status_code=400, detail="Relay domain header mismatch.")
        _verify_relay_request(
            ctx,
            "/v1/relay/incoming",
            payload.source_domain,
            x_relay_timestamp,
            x_relay_nonce,
            x_relay_mac,
            payload.model_dump(),
        )
        invalid_format = [recipient for recipient in payload.recipients if not is_valid_email(recipient)]
        if invalid_format:
            raise HTTPException(status_code=400, detail=f"Invalid recipient address: {', '.join(invalid_format)}")
        invalid = [recipient for recipient in payload.recipients if email_domain(recipient) != ctx.config.domain]
        if invalid:
            raise HTTPException(status_code=400, detail=f"Recipient(s) not local to {ctx.config.domain}: {', '.join(invalid)}")
        missing = [recipient for recipient in payload.recipients if not recipient_exists(ctx, recipient)]
        if missing:
            raise HTTPException(status_code=404, detail=f"Unknown recipient(s): {', '.join(missing)}")
        ctx.enqueue_job(
            "inbound_delivery",
            payload.model_dump(),
            message_id=payload.message_id,
        )
        log_event(ctx, "relay_incoming", actor_email=payload.source_email, message_id=payload.message_id, recipients=payload.recipients)
        return {"status": "queued", "recipients": payload.recipients}

    @app.post("/v1/relay/recall")
    def relay_recall(
        payload: RelayRecallRequest,
        x_relay_domain: str | None = Header(default=None),
        x_relay_timestamp: str | None = Header(default=None),
        x_relay_nonce: str | None = Header(default=None),
        x_relay_mac: str | None = Header(default=None),
    ) -> dict[str, object]:
        claimed_domain = x_relay_domain or payload.source_domain
        if claimed_domain != payload.source_domain:
            raise HTTPException(status_code=400, detail="Relay domain header mismatch.")
        _verify_relay_request(
            ctx,
            "/v1/relay/recall",
            payload.source_domain,
            x_relay_timestamp,
            x_relay_nonce,
            x_relay_mac,
            payload.model_dump(),
        )
        invalid_format = [recipient for recipient in payload.recipients if not is_valid_email(recipient)]
        if invalid_format:
            raise HTTPException(status_code=400, detail=f"Invalid recipient address: {', '.join(invalid_format)}")
        statuses = cancel_pending_delivery_jobs(ctx, payload.message_id, payload.recipients, ("inbound_delivery",))
        remaining = [recipient for recipient in payload.recipients if recipient not in statuses]
        statuses.update(apply_recall(ctx, payload.message_id, remaining))
        log_event(ctx, "relay_recall", actor_email=payload.source_email, message_id=payload.message_id, statuses=statuses)
        return {"status": "processed", "statuses": statuses}
