from __future__ import annotations

from datetime import timedelta

from fastapi import FastAPI, Header, HTTPException, Request

from common.crypto import mac_hex
from common.schemas import KeyResolveRequest, KeyResolveResponse, PublishKeyRequest, PublishedKey
from common.utils import email_domain, isoformat_utc, json_dumps, normalize_email, utcnow
from server.auth import get_current_user, verify_authenticated_request
from server.logging import log_event
from server.storage import AppContext


def _published_key_from_row(row) -> PublishedKey:
    return PublishedKey(
        email=row["email"],
        algorithm=row["algorithm"],
        curve=row["curve"],
        public_key=row["public_key"],
        updated_at=row["updated_at"],
    )


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
        raise HTTPException(status_code=401, detail="Relay MAC validation failed.")
    with ctx.connect() as conn:
        cutoff = isoformat_utc(utcnow() - timedelta(hours=1))
        conn.execute("DELETE FROM relay_guards WHERE created_at < ?", (cutoff,))
        duplicate = conn.execute(
            "SELECT 1 FROM relay_guards WHERE source_domain = ? AND nonce = ?",
            (source_domain, nonce),
        ).fetchone()
        if duplicate is not None:
            raise HTTPException(status_code=409, detail="Duplicate relay request detected.")
        conn.execute(
            "INSERT INTO relay_guards(source_domain, nonce, created_at) VALUES (?, ?, ?)",
            (source_domain, nonce, isoformat_utc()),
        )


def _lookup_local_keys(ctx: AppContext, emails: list[str]) -> tuple[list[PublishedKey], list[str]]:
    normalized = [normalize_email(email) for email in emails if normalize_email(email)]
    if not normalized:
        return [], []
    placeholders = ",".join("?" for _ in normalized)
    with ctx.connect() as conn:
        rows = conn.execute(
            f"SELECT email, algorithm, curve, public_key, updated_at FROM user_public_keys WHERE email IN ({placeholders})",
            normalized,
        ).fetchall()
    found = {_published_key_from_row(row).email: _published_key_from_row(row) for row in rows}
    keys = [found[email] for email in normalized if email in found]
    missing = [email for email in normalized if email not in found]
    return keys, missing


def resolve_keys(ctx: AppContext, emails: list[str]) -> KeyResolveResponse:
    normalized = [normalize_email(email) for email in emails if normalize_email(email)]
    grouped: dict[str, list[str]] = {}
    for email in normalized:
        grouped.setdefault(email_domain(email), []).append(email)
    keys: list[PublishedKey] = []
    missing: list[str] = []
    for domain, domain_emails in grouped.items():
        if domain == ctx.config.domain:
            local_keys, local_missing = _lookup_local_keys(ctx, domain_emails)
            keys.extend(local_keys)
            missing.extend(local_missing)
            continue
        if domain not in ctx.config.peer_domains:
            missing.extend(domain_emails)
            continue
        response = ctx.relay_post_sync(
            domain,
            "/v1/relay/public_keys",
            {"emails": domain_emails},
        )
        keys.extend(PublishedKey(**item) for item in response.get("keys", []))
        missing.extend(response.get("missing", []))
    return KeyResolveResponse(keys=keys, missing=missing)


def register_routes(app: FastAPI, ctx: AppContext) -> None:
    @app.post("/v1/keys/publish", response_model=PublishedKey)
    def publish_key(
        payload: PublishKeyRequest,
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> PublishedKey:
        user = verify_authenticated_request(ctx, request, authorization, payload.model_dump())
        published = PublishedKey(
            email=user["email"],
            algorithm=payload.algorithm,
            curve=payload.curve,
            public_key=payload.public_key,
            updated_at=isoformat_utc(),
        )
        with ctx.connect() as conn:
            conn.execute(
                "INSERT INTO user_public_keys(email, algorithm, curve, public_key, updated_at) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(email) DO UPDATE SET algorithm = excluded.algorithm, curve = excluded.curve, "
                "public_key = excluded.public_key, updated_at = excluded.updated_at",
                (
                    published.email,
                    published.algorithm,
                    published.curve,
                    published.public_key,
                    published.updated_at,
                ),
            )
        log_event(ctx, "e2e_public_key_published", actor_email=user["email"], curve=payload.curve)
        return published

    @app.get("/v1/keys/me", response_model=PublishedKey | None)
    def my_key(authorization: str | None = Header(default=None)) -> PublishedKey | None:
        user = get_current_user(ctx, authorization)
        keys, _ = _lookup_local_keys(ctx, [user["email"]])
        return keys[0] if keys else None

    @app.post("/v1/keys/resolve", response_model=KeyResolveResponse)
    def resolve(
        payload: KeyResolveRequest,
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> KeyResolveResponse:
        user = verify_authenticated_request(ctx, request, authorization, payload.model_dump())
        response = resolve_keys(ctx, payload.emails)
        log_event(
            ctx,
            "e2e_keys_resolved",
            actor_email=user["email"],
            resolved=[item.email for item in response.keys],
            missing=response.missing,
        )
        return response

    @app.post("/v1/relay/public_keys", response_model=KeyResolveResponse)
    def relay_public_keys(
        payload: KeyResolveRequest,
        x_relay_domain: str | None = Header(default=None),
        x_relay_timestamp: str | None = Header(default=None),
        x_relay_nonce: str | None = Header(default=None),
        x_relay_mac: str | None = Header(default=None),
    ) -> KeyResolveResponse:
        if not x_relay_domain:
            raise HTTPException(status_code=400, detail="Missing relay domain header.")
        _verify_relay_request(
            ctx,
            "/v1/relay/public_keys",
            x_relay_domain,
            x_relay_timestamp,
            x_relay_nonce,
            x_relay_mac,
            payload.model_dump(),
        )
        local_only = [email for email in payload.emails if email_domain(email) == ctx.config.domain]
        keys, missing = _lookup_local_keys(ctx, local_only)
        return KeyResolveResponse(keys=keys, missing=missing)
