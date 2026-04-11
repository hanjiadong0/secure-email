from __future__ import annotations

from datetime import timedelta

from fastapi import FastAPI, Header, HTTPException, Request

from common.crypto import hash_password, mac_hex, new_session_token, verify_password
from common.schemas import AuthResponse, LoginRequest, RegisterRequest
from common.utils import email_domain, isoformat_utc, json_dumps, normalize_email, parse_timestamp, utcnow
from server.logging import log_event
from server.rate_limit import check_login_lockout, clear_login_failures, record_login_failure
from server.storage import AppContext


def _client_ip(request: Request) -> str:
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def _parse_token(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token.")
    return authorization.split(" ", 1)[1].strip()


def _load_user_row(ctx: AppContext, email: str):
    with ctx.connect() as conn:
        return conn.execute("SELECT id, email, password_hash FROM users WHERE email = ?", (email,)).fetchone()


def get_current_user(ctx: AppContext, authorization: str | None) -> dict[str, str]:
    token = _parse_token(authorization)
    with ctx.connect() as conn:
        row = conn.execute(
            "SELECT users.id AS user_id, users.email AS email, sessions.expires_at AS expires_at, "
            "sessions.session_key AS session_key, sessions.last_seq_no AS last_seq_no "
            "FROM sessions JOIN users ON users.id = sessions.user_id WHERE sessions.token = ?",
            (token,),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=401, detail="Invalid session token.")
        if parse_timestamp(row["expires_at"]) <= utcnow():
            raise HTTPException(status_code=401, detail="Session expired.")
        rolling = isoformat_utc(utcnow() + timedelta(minutes=ctx.config.session_ttl_minutes))
        conn.execute(
            "UPDATE sessions SET last_seen = ?, expires_at = ? WHERE token = ?",
            (isoformat_utc(), rolling, token),
        )
    return {
        "user_id": str(row["user_id"]),
        "email": row["email"],
        "token": token,
        "session_id": token,
        "session_key": ctx.decrypt_text(row["session_key"]),
        "last_seq_no": str(row["last_seq_no"]),
    }


def verify_authenticated_request(
    ctx: AppContext,
    request: Request,
    authorization: str | None,
    payload: dict | None,
) -> dict[str, str]:
    user = get_current_user(ctx, authorization)
    request_id = request.headers.get("X-Request-Id")
    session_id = request.headers.get("X-Session-Id")
    seq_no_raw = request.headers.get("X-Seq-No")
    timestamp_raw = request.headers.get("X-Timestamp")
    nonce = request.headers.get("X-Nonce")
    body_mac = request.headers.get("X-Body-Mac")
    if not all([request_id, session_id, seq_no_raw, timestamp_raw, nonce, body_mac]):
        raise HTTPException(status_code=400, detail="Missing authenticated request headers.")
    if session_id != user["session_id"]:
        raise HTTPException(status_code=401, detail="Session header mismatch.")
    try:
        seq_no = int(seq_no_raw)
        timestamp = int(timestamp_raw)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid sequence or timestamp header.") from exc
    if seq_no <= 0:
        raise HTTPException(status_code=400, detail="Sequence number must be positive.")
    now_ts = int(utcnow().timestamp())
    if abs(now_ts - timestamp) > 300:
        raise HTTPException(status_code=401, detail="Request timestamp is outside the replay window.")
    canonical = json_dumps(
        {
            "method": request.method.upper(),
            "path": request.url.path,
            "request_id": request_id,
            "session_id": session_id,
            "seq_no": seq_no,
            "timestamp": timestamp,
            "nonce": nonce,
            "body": payload or {},
        }
    )
    expected = mac_hex(user["session_key"], canonical)
    if expected != body_mac:
        log_event(ctx, "request_mac_failed", actor_email=user["email"], path=request.url.path)
        raise HTTPException(status_code=401, detail="Request MAC validation failed.")
    with ctx.connect() as conn:
        row = conn.execute(
            "SELECT last_seq_no FROM sessions WHERE token = ?",
            (user["token"],),
        ).fetchone()
        current_seq = int(row["last_seq_no"]) if row else 0
        if seq_no <= current_seq:
            log_event(ctx, "request_replay_rejected", actor_email=user["email"], path=request.url.path, reason="sequence")
            raise HTTPException(status_code=409, detail="Sequence replay detected.")
        duplicate = conn.execute(
            "SELECT 1 FROM request_guards WHERE session_token = ? AND (request_id = ? OR nonce = ?) LIMIT 1",
            (user["token"], request_id, nonce),
        ).fetchone()
        if duplicate is not None:
            log_event(ctx, "request_replay_rejected", actor_email=user["email"], path=request.url.path, reason="duplicate_request")
            raise HTTPException(status_code=409, detail="Duplicate or replayed request detected.")
        cutoff = isoformat_utc(utcnow() - timedelta(hours=1))
        conn.execute("DELETE FROM request_guards WHERE created_at < ?", (cutoff,))
        conn.execute(
            "INSERT INTO request_guards(session_token, request_id, nonce, seq_no, created_at) VALUES (?, ?, ?, ?, ?)",
            (user["token"], request_id, nonce, seq_no, isoformat_utc()),
        )
        conn.execute(
            "UPDATE sessions SET last_seq_no = ? WHERE token = ?",
            (seq_no, user["token"]),
        )
    return user


def register_routes(app: FastAPI, ctx: AppContext) -> None:
    @app.post("/v1/auth/register", status_code=201)
    def register(payload: RegisterRequest, request: Request) -> dict[str, str]:
        email = normalize_email(payload.email)
        if "@" not in email or email_domain(email) != ctx.config.domain:
            raise HTTPException(status_code=400, detail=f"Email must belong to {ctx.config.domain}.")
        if payload.confirm_password is not None and payload.password != payload.confirm_password:
            raise HTTPException(status_code=400, detail="Password confirmation does not match.")
        with ctx.connect() as conn:
            existing = conn.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone()
            if existing:
                raise HTTPException(status_code=409, detail="User already exists.")
            conn.execute(
                "INSERT INTO users(email, password_hash, created_at) VALUES (?, ?, ?)",
                (email, hash_password(payload.password), isoformat_utc()),
            )
        log_event(ctx, "register", actor_email=email, ip=_client_ip(request))
        return {"status": "registered", "email": email}

    @app.post("/v1/auth/login", response_model=AuthResponse)
    def login(payload: LoginRequest, request: Request) -> AuthResponse:
        email = normalize_email(payload.email)
        ip_address = _client_ip(request)
        check_login_lockout(ctx, email, ip_address)
        user = _load_user_row(ctx, email)
        if user is None or not verify_password(user["password_hash"], payload.password):
            retry_after = record_login_failure(ctx, email, ip_address)
            log_event(ctx, "login_failed", actor_email=email, ip=ip_address)
            if retry_after is not None:
                log_event(ctx, "login_lockout", actor_email=email, ip=ip_address, retry_after=retry_after)
                raise HTTPException(
                    status_code=429,
                    detail="Account temporarily locked.",
                    headers={"Retry-After": str(retry_after)},
                )
            raise HTTPException(status_code=401, detail="Invalid credentials.")
        clear_login_failures(ctx, email, ip_address)
        token = new_session_token()
        session_key = new_session_token()
        expires_at = isoformat_utc(utcnow() + timedelta(minutes=ctx.config.session_ttl_minutes))
        with ctx.connect() as conn:
            conn.execute(
                "INSERT INTO sessions(token, user_id, session_key, expires_at, created_at, last_seen, last_seq_no) "
                "VALUES (?, ?, ?, ?, ?, ?, 0)",
                (token, user["id"], ctx.encrypt_text(session_key), expires_at, isoformat_utc(), isoformat_utc()),
            )
        log_event(ctx, "login_success", actor_email=email, ip=ip_address)
        return AuthResponse(
            email=email,
            session_id=token,
            session_token=token,
            session_key=session_key,
            expires_at=expires_at,
        )

    @app.get("/v1/auth/me")
    def me(authorization: str | None = Header(default=None)) -> dict[str, str]:
        return get_current_user(ctx, authorization)
