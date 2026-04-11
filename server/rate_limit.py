from __future__ import annotations

from datetime import timedelta

from fastapi import HTTPException

from common.utils import isoformat_utc, parse_timestamp, utcnow
from server.storage import AppContext


def _delete_old_events(ctx: AppContext, bucket: str, window_seconds: int) -> None:
    cutoff = isoformat_utc(utcnow() - timedelta(seconds=window_seconds * 2))
    with ctx.connect() as conn:
        conn.execute("DELETE FROM rate_events WHERE bucket = ? AND created_at < ?", (bucket, cutoff))


def _window_stats(ctx: AppContext, bucket: str, window_seconds: int) -> tuple[int, str | None]:
    cutoff = isoformat_utc(utcnow() - timedelta(seconds=window_seconds))
    with ctx.connect() as conn:
        row = conn.execute(
            "SELECT COALESCE(SUM(amount), 0) AS total, MIN(created_at) AS oldest "
            "FROM rate_events WHERE bucket = ? AND created_at >= ?",
            (bucket, cutoff),
        ).fetchone()
    total = int(row["total"]) if row and row["total"] is not None else 0
    oldest = row["oldest"] if row else None
    return total, oldest


def _record_event(ctx: AppContext, bucket: str, amount: int) -> None:
    _delete_old_events(ctx, bucket, 3600)
    with ctx.connect() as conn:
        conn.execute(
            "INSERT INTO rate_events(bucket, amount, created_at) VALUES (?, ?, ?)",
            (bucket, amount, isoformat_utc()),
        )


def _retry_after(oldest: str | None, window_seconds: int) -> int:
    if not oldest:
        return window_seconds
    age = (utcnow() - parse_timestamp(oldest)).total_seconds()
    return max(1, int(window_seconds - age))


def _raise_limited(message: str, retry_after_seconds: int) -> None:
    raise HTTPException(
        status_code=429,
        detail=message,
        headers={"Retry-After": str(retry_after_seconds)},
    )


def enforce_budget(ctx: AppContext, bucket: str, limit: int, window_seconds: int, amount: int = 1) -> None:
    current, oldest = _window_stats(ctx, bucket, window_seconds)
    if current + amount > limit:
        event_type = "upload_rate_limited" if bucket.startswith("upload-bytes:") else "send_rate_limited"
        ctx.audit(event_type, details={"bucket": bucket, "limit": limit, "window_seconds": window_seconds, "amount": amount})
        ctx.alert(
            event_type,
            severity="warning",
            details={"bucket": bucket, "limit": limit, "window_seconds": window_seconds, "amount": amount},
        )
        _raise_limited("Rate limit exceeded.", _retry_after(oldest, window_seconds))
    _record_event(ctx, bucket, amount)


def check_login_lockout(ctx: AppContext, email: str, ip_address: str) -> None:
    buckets = [f"login:user:{email}", f"login:user-ip:{email}:{ip_address}"]
    with ctx.connect() as conn:
        row = conn.execute(
            f"SELECT MAX(until_at) AS until_at FROM lockouts WHERE bucket IN ({','.join('?' for _ in buckets)})",
            buckets,
        ).fetchone()
    locked_until = row["until_at"] if row else None
    if locked_until and parse_timestamp(locked_until) > utcnow():
        retry_after_seconds = int((parse_timestamp(locked_until) - utcnow()).total_seconds())
        ctx.audit("login_rate_limited", details={"email": email, "ip_address": ip_address, "retry_after": retry_after_seconds})
        ctx.alert(
            "login_rate_limited",
            actor_email=email,
            severity="warning",
            details={"ip_address": ip_address, "retry_after": retry_after_seconds},
        )
        _raise_limited("Account temporarily locked.", max(1, retry_after_seconds))


def record_login_failure(ctx: AppContext, email: str, ip_address: str) -> int | None:
    buckets = [f"login:user:{email}", f"login:user-ip:{email}:{ip_address}"]
    now = utcnow()
    lockout_until = isoformat_utc(now + timedelta(seconds=ctx.config.lockout_seconds))
    for bucket in buckets:
        _record_event(ctx, bucket, 1)
        total, _ = _window_stats(ctx, bucket, ctx.config.login_window_seconds)
        if total >= ctx.config.login_max_attempts:
            with ctx.connect() as conn:
                conn.execute(
                    "INSERT INTO lockouts(bucket, until_at) VALUES (?, ?) "
                    "ON CONFLICT(bucket) DO UPDATE SET until_at = excluded.until_at",
                    (bucket, lockout_until),
                )
            return ctx.config.lockout_seconds
    return None


def clear_login_failures(ctx: AppContext, email: str, ip_address: str) -> None:
    buckets = [f"login:user:{email}", f"login:user-ip:{email}:{ip_address}"]
    with ctx.connect() as conn:
        conn.execute(
            f"DELETE FROM rate_events WHERE bucket IN ({','.join('?' for _ in buckets)})",
            buckets,
        )
        conn.execute(
            f"DELETE FROM lockouts WHERE bucket IN ({','.join('?' for _ in buckets)})",
            buckets,
        )


def enforce_send_limits(ctx: AppContext, email: str, ip_address: str) -> None:
    enforce_budget(ctx, f"send:user:{email}", ctx.config.send_rate_limit_per_minute, 60)
    enforce_budget(ctx, f"send:user-ip:{email}:{ip_address}", ctx.config.send_rate_limit_per_minute, 60)


def enforce_upload_limits(ctx: AppContext, email: str, size_bytes: int) -> None:
    enforce_budget(
        ctx,
        f"upload-bytes:user:{email}",
        ctx.config.upload_rate_limit_bytes_per_minute,
        60,
        amount=size_bytes,
    )
