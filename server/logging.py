from __future__ import annotations

from typing import Any

from server.storage import AppContext


ALERT_SEVERITY = {
    "job_failed": "high",
    "login_lockout": "high",
    "send_rate_limited": "warning",
    "upload_rate_limited": "warning",
    "login_rate_limited": "warning",
    "relay_replay_rejected": "high",
    "request_replay_rejected": "high",
    "request_mac_failed": "high",
    "relay_mac_failed": "high",
    "suspicious_mail_detected": "warning",
}


def log_event(ctx: AppContext, event_type: str, actor_email: str | None = None, **details: Any) -> None:
    ctx.audit(event_type, actor_email=actor_email, details=details)
    severity = ALERT_SEVERITY.get(event_type)
    if severity is not None:
        ctx.alert(event_type, actor_email=actor_email, severity=severity, details=details)
