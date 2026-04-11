from __future__ import annotations

from typing import Any

from server.storage import AppContext


def log_event(ctx: AppContext, event_type: str, actor_email: str | None = None, **details: Any) -> None:
    ctx.audit(event_type, actor_email=actor_email, details=details)

