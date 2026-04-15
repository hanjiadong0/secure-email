from __future__ import annotations

from fastapi import FastAPI, Header, Request

from common.schemas import ComposeAssistRequest, ComposeAssistResponse, SmartModuleStatus
from server.auth import verify_authenticated_request
from server.smart import compose_with_smart_backend, smart_backend_status
from server.storage import AppContext


def _load_context_message(ctx: AppContext, owner_email: str, message_id: str | None) -> dict[str, str] | None:
    if not message_id:
        return None
    with ctx.connect() as conn:
        row = conn.execute(
            "SELECT message_id, thread_id, from_email, subject, body_text FROM mail_items "
            "WHERE owner_email = ? AND message_id = ? ORDER BY created_at DESC LIMIT 1",
            (owner_email, message_id),
        ).fetchone()
    if row is None:
        return None
    return {
        "message_id": row["message_id"],
        "thread_id": row["thread_id"],
        "from_email": ctx.decrypt_text(row["from_email"]),
        "subject": ctx.decrypt_text(row["subject"]),
        "body_text": ctx.decrypt_text(row["body_text"]),
    }


def register_routes(app: FastAPI, ctx: AppContext) -> None:
    @app.get("/v1/smart/status", response_model=SmartModuleStatus)
    def smart_status() -> SmartModuleStatus:
        payload = smart_backend_status(
            ctx.config,
            ctx.get_secret("openai_api_key") or ctx.config.openai_api_key,
        )
        return SmartModuleStatus.model_validate(payload)

    @app.post("/v1/smart/compose", response_model=ComposeAssistResponse)
    async def compose_assist(
        payload: ComposeAssistRequest,
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> ComposeAssistResponse:
        raw_payload = await request.json()
        user = verify_authenticated_request(
            ctx,
            request,
            authorization,
            raw_payload if isinstance(raw_payload, dict) else payload.model_dump(),
        )
        context_message = _load_context_message(ctx, user["email"], payload.context_message_id)
        result = compose_with_smart_backend(
            ctx.config,
            action=payload.action,
            instruction=payload.instruction,
            to=payload.to,
            cc=payload.cc,
            subject=payload.subject,
            body_text=payload.body_text,
            thread_id=payload.thread_id,
            context_message=context_message,
            preferred_language=payload.preferred_language,
            openai_api_key=ctx.get_secret("openai_api_key") or ctx.config.openai_api_key,
        )
        ctx.audit(
            "compose_assist_used",
            actor_email=user["email"],
            details={
                "action": payload.action,
                "backend": result.get("smart_backend", "heuristic"),
                "used_fallback": bool(result.get("used_fallback")),
                "context_message_id": payload.context_message_id,
                "language": result.get("language", "English"),
            },
        )
        return ComposeAssistResponse.model_validate(result)
