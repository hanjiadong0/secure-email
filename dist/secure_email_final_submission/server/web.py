from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from common.config import DomainConfig


WEB_ROOT = Path(__file__).resolve().parent.parent / "web"


def register_routes(app: FastAPI, config: DomainConfig) -> None:
    app.mount("/static", StaticFiles(directory=WEB_ROOT), name="static")

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(WEB_ROOT / "index.html")

    @app.get("/security-lab", include_in_schema=False)
    def security_lab() -> FileResponse:
        return FileResponse(WEB_ROOT / "security-lab.html")

    @app.get("/api-info")
    def api_info() -> dict[str, object]:
        return {
            "service": "secure-email",
            "domain": config.domain,
            "status": "ok",
            "web_ui": "/",
            "security_lab": "/security-lab",
            "endpoints": {
                "health": "/health",
                "auth": ["/v1/auth/register", "/v1/auth/login"],
                "mail": ["/v1/mail/inbox", "/v1/mail/send", "/v1/mail/recall"],
                "attachments": ["/v1/attachments", "/v1/attachments/upload"],
                "calendar": ["/v1/calendar/events"],
                "groups": ["/v1/groups", "/v1/groups/create"],
                "search": ["/v1/mail/search", "/v1/contacts/autocomplete"],
                "security": ["/v1/security/evidence", "/v1/security/simulate"],
                "smart": ["/v1/smart/status", "/v1/smart/compose"],
            },
        }

    @app.get("/favicon.ico", include_in_schema=False)
    def favicon() -> Response:
        return Response(status_code=204)
