from __future__ import annotations

import argparse
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI

from common.config import DomainConfig
from server import attachments, auth, e2e_keys, mailbox, relay, security, web
from server.storage import AppContext, RelayDispatch
from server.workers import start_workers, stop_workers


def create_app(config: DomainConfig, relay_dispatch: RelayDispatch | None = None) -> FastAPI:
    ctx = AppContext(config=config, relay_dispatch=relay_dispatch)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        start_workers(ctx)
        try:
            yield
        finally:
            stop_workers(ctx)

    app = FastAPI(title=f"Secure Email - {config.domain}", version="0.1.0", lifespan=lifespan)
    app.state.ctx = ctx

    @app.middleware("http")
    async def apply_security_headers(request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'",
        )
        return response

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "domain": config.domain}

    auth.register_routes(app, ctx)
    e2e_keys.register_routes(app, ctx)
    attachments.register_routes(app, ctx)
    mailbox.register_routes(app, ctx)
    relay.register_routes(app, ctx)
    security.register_routes(app, ctx)
    web.register_routes(app, config)
    return app


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a secure email domain server.")
    parser.add_argument("--config", required=True, help="Path to the domain YAML config.")
    parser.add_argument("--ssl-certfile", default=None, help="Optional TLS certificate for HTTPS.")
    parser.add_argument("--ssl-keyfile", default=None, help="Optional TLS private key for HTTPS.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config = DomainConfig.from_file(args.config)
    app = create_app(config)
    uvicorn.run(
        app,
        host=config.host,
        port=config.port,
        ssl_certfile=args.ssl_certfile or config.ssl_certfile,
        ssl_keyfile=args.ssl_keyfile or config.ssl_keyfile,
    )


if __name__ == "__main__":
    main()
