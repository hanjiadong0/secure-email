from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse

from common.schemas import SecurityEvidenceResponse, SecuritySimulationRequest
from common.utils import ensure_directory, isoformat_utc
from server.auth import verify_authenticated_request
from server.logging import log_event
from server.security_simulation import run_attack_defense_simulation
from server.storage import AppContext


ALLOWED_EVIDENCE_FILES = {
    "attacker_vs_defender.png",
    "scenario_matrix.png",
}


def _evidence_root(ctx: AppContext) -> Path:
    return ensure_directory(ctx.config.data_root / "security_evidence")


def _report_path(ctx: AppContext) -> Path:
    return _evidence_root(ctx) / "security_report.json"


def _load_report(ctx: AppContext) -> dict:
    report_file = _report_path(ctx)
    if not report_file.exists():
        return {
            "status": "unavailable",
            "generated_at": None,
            "metrics": {},
            "scenarios": [],
            "recommendations": [],
            "images": {},
        }
    try:
        return json.loads(report_file.read_text(encoding="utf-8"))
    except Exception:
        return {
            "status": "error",
            "generated_at": isoformat_utc(),
            "metrics": {},
            "scenarios": [],
            "recommendations": ["Security report file is invalid and should be regenerated."],
            "images": {},
        }


def register_routes(app: FastAPI, ctx: AppContext) -> None:
    @app.get("/v1/security/evidence", response_model=SecurityEvidenceResponse)
    def security_evidence() -> SecurityEvidenceResponse:
        return SecurityEvidenceResponse(**_load_report(ctx))

    @app.get("/v1/security/evidence/{filename}", include_in_schema=False)
    def security_evidence_file(filename: str) -> FileResponse:
        if filename not in ALLOWED_EVIDENCE_FILES:
            raise HTTPException(status_code=404, detail="Evidence file not found.")
        path = _evidence_root(ctx) / filename
        if not path.exists() or not path.is_file():
            raise HTTPException(status_code=404, detail="Evidence file not available.")
        return FileResponse(path, media_type="image/png")

    @app.post("/v1/security/simulate", response_model=SecurityEvidenceResponse)
    def run_security_simulation(
        payload: SecuritySimulationRequest,
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> SecurityEvidenceResponse:
        user = verify_authenticated_request(ctx, request, authorization, payload.model_dump())
        if payload.scenario.strip().lower() not in {"full", "default"}:
            raise HTTPException(status_code=400, detail="Only 'full' scenario is supported in this build.")
        report = run_attack_defense_simulation(ctx.config, _evidence_root(ctx))
        log_event(
            ctx,
            "security_simulation_run",
            actor_email=user["email"],
            scenarios=len(report.get("scenarios", [])),
            attacker_success=report.get("metrics", {}).get("attacker_success", 0),
        )
        return SecurityEvidenceResponse(**report)
