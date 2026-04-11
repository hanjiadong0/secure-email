from __future__ import annotations

import base64
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request, Response

from common.crypto import sha256_hex
from common.schemas import AttachmentMeta, AttachmentUploadRequest
from common.utils import ensure_directory, isoformat_utc, new_id
from server.auth import get_current_user, verify_authenticated_request
from server.logging import log_event
from server.rate_limit import enforce_upload_limits
from server.storage import AppContext


ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg"}


def _detect_content_type(data: bytes) -> str | None:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    return None


def _blob_path(ctx: AppContext, blob_key: str) -> Path:
    bucket = ensure_directory(ctx.blobs_root / blob_key[:2])
    return bucket / f"{blob_key}.bin"


def store_attachment_bytes(ctx: AppContext, owner_email: str, filename: str, data: bytes) -> AttachmentMeta:
    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail="Only PNG and JPEG attachments are allowed.")
    if len(data) > ctx.config.max_attachment_bytes:
        raise HTTPException(status_code=400, detail="Attachment exceeds the 5MB limit.")
    content_type = _detect_content_type(data)
    if not content_type:
        raise HTTPException(status_code=400, detail="Attachment magic bytes do not match PNG/JPEG.")
    blob_key = sha256_hex(data)
    path = _blob_path(ctx, blob_key)
    with ctx.connect() as conn:
        existing = conn.execute(
            "SELECT blob_key, ref_count FROM attachment_blobs WHERE blob_key = ?",
            (blob_key,),
        ).fetchone()
        if existing is None:
            path.write_bytes(data)
            conn.execute(
                "INSERT INTO attachment_blobs(blob_key, path, size_bytes, ref_count, created_at) VALUES (?, ?, ?, ?, ?)",
                (blob_key, str(path), len(data), 1, isoformat_utc()),
            )
        else:
            conn.execute(
                "UPDATE attachment_blobs SET ref_count = ref_count + 1 WHERE blob_key = ?",
                (blob_key,),
            )
        attachment_id = new_id()
        conn.execute(
            "INSERT INTO attachments(id, blob_key, filename, content_type, size_bytes, sha256, created_by, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (attachment_id, blob_key, filename, content_type, len(data), blob_key, owner_email, isoformat_utc()),
        )
    return AttachmentMeta(
        id=attachment_id,
        filename=filename,
        content_type=content_type,
        size_bytes=len(data),
        sha256=blob_key,
    )


def load_attachment_metas(ctx: AppContext, attachment_ids: list[str], owner_email: str) -> list[AttachmentMeta]:
    if not attachment_ids:
        return []
    placeholders = ",".join("?" for _ in attachment_ids)
    with ctx.connect() as conn:
        rows = conn.execute(
            f"SELECT id, filename, content_type, size_bytes, sha256 FROM attachments "
            f"WHERE created_by = ? AND id IN ({placeholders})",
            [owner_email, *attachment_ids],
        ).fetchall()
    found = {row["id"] for row in rows}
    missing = [attachment_id for attachment_id in attachment_ids if attachment_id not in found]
    if missing:
        raise HTTPException(status_code=404, detail=f"Attachment(s) not found: {', '.join(missing)}")
    return [
        AttachmentMeta(
            id=row["id"],
            filename=row["filename"],
            content_type=row["content_type"],
            size_bytes=row["size_bytes"],
            sha256=row["sha256"],
        )
        for row in rows
    ]


def export_attachment_payloads(ctx: AppContext, attachment_ids: list[str], owner_email: str) -> tuple[list[AttachmentMeta], list[dict[str, str]]]:
    metas = load_attachment_metas(ctx, attachment_ids, owner_email)
    relay_payloads: list[dict[str, str]] = []
    with ctx.connect() as conn:
        for meta in metas:
            row = conn.execute(
                "SELECT attachment_blobs.path FROM attachments "
                "JOIN attachment_blobs ON attachment_blobs.blob_key = attachments.blob_key "
                "WHERE attachments.id = ?",
                (meta.id,),
            ).fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail=f"Attachment blob missing for {meta.id}.")
            data = Path(row["path"]).read_bytes()
            relay_payloads.append(
                {
                    "filename": meta.filename,
                    "content_base64": base64.b64encode(data).decode("ascii"),
                }
            )
    return metas, relay_payloads


def store_relay_attachments(ctx: AppContext, owner_email: str, attachments: list[dict[str, str]]) -> list[AttachmentMeta]:
    stored: list[AttachmentMeta] = []
    for payload in attachments:
        data = base64.b64decode(payload["content_base64"])
        stored.append(store_attachment_bytes(ctx, owner_email, payload["filename"], data))
    return stored


def register_routes(app: FastAPI, ctx: AppContext) -> None:
    @app.post("/v1/attachments/upload", response_model=AttachmentMeta)
    def upload(
        payload: AttachmentUploadRequest,
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> AttachmentMeta:
        user = verify_authenticated_request(ctx, request, authorization, payload.model_dump())
        raw = base64.b64decode(payload.content_base64)
        enforce_upload_limits(ctx, user["email"], len(raw))
        stored = store_attachment_bytes(ctx, user["email"], payload.filename, raw)
        log_event(ctx, "attachment_upload", actor_email=user["email"], attachment_id=stored.id, size_bytes=stored.size_bytes)
        return stored

    @app.get("/v1/attachments/{attachment_id}")
    def download(attachment_id: str, authorization: str | None = Header(default=None)) -> Response:
        user = get_current_user(ctx, authorization)
        with ctx.connect() as conn:
            row = conn.execute(
                "SELECT attachments.filename, attachments.content_type, attachment_blobs.path "
                "FROM attachments JOIN attachment_blobs ON attachment_blobs.blob_key = attachments.blob_key "
                "WHERE attachments.id = ?",
                (attachment_id,),
            ).fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="Attachment not found.")
            permitted = conn.execute(
                "SELECT 1 FROM attachments WHERE id = ? AND created_by = ? "
                "UNION SELECT 1 FROM mail_attachment_links WHERE attachment_id = ? AND owner_email = ? LIMIT 1",
                (attachment_id, user["email"], attachment_id, user["email"]),
            ).fetchone()
            if permitted is None:
                raise HTTPException(status_code=403, detail="Attachment access denied.")
        data = Path(row["path"]).read_bytes()
        return Response(
            content=data,
            media_type=row["content_type"],
            headers={"Content-Disposition": f'inline; filename="{row["filename"]}"'},
        )
