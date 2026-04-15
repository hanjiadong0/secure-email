from __future__ import annotations

import base64
import io
import mimetypes
import zipfile
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request, Response
from PIL import Image, UnidentifiedImageError

from common.crypto import sha256_hex
from common.schemas import (
    AttachmentAnalysisResponse,
    AttachmentMeta,
    AttachmentTransformRequest,
    AttachmentUploadRequest,
    SavedAttachment,
)
from common.utils import ensure_directory, isoformat_utc, new_id
from server.auth import get_current_user, verify_authenticated_request
from server.image_ai import analyze_attachment_image, compress_attachment_image, transform_attachment_image
from server.logging import log_event
from server.rate_limit import enforce_upload_limits
from server.storage import AppContext


def _detect_content_type(filename: str, data: bytes) -> str:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data.startswith(b"%PDF-"):
        return "application/pdf"
    if data.startswith(b"PK\x03\x04"):
        return "application/zip"
    try:
        with Image.open(io.BytesIO(data)) as image:
            image.verify()
            image_format = (image.format or "").upper()
        if image_format == "PNG":
            return "image/png"
        if image_format in {"JPG", "JPEG"}:
            return "image/jpeg"
        if image_format:
            return f"image/{image_format.lower()}"
    except (UnidentifiedImageError, OSError, ValueError):
        pass
    guessed_type, _ = mimetypes.guess_type(filename)
    if guessed_type and guessed_type.startswith("image/"):
        # Do not trust extension-only image types if bytes are not valid image data.
        return "application/octet-stream"
    return guessed_type or "application/octet-stream"


def _default_attachment_analysis(filename: str, content_type: str) -> dict:
    return {
        "summary": f"Stored as {content_type}",
        "labels": ["attachment", content_type.split("/", 1)[0]],
        "suspicious": False,
        "risk_score": 0,
        "reasons": [],
        "backend": "non_image_attachment",
        "preview_ready": False,
        "transform_modes": [],
        "source_filename": filename,
    }


def _blob_path(ctx: AppContext, blob_key: str) -> Path:
    bucket = ensure_directory(ctx.blobs_root / blob_key[:2])
    return bucket / f"{blob_key}.bin"


def _attachment_meta_from_row(ctx: AppContext, row) -> AttachmentMeta:
    return AttachmentMeta(
        id=row["id"],
        filename=ctx.decrypt_text(row["filename"]),
        content_type=row["content_type"],
        size_bytes=row["size_bytes"],
        sha256=row["sha256"],
        analysis=ctx.decrypt_json(row["analysis_json"]) or {},
    )


def _saved_attachment_from_row(ctx: AppContext, row) -> SavedAttachment:
    linked_folders = sorted(
        {
            folder
            for folder in str(row["linked_folders"] or "").split(",")
            if folder
        }
    )
    linked_mail_count = int(row["linked_mail_count"] or 0)
    return SavedAttachment(
        id=row["id"],
        filename=ctx.decrypt_text(row["filename"]),
        content_type=row["content_type"],
        size_bytes=row["size_bytes"],
        sha256=row["sha256"],
        analysis=ctx.decrypt_json(row["analysis_json"]) or {},
        created_at=row["created_at"],
        linked_folders=linked_folders,
        deletable=linked_mail_count == 0,
    )


def _resolve_attachment_row_for_user(ctx: AppContext, attachment_id: str, user_email: str):
    with ctx.connect() as conn:
        row = conn.execute(
            "SELECT attachments.id, attachments.filename, attachments.content_type, attachments.size_bytes, attachments.sha256, "
            "attachments.analysis_json, attachment_blobs.path "
            "FROM attachments JOIN attachment_blobs ON attachment_blobs.blob_key = attachments.blob_key "
            "WHERE attachments.id = ?",
            (attachment_id,),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Attachment not found.")
        permitted = conn.execute(
            "SELECT 1 FROM attachments WHERE id = ? AND created_by = ? "
            "UNION SELECT 1 FROM mail_attachment_links WHERE attachment_id = ? AND owner_email = ? LIMIT 1",
            (attachment_id, user_email, attachment_id, user_email),
        ).fetchone()
        if permitted is None:
            raise HTTPException(status_code=403, detail="Attachment access denied.")
    return row


def _compression_analysis(
    *,
    filename: str,
    content_type: str,
    original_size: int,
    compressed_size: int,
    source_filename: str,
    source_content_type: str,
    base_analysis: dict | None = None,
) -> dict:
    saved_bytes = max(original_size - compressed_size, 0)
    ratio_percent = round((compressed_size / max(original_size, 1)) * 100, 1)
    analysis = dict(base_analysis or _default_attachment_analysis(filename, content_type))
    analysis["source_transform"] = "compress"
    analysis["source_filename"] = source_filename
    analysis["source_content_type"] = source_content_type
    analysis["compression"] = {
        "original_size_bytes": original_size,
        "compressed_size_bytes": compressed_size,
        "saved_bytes": saved_bytes,
        "ratio_percent": ratio_percent,
    }
    if compressed_size < original_size:
        analysis["summary"] = (
            f"Compressed copy saved {saved_bytes} bytes "
            f"({ratio_percent}% of original size retained)."
        )
    else:
        analysis["summary"] = (
            "Archive copy created. The source file was already compact, "
            "so the compressed version is not smaller."
        )
    labels = list(analysis.get("labels") or [])
    if "compressed" not in labels:
        labels.append("compressed")
    analysis["labels"] = labels[:6]
    return analysis


def _zip_attachment_copy(filename: str, data: bytes) -> tuple[str, bytes]:
    archive_name = f"{filename}.zip"
    output = io.BytesIO()
    with zipfile.ZipFile(output, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        archive.writestr(filename, data)
    return archive_name, output.getvalue()


def _replace_attachment_in_owner_drafts(
    ctx: AppContext,
    owner_email: str,
    source_attachment_id: str,
    replacement: AttachmentMeta,
) -> int:
    replacement_payload = replacement.model_dump()
    updated_drafts = 0
    with ctx.connect() as conn:
        rows = conn.execute(
            "SELECT mailbox_item_id, attachments_json FROM mail_items WHERE owner_email = ? AND folder = 'draft'",
            (owner_email,),
        ).fetchall()
        for row in rows:
            attachments = ctx.decrypt_json(row["attachments_json"]) or []
            if not isinstance(attachments, list):
                continue
            replacement_present = any(
                isinstance(item, dict) and item.get("id") == replacement.id
                for item in attachments
            )
            updated_attachments: list[dict] = []
            changed = False
            for item in attachments:
                if not isinstance(item, dict):
                    continue
                if item.get("id") == source_attachment_id:
                    changed = True
                    if not replacement_present:
                        updated_attachments.append(replacement_payload)
                        replacement_present = True
                    continue
                updated_attachments.append(item)
            if not changed:
                continue
            conn.execute(
                "UPDATE mail_items SET attachments_json = ? WHERE mailbox_item_id = ?",
                (ctx.encrypt_json(updated_attachments), row["mailbox_item_id"]),
            )
            conn.execute(
                "DELETE FROM mail_attachment_links WHERE mailbox_item_id = ? AND attachment_id = ?",
                (row["mailbox_item_id"], source_attachment_id),
            )
            if any(isinstance(item, dict) and item.get("id") == replacement.id for item in updated_attachments):
                conn.execute(
                    "INSERT OR IGNORE INTO mail_attachment_links(mailbox_item_id, owner_email, attachment_id) VALUES (?, ?, ?)",
                    (row["mailbox_item_id"], owner_email, replacement.id),
                )
            updated_drafts += 1
    return updated_drafts


def store_attachment_bytes(
    ctx: AppContext,
    owner_email: str,
    filename: str,
    data: bytes,
    *,
    analysis: dict | None = None,
) -> AttachmentMeta:
    if not filename.strip():
        raise HTTPException(status_code=400, detail="Attachment filename is required.")
    if len(data) > ctx.config.max_attachment_bytes:
        raise HTTPException(status_code=400, detail="Attachment exceeds the 5MB limit.")
    content_type = _detect_content_type(filename, data)
    if analysis is not None:
        resolved_analysis = analysis
    elif content_type.startswith("image/"):
        resolved_analysis = analyze_attachment_image(
            config=ctx.config,
            filename=filename,
            content_type=content_type,
            data=data,
        )
    else:
        resolved_analysis = _default_attachment_analysis(filename, content_type)
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
            "INSERT INTO attachments(id, blob_key, filename, content_type, size_bytes, sha256, analysis_json, created_by, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                attachment_id,
                blob_key,
                ctx.encrypt_text(filename),
                content_type,
                len(data),
                blob_key,
                ctx.encrypt_json(resolved_analysis),
                owner_email,
                isoformat_utc(),
            ),
        )
    return AttachmentMeta(
        id=attachment_id,
        filename=filename,
        content_type=content_type,
        size_bytes=len(data),
        sha256=blob_key,
        analysis=resolved_analysis,
    )


def load_attachment_metas(ctx: AppContext, attachment_ids: list[str], owner_email: str) -> list[AttachmentMeta]:
    if not attachment_ids:
        return []
    placeholders = ",".join("?" for _ in attachment_ids)
    with ctx.connect() as conn:
        rows = conn.execute(
            f"SELECT id, filename, content_type, size_bytes, sha256, analysis_json FROM attachments "
            f"WHERE created_by = ? AND id IN ({placeholders})",
            [owner_email, *attachment_ids],
        ).fetchall()
    found = {row["id"] for row in rows}
    missing = [attachment_id for attachment_id in attachment_ids if attachment_id not in found]
    if missing:
        raise HTTPException(status_code=404, detail=f"Attachment(s) not found: {', '.join(missing)}")
    return [_attachment_meta_from_row(ctx, row) for row in rows]


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

    @app.get("/v1/attachments", response_model=list[SavedAttachment])
    def list_saved_attachments(authorization: str | None = Header(default=None)) -> list[SavedAttachment]:
        user = get_current_user(ctx, authorization)
        with ctx.connect() as conn:
            rows = conn.execute(
                "SELECT attachments.id, attachments.filename, attachments.content_type, attachments.size_bytes, attachments.sha256, "
                "attachments.analysis_json, attachments.created_at, "
                "(SELECT COUNT(*) FROM mail_attachment_links WHERE attachment_id = attachments.id) AS linked_mail_count, "
                "(SELECT GROUP_CONCAT(DISTINCT mail_items.folder) "
                " FROM mail_attachment_links "
                " JOIN mail_items ON mail_items.mailbox_item_id = mail_attachment_links.mailbox_item_id "
                " WHERE mail_attachment_links.attachment_id = attachments.id AND mail_attachment_links.owner_email = ?) AS linked_folders "
                "FROM attachments WHERE created_by = ? ORDER BY created_at DESC",
                (user["email"], user["email"]),
            ).fetchall()
        return [_saved_attachment_from_row(ctx, row) for row in rows]

    @app.get("/v1/attachments/{attachment_id}")
    def download(attachment_id: str, authorization: str | None = Header(default=None)) -> Response:
        user = get_current_user(ctx, authorization)
        row = _resolve_attachment_row_for_user(ctx, attachment_id, user["email"])
        data = Path(row["path"]).read_bytes()
        return Response(
            content=data,
            media_type=row["content_type"],
            headers={"Content-Disposition": f'inline; filename="{ctx.decrypt_text(row["filename"])}"'},
        )

    @app.get("/v1/attachments/{attachment_id}/analysis", response_model=AttachmentAnalysisResponse)
    def analysis(attachment_id: str, authorization: str | None = Header(default=None)) -> AttachmentAnalysisResponse:
        user = get_current_user(ctx, authorization)
        row = _resolve_attachment_row_for_user(ctx, attachment_id, user["email"])
        return AttachmentAnalysisResponse(
            attachment_id=attachment_id,
            filename=ctx.decrypt_text(row["filename"]),
            content_type=row["content_type"],
            analysis=ctx.decrypt_json(row["analysis_json"]) or {},
        )

    @app.post("/v1/attachments/{attachment_id}/transform", response_model=AttachmentMeta)
    def transform(
        attachment_id: str,
        payload: AttachmentTransformRequest,
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> AttachmentMeta:
        user = verify_authenticated_request(
            ctx,
            request,
            authorization,
            payload.model_dump(),
        )
        row = _resolve_attachment_row_for_user(ctx, attachment_id, user["email"])
        source_filename = ctx.decrypt_text(row["filename"])
        if not str(row["content_type"]).lower().startswith("image/"):
            raise HTTPException(status_code=400, detail="Attachment transform is only available for image attachments.")
        raw = Path(row["path"]).read_bytes()
        try:
            transformed_name, transformed_bytes, analysis_payload = transform_attachment_image(
                config=ctx.config,
                filename=source_filename,
                data=raw,
                mode=payload.mode,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        stored = store_attachment_bytes(
            ctx,
            user["email"],
            transformed_name,
            transformed_bytes,
            analysis=analysis_payload,
        )
        log_event(
            ctx,
            "attachment_transform",
            actor_email=user["email"],
            source_attachment_id=attachment_id,
            transformed_attachment_id=stored.id,
            mode=payload.mode,
        )
        return stored

    @app.post("/v1/attachments/{attachment_id}/compress", response_model=AttachmentMeta)
    def compress(
        attachment_id: str,
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> AttachmentMeta:
        user = verify_authenticated_request(ctx, request, authorization, {})
        row = _resolve_attachment_row_for_user(ctx, attachment_id, user["email"])
        source_filename = ctx.decrypt_text(row["filename"])
        source_content_type = str(row["content_type"] or "application/octet-stream")
        raw = Path(row["path"]).read_bytes()

        compressed_name: str
        compressed_bytes: bytes
        base_analysis: dict | None = None

        if source_content_type.lower().startswith("image/"):
            compressed_image = compress_attachment_image(
                filename=source_filename,
                content_type=source_content_type,
                data=raw,
            )
            if compressed_image is not None:
                compressed_name, compressed_bytes = compressed_image
                compressed_content_type = _detect_content_type(compressed_name, compressed_bytes)
                base_analysis = analyze_attachment_image(
                    config=ctx.config,
                    filename=compressed_name,
                    content_type=compressed_content_type,
                    data=compressed_bytes,
                )
            else:
                compressed_name, compressed_bytes = _zip_attachment_copy(source_filename, raw)
        else:
            compressed_name, compressed_bytes = _zip_attachment_copy(source_filename, raw)

        analysis = _compression_analysis(
            filename=compressed_name,
            content_type=_detect_content_type(compressed_name, compressed_bytes),
            original_size=len(raw),
            compressed_size=len(compressed_bytes),
            source_filename=source_filename,
            source_content_type=source_content_type,
            base_analysis=base_analysis,
        )
        stored = store_attachment_bytes(
            ctx,
            user["email"],
            compressed_name,
            compressed_bytes,
            analysis=analysis,
        )
        draft_replacements = _replace_attachment_in_owner_drafts(ctx, user["email"], attachment_id, stored)
        if draft_replacements:
            stored.analysis = {
                **stored.analysis,
                "draft_replacements": draft_replacements,
                "replacement_note": f"Updated {draft_replacements} editable draft(s) to use the compressed copy.",
            }
        log_event(
            ctx,
            "attachment_compressed",
            actor_email=user["email"],
            source_attachment_id=attachment_id,
            compressed_attachment_id=stored.id,
            original_size_bytes=len(raw),
            compressed_size_bytes=len(compressed_bytes),
            draft_replacements=draft_replacements,
        )
        return stored

    @app.post("/v1/attachments/{attachment_id}/delete")
    def delete_attachment(
        attachment_id: str,
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> dict[str, str]:
        user = verify_authenticated_request(ctx, request, authorization, {})
        blob_path: Path | None = None
        with ctx.connect() as conn:
            row = conn.execute(
                "SELECT attachments.id, attachments.blob_key, attachments.created_by, attachment_blobs.path "
                "FROM attachments JOIN attachment_blobs ON attachment_blobs.blob_key = attachments.blob_key "
                "WHERE attachments.id = ?",
                (attachment_id,),
            ).fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="Attachment not found.")
            if row["created_by"] != user["email"]:
                raise HTTPException(status_code=403, detail="Only the owner can delete a saved attachment.")
            linked = conn.execute(
                "SELECT COUNT(*) AS total FROM mail_attachment_links WHERE attachment_id = ?",
                (attachment_id,),
            ).fetchone()
            if int(linked["total"] or 0) > 0:
                raise HTTPException(
                    status_code=400,
                    detail="Attachment is already linked to mail history and cannot be deleted.",
                )
            conn.execute("DELETE FROM attachments WHERE id = ?", (attachment_id,))
            blob = conn.execute(
                "SELECT ref_count, path FROM attachment_blobs WHERE blob_key = ?",
                (row["blob_key"],),
            ).fetchone()
            if blob is not None and int(blob["ref_count"] or 0) <= 1:
                conn.execute("DELETE FROM attachment_blobs WHERE blob_key = ?", (row["blob_key"],))
                blob_path = Path(blob["path"])
            elif blob is not None:
                conn.execute(
                    "UPDATE attachment_blobs SET ref_count = ref_count - 1 WHERE blob_key = ?",
                    (row["blob_key"],),
                )
        if blob_path is not None and blob_path.exists():
            blob_path.unlink()
        log_event(ctx, "attachment_deleted", actor_email=user["email"], attachment_id=attachment_id)
        return {"status": "deleted", "attachment_id": attachment_id}
