from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class RegisterRequest(BaseModel):
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


class AuthResponse(BaseModel):
    email: str
    session_id: str
    session_token: str
    session_key: str
    expires_at: str


class AttachmentUploadRequest(BaseModel):
    filename: str
    content_base64: str


class AttachmentMeta(BaseModel):
    id: str
    filename: str
    content_type: str
    size_bytes: int
    sha256: str


class QuickAction(BaseModel):
    action: str
    label: str
    token: str


class MailSummary(BaseModel):
    message_id: str
    thread_id: str
    folder: str
    delivery_state: str = "delivered"
    from_email: str
    to: list[str] = Field(default_factory=list)
    cc: list[str] = Field(default_factory=list)
    subject: str
    body_text: str
    created_at: str
    attachments: list[AttachmentMeta] = Field(default_factory=list)
    security_flags: dict[str, Any] = Field(default_factory=dict)
    keywords: list[str] = Field(default_factory=list)
    classification: str = "General"
    quick_replies: list[str] = Field(default_factory=list)
    actions: list[QuickAction] = Field(default_factory=list)
    recalled: bool = False
    recall_status: str | None = None
    is_read: bool = False


class SendMailRequest(BaseModel):
    to: list[str]
    cc: list[str] = Field(default_factory=list)
    subject: str
    body_text: str
    attachment_ids: list[str] = Field(default_factory=list)
    thread_id: str | None = None


class DraftRequest(BaseModel):
    message_id: str | None = None
    to: list[str] = Field(default_factory=list)
    cc: list[str] = Field(default_factory=list)
    subject: str = ""
    body_text: str = ""
    attachment_ids: list[str] = Field(default_factory=list)
    send_now: bool = False


class RecallRequest(BaseModel):
    message_id: str


class GroupCreateRequest(BaseModel):
    name: str
    members: list[str] = Field(default_factory=list)


class GroupMemberRequest(BaseModel):
    name: str
    member_email: str


class GroupSendRequest(BaseModel):
    group_name: str
    subject: str
    body_text: str
    attachment_ids: list[str] = Field(default_factory=list)


class ActionExecutionRequest(BaseModel):
    token: str


class TodoItem(BaseModel):
    id: str
    owner_email: str
    message_id: str
    title: str
    created_at: str


class ContactSuggestion(BaseModel):
    email: str
    score: float


class SearchResponse(BaseModel):
    messages: list[MailSummary] = Field(default_factory=list)
    contacts: list[ContactSuggestion] = Field(default_factory=list)


class RelayAttachment(BaseModel):
    filename: str
    content_base64: str


class RelayIncomingRequest(BaseModel):
    source_domain: str
    source_email: str
    to: list[str] = Field(default_factory=list)
    recipients: list[str]
    cc: list[str] = Field(default_factory=list)
    message_id: str
    thread_id: str
    subject: str
    body_text: str
    created_at: str
    attachments: list[RelayAttachment] = Field(default_factory=list)


class RelayRecallRequest(BaseModel):
    source_domain: str
    source_email: str
    message_id: str
    recipients: list[str]
    requested_at: str
