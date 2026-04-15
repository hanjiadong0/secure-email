from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class RegisterRequest(BaseModel):
    email: str
    password: str
    confirm_password: str | None = None


class LoginRequest(BaseModel):
    email: str
    password: str


class AuthResponse(BaseModel):
    email: str
    session_id: str
    session_token: str
    session_key: str
    expires_at: str


class PublishKeyRequest(BaseModel):
    algorithm: str = "ECDH-P256-HKDF-SHA256-AESGCM"
    curve: str = "P-256"
    public_key: str


class PublishedKey(BaseModel):
    email: str
    algorithm: str
    curve: str
    public_key: str
    updated_at: str


class KeyResolveRequest(BaseModel):
    emails: list[str] = Field(default_factory=list)


class KeyResolveResponse(BaseModel):
    keys: list[PublishedKey] = Field(default_factory=list)
    missing: list[str] = Field(default_factory=list)


class AttachmentUploadRequest(BaseModel):
    filename: str
    content_base64: str


class AttachmentMeta(BaseModel):
    id: str
    filename: str
    content_type: str
    size_bytes: int
    sha256: str
    analysis: dict[str, Any] = Field(default_factory=dict)


class AttachmentAnalysisResponse(BaseModel):
    attachment_id: str
    filename: str
    content_type: str
    analysis: dict[str, Any] = Field(default_factory=dict)


class AttachmentTransformRequest(BaseModel):
    mode: str


class SavedAttachment(BaseModel):
    id: str
    filename: str
    content_type: str
    size_bytes: int
    sha256: str
    analysis: dict[str, Any] = Field(default_factory=dict)
    created_at: str
    linked_folders: list[str] = Field(default_factory=list)
    deletable: bool = True


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
    e2e_encrypted: bool = False
    e2e_envelope: dict[str, Any] = Field(default_factory=dict)


class SendMailRequest(BaseModel):
    to: list[str]
    cc: list[str] = Field(default_factory=list)
    subject: str
    body_text: str
    attachment_ids: list[str] = Field(default_factory=list)
    thread_id: str | None = None
    e2e_envelope: dict[str, Any] | None = None


class DraftRequest(BaseModel):
    message_id: str | None = None
    to: list[str] = Field(default_factory=list)
    cc: list[str] = Field(default_factory=list)
    subject: str = ""
    body_text: str = ""
    attachment_ids: list[str] = Field(default_factory=list)
    thread_id: str | None = None
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


class GroupSummary(BaseModel):
    name: str
    members: list[str] = Field(default_factory=list)
    created_at: str


class ActionExecutionRequest(BaseModel):
    token: str


class TodoItem(BaseModel):
    id: str
    owner_email: str
    message_id: str
    title: str
    created_at: str


class CalendarEvent(BaseModel):
    id: str
    owner_email: str
    message_id: str
    title: str
    starts_at: str
    duration_minutes: int = 30
    created_at: str
    source_action: str


class MailboxDashboardResponse(BaseModel):
    inbox: list[MailSummary] = Field(default_factory=list)
    sent: list[MailSummary] = Field(default_factory=list)
    drafts: list[MailSummary] = Field(default_factory=list)
    todos: list[TodoItem] = Field(default_factory=list)
    calendar_events: list[CalendarEvent] = Field(default_factory=list)
    groups: list[GroupSummary] = Field(default_factory=list)


class SmartModuleStatus(BaseModel):
    configured_backend: str = "heuristic"
    effective_backend: str = "heuristic"
    status: str = "ready"
    available: bool = True
    local_only: bool = True
    configured_model: str | None = None
    endpoint: str | None = None
    detail: str = ""


class ComposeAssistRequest(BaseModel):
    action: Literal["draft", "continue", "polish"] = "draft"
    instruction: str = ""
    to: list[str] = Field(default_factory=list)
    cc: list[str] = Field(default_factory=list)
    subject: str = ""
    body_text: str = ""
    thread_id: str | None = None
    context_message_id: str | None = None
    preferred_language: str | None = None


class ComposeAssistResponse(BaseModel):
    action: Literal["draft", "continue", "polish"]
    subject: str = ""
    body_text: str = ""
    smart_backend: str = "heuristic"
    smart_model: str | None = None
    used_fallback: bool = False
    language: str = "English"
    context_used: bool = False
    detail: str = ""


class SecuritySimulationRequest(BaseModel):
    scenario: str = "full"


class SecurityScenarioReport(BaseModel):
    scenario_id: str
    scenario: str
    category: str = ""
    severity: str = "medium"
    attacker_name: str = ""
    attacker_class: str = ""
    attacker_script: str = ""
    trust_boundary: str = ""
    security_objectives: list[str] = Field(default_factory=list)
    entry_points: list[str] = Field(default_factory=list)
    attacker_goal: str = ""
    attack_path: list[str] = Field(default_factory=list)
    defender_controls: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    outcome: str = ""
    result_label: str = ""
    explanation: str = ""
    residual_risk: str = ""
    attempts: int = 0
    blocked: int = 0
    detected: int = 0
    attacker_success: int = 0
    notes: str = ""


class SecurityEvidenceResponse(BaseModel):
    status: str = "unavailable"
    generated_at: str | None = None
    metrics: dict[str, int] = Field(default_factory=dict)
    overview: dict[str, Any] = Field(default_factory=dict)
    methodology: list[str] = Field(default_factory=list)
    threat_model: dict[str, Any] = Field(default_factory=dict)
    scenarios: list[SecurityScenarioReport] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    images: dict[str, dict[str, str]] = Field(default_factory=dict)


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
    e2e_envelope: dict[str, Any] | None = None


class RelayRecallRequest(BaseModel):
    source_domain: str
    source_email: str
    message_id: str
    recipients: list[str]
    requested_at: str
