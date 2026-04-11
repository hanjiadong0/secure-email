# Protocol

## Overview

The system uses a local HTTPS/JSON-style protocol for:

- client -> server authentication and mailbox operations
- server -> server relay delivery and recall

The implementation stays conceptually aligned with RFC 5321 / RFC 5322 / MIME ideas without implementing full SMTP/IMAP.

## Auth Flow

### Register

`POST /v1/auth/register`

```json
{
  "email": "alice@a.test",
  "password": "demo123"
}
```

### Login

`POST /v1/auth/login`

```json
{
  "email": "alice@a.test",
  "password": "demo123"
}
```

Response:

```json
{
  "email": "alice@a.test",
  "session_id": "...",
  "session_token": "...",
  "session_key": "...",
  "expires_at": "2026-04-11T20:00:00+00:00"
}
```

The registration payload may also include `confirm_password`, and the server
rejects mismatches.

## Authenticated Request Protection

Authenticated state-changing requests include:

- `Authorization: Bearer <session_token>`
- `X-Request-Id`
- `X-Session-Id`
- `X-Seq-No`
- `X-Timestamp`
- `X-Nonce`
- `X-Body-Mac`

`X-Body-Mac` is an HMAC over a canonical JSON structure containing method, path, request metadata, and request body.

This protects against:

- tampering
- replay
- duplicate submission
- stale session action reuse

The per-session `session_key` used for request MACs is encrypted at rest inside
the local SQLite database rather than stored in plaintext.

## Mail Endpoints

### Send Mail

`POST /v1/mail/send`

```json
{
  "to": ["bob@b.test"],
  "cc": [],
  "subject": "Meeting",
  "body_text": "Can we meet tomorrow?",
  "attachment_ids": [],
  "thread_id": null
}
```

Typical response:

```json
{
  "status": "queued",
  "message_id": "...",
  "thread_id": "...",
  "queued_jobs": 1
}
```

### Draft

`POST /v1/mail/draft`

```json
{
  "message_id": null,
  "to": ["bob@b.test"],
  "cc": [],
  "subject": "Draft subject",
  "body_text": "Draft body",
  "attachment_ids": [],
  "send_now": false
}
```

### Recall

`POST /v1/mail/recall`

```json
{
  "message_id": "..."
}
```

### Upload Attachment

`POST /v1/attachments/upload`

```json
{
  "filename": "photo.png",
  "content_base64": "..."
}
```

Only PNG and JPEG are accepted.

Attachment metadata stays API-visible, but sensitive database fields and
persistent queued job payloads are encrypted at rest before being written to the
SQLite store.

### Attachment Analysis

`GET /v1/attachments/{attachment_id}/analysis`

Returns locally generated metadata such as:

- dimensions
- analysis backend
- risk score
- labels
- reasons

### Attachment Transform

`POST /v1/attachments/{attachment_id}/transform`

```json
{
  "mode": "anime"
}
```

Supported transform modes:

- `anime`
- `photo_boost`
- `thumbnail`

## Relay Protocol

Relay requests are sent to:

- `POST /v1/relay/incoming`
- `POST /v1/relay/recall`

Relay security headers:

- `X-Relay-Domain`
- `X-Relay-Timestamp`
- `X-Relay-Nonce`
- `X-Relay-Mac`

The relay MAC is an HMAC over method, path, source domain, timestamp, nonce, and body.

## Smart Module

The default demo configs use a local Ollama runtime:

- `smart_backend: ollama`
- `smart_local_only: true`
- `ollama_model: llama3.2:latest`
- `ollama_base_url: http://127.0.0.1:11434`

Optional local Hugging Face mode is also supported through:

- `smart_backend: huggingface_local`
- `hf_text_model: <local-or-cached-model>`
- `hf_vision_model: <local-or-cached-model>`
- `hf_device: cpu`

The smart pipeline asks the local model for:

- classification
- keyword suggestions
- quick replies
- phishing hints
- optional image labels for attachment analysis

If the local model is unavailable or returns invalid output, the server falls
back to the built-in heuristic engine.

## Mailbox States

The system is designed around explicit lifecycle states such as:

- `draft`
- `queued`
- `sending`
- `delivered`
- `read`
- `recall_requested`
- `recalled`
- `recall_failed`

The current implementation stores:

- mailbox `folder`
- sender-visible `delivery_state`
- read metadata
- recall metadata

Queued delivery workers move sent mail from `queued` toward `delivered`
as background jobs complete.
