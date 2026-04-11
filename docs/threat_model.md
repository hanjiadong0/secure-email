# Threat Model

## Assets

Primary assets:

- user credentials
- session secrets
- mailbox contents
- attachment blobs
- relay trust boundary
- audit logs

## Trust Boundaries

- client <-> domain server
- domain A <-> domain B
- authenticated request layer <-> background / relay work
- mailbox metadata <-> attachment storage
- smart suggestion logic <-> privileged state mutation

## Main Threats

### Authentication

- brute-force login
- credential stuffing
- weak password storage
- session theft

Mitigations:

- Argon2id hashing
- lockout / throttling
- random session secrets
- expiring sessions

### Authenticated Request Tampering

- replayed requests
- modified request body
- duplicated submits
- session sequence abuse

Mitigations:

- request IDs
- nonce
- timestamp window
- sequence tracking
- HMAC over canonical request content

### Relay Attacks

- forged relay requests
- open-relay abuse
- duplicate relay delivery
- replay of prior delivery

Mitigations:

- trusted peer-domain map
- relay HMAC
- relay nonce replay guard
- strict recipient-domain ownership validation

### Authorization

- reading another user's mailbox
- downloading another user's attachment
- recalling someone else's mail
- action-token abuse

Mitigations:

- owner-based queries
- mailbox-to-attachment link checks
- sender ownership validation for recall
- HMAC-protected quick action tokens

### Upload / Storage

- fake image upload
- oversized attachment DoS
- path traversal
- unsafe filename reuse
- cross-domain storage leakage

Mitigations:

- extension allowlist
- magic-byte validation
- size limits
- server-generated storage paths
- per-domain data roots
- dedup only at physical blob level

### Smart Feature Abuse

- prompt injection from malicious mail body
- over-sharing mailbox context
- unsafe autonomous actions

Mitigations:

- advisory-only smart features
- bounded context
- no privileged autonomous execution
- server-side validation on all state-changing actions

## Residual Risk

This repo is a security-conscious prototype, not a production mail platform. Residual risks remain around:

- production TLS handling
- stronger relay identity assurance
- advanced phishing / malware controls
- full queue reliability and recovery
- stronger privacy / retention controls

