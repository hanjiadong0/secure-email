# Assignment Coverage

This document maps the assignment requirements to the current implementation.

## Core Goal

Requirement:
- Build a usable, testable, and security-aware email system in a local environment.

Implemented by:
- Two local FastAPI domain servers in [server/main.py](../server/main.py)
- CLI client in [client/cli.py](../client/cli.py)
- Browser client in [web/index.html](../web/index.html) and [web/app.js](../web/app.js)
- Security controls in [server/auth.py](../server/auth.py), [server/rate_limit.py](../server/rate_limit.py), [server/relay.py](../server/relay.py), and [server/attachments.py](../server/attachments.py)
- Reproducible tests in [tests/test_secure_mail.py](../tests/test_secure_mail.py)

## Overall Constraints

Requirement:
- Do not directly use a mature open-source email system as the core implementation.

Implemented by:
- Custom HTTPS/JSON protocol and local mail lifecycle
- No Postfix/Dovecot/SMTP stack used as the runtime core

Requirement:
- General networking and crypto libraries are allowed if their usage is explained.

Implemented by:
- `FastAPI` and `httpx` for local HTTP APIs and relay
- `argon2-cffi` for password hashing
- HMAC and SHA-256 helpers in [common/crypto.py](../common/crypto.py)

Requirement:
- All functions need reproducible tests and results.

Implemented by:
- Test suite in [tests/test_secure_mail.py](../tests/test_secure_mail.py)
- Test summary in [docs/test_report.md](./test_report.md)
- Demo and stress scripts in [scripts](../scripts)

## Mandatory Function 1: Server Management

Requirement:
- Implement a server process that receives, stores, and distributes mail.

Implemented by:
- [server/main.py](../server/main.py)
- [server/mailbox.py](../server/mailbox.py)
- [server/relay.py](../server/relay.py)
- [server/storage.py](../server/storage.py)
- [server/workers.py](../server/workers.py)

Requirement:
- Run two servers at the same time as isolated domains.

Implemented by:
- [configs/domainA.yaml](../configs/domainA.yaml)
- [configs/domainB.yaml](../configs/domainB.yaml)
- [scripts/start_domain_a.ps1](../scripts/start_domain_a.ps1)
- [scripts/start_domain_b.ps1](../scripts/start_domain_b.ps1)

Requirement:
- The two systems can send mail to each other.

Implemented by:
- Authenticated relay endpoints in [server/relay.py](../server/relay.py)
- Cross-domain queue-backed delivery in [server/workers.py](../server/workers.py)

Requirement:
- Storage must be logically isolated.

Implemented by:
- Per-domain `data_root` configuration in [common/config.py](../common/config.py)
- Separate SQLite, attachments, and logs per domain

## Mandatory Function 2: Client Management

Requirement:
- Register/login with username, password, confirm password.

Implemented by:
- Browser registration form with confirm password in [web/index.html](../web/index.html)
- Browser validation and API request in [web/app.js](../web/app.js)
- CLI registration with `--confirm-password` in [client/cli.py](../client/cli.py)
- Backend validation in [server/auth.py](../server/auth.py)

Requirement:
- Compose mail, inbox, sent, drafts.

Implemented by:
- [server/mailbox.py](../server/mailbox.py)
- [client/api.py](../client/api.py)
- [web/app.js](../web/app.js)

Requirement:
- Group send and groups.

Implemented by:
- Group endpoints in [server/mailbox.py](../server/mailbox.py)
- Browser forms in [web/index.html](../web/index.html)

Requirement:
- Quick reply with recipient and subject context plus recommendations.

Implemented by:
- Reply suggestions in [common/text_features.py](../common/text_features.py)
- Quick reply action in [web/app.js](../web/app.js)
- CLI reply flow in [client/cli.py](../client/cli.py)

Requirement:
- Image attachment sending and reading.

Implemented by:
- Upload/download logic in [server/attachments.py](../server/attachments.py)
- Browser upload and preview in [web/app.js](../web/app.js)
- Florence-2-backed attachment review in [server/image_ai.py](../server/image_ai.py)

Requirement:
- Mail recall.

Implemented by:
- Recall flow in [server/mailbox.py](../server/mailbox.py)
- Relay recall in [server/relay.py](../server/relay.py)

Requirement:
- Useful and safe quick actions.

Implemented by:
- Signed quick action tokens in [server/mailbox.py](../server/mailbox.py)
- Current actions:
  - add TODO
  - acknowledge message

Requirement:
- At least 2 intelligent/algorithm-enhanced functions.

Implemented by:
- Local Ollama-backed smart analysis with heuristic fallback
- Florence-2-backed attachment analysis
- Keyword extraction with stopword filtering
- Mail classification
- Fuzzy search
- Quick reply suggestions
- Suspicious-mail heuristics
- Attachment deduplication

## Security and Stability

Requirement:
- Secure post-login client/server interaction.

Implemented by:
- Session token plus per-request HMAC, request ID, nonce, timestamp, and sequence number
- Code:
  - [server/auth.py](../server/auth.py)
  - [common/crypto.py](../common/crypto.py)
  - [client/api.py](../client/api.py)
  - [web/app.js](../web/app.js)

Requirement:
- Anti-brute-force login.

Implemented by:
- Rate limiting and short-term lockout in [server/rate_limit.py](../server/rate_limit.py)

Requirement:
- Basic client anti-abuse / anti-DOS protection.

Implemented by:
- Browser-side duplicate submission guard and cooldown in [web/app.js](../web/app.js)
- Server-side send/upload rate limiting still remains the main enforcement layer

Requirement:
- Sensitive account information must not be stored in plaintext.

Implemented by:
- Argon2id password hashing in [common/crypto.py](../common/crypto.py)
- Encrypted-at-rest session keys, mailbox fields, and queued job payloads via [common/data_security.py](../common/data_security.py) and [server/storage.py](../server/storage.py)

Requirement:
- Basic phishing / spam identification.

Implemented by:
- Heuristics in [common/text_features.py](../common/text_features.py)
- Integration in [server/phishing.py](../server/phishing.py)
- Suspicious mail highlighting in the UI

Requirement:
- Recall verification must prevent wrong execution.

Implemented by:
- Ownership, recall window, unread-state, relay verification, and pending-job cancellation in [server/mailbox.py](../server/mailbox.py) and [server/relay.py](../server/relay.py)

## Testing and Acceptance

Requirement:
- Two-domain interoperability.

Covered by:
- [tests/test_secure_mail.py](../tests/test_secure_mail.py)

Requirement:
- Multi-client concurrent login/send/receive without crash.

Covered by:
- Concurrent acceptance test in [tests/test_secure_mail.py](../tests/test_secure_mail.py)
- Stress script in [scripts/stress_test.py](../scripts/stress_test.py)

Requirement:
- Brute-force login protection triggers.

Covered by:
- Lockout test in [tests/test_secure_mail.py](../tests/test_secure_mail.py)

Requirement:
- High-frequency sending triggers rate limit.

Covered by:
- Rate-limit test in [tests/test_secure_mail.py](../tests/test_secure_mail.py)

Requirement:
- Phishing sample can be marked.

Covered by:
- Suspicious-mail test in [tests/test_secure_mail.py](../tests/test_secure_mail.py)

Requirement:
- Image attachments can be sent and received.

Covered by:
- Attachment send/receive test in [tests/test_secure_mail.py](../tests/test_secure_mail.py)

Requirement:
- Storage strategy such as deduplication behaves correctly.

Covered by:
- Deduplication test in [tests/test_secure_mail.py](../tests/test_secure_mail.py)

## Deliverables

Requirement:
- Server/client source code
- Startup scripts and dual-domain config
- Protocol explanation
- Test scripts and results
- Threat model and protections

Delivered as:
- [server](../server)
- [client](../client)
- [configs](../configs)
- [scripts](../scripts)
- [docs/protocol.md](./protocol.md)
- [docs/test_report.md](./test_report.md)
- [docs/threat_model.md](./threat_model.md)

## Bonus Items

Delivered as implementation or design/analysis docs:
- Malicious mail script PoC discussion: [docs/malicious_mail_poc.md](./malicious_mail_poc.md)
- End-to-end encryption implementation and design notes: [docs/end_to_end_encryption_design.md](./end_to_end_encryption_design.md)
- Audit logging and anomaly alerting: [docs/alerting_and_audit.md](./alerting_and_audit.md)
- P2P mail feasibility: [docs/p2p_feasibility.md](./p2p_feasibility.md)
