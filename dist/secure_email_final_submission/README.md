# Smart Secure Email System

A local, security-aware email prototype with two isolated domains, cross-domain delivery, image attachments, recall, quick actions, quick replies, local-Ollama smart text analysis, Florence-2-backed attachment review, optional ECC end-to-end encrypted mail, encrypted-at-rest mailbox storage, and reproducible tests.

This project combines the PDF deep-research plan with the current README direction:

- the PDF defines the MVP scope, security baseline, interview-ready explanations, and four-day delivery plan
- the README adds stronger concurrency, queueing, replay protection, and post-login request integrity requirements

The result is a local secure mail system that is meant to feel like a small real distributed system, not just a mailbox CRUD app.

## Scope

This is not a production SMTP/IMAP server and it does not use a full mailserver like Postfix or Dovecot as the core implementation.

Instead, the project builds its own small mail protocol over HTTP/JSON for local demos, with optional TLS support for HTTPS deployments, while staying conceptually aligned with:

- SMTP transport ideas from RFC 5321
- mail/message structure from RFC 5322
- attachment concepts from MIME

That keeps the implementation achievable while still letting us explain the design using real standards.

## Must-Have Goals

The merged target for this repo is:

- two independent server processes simulating two isolated domains
- logically separated storage roots for each domain
- registration and login
- inbox, sent, drafts
- cross-domain mail delivery
- multiple recipients and group send
- image attachment upload and download
- attachment preview, Florence-2-backed risk analysis, and safe local transforms
- mail recall with verification rules
- quick actions with safe server-side validation
- quick replies and lightweight smart suggestions
- local LLM smart analysis through Ollama plus local Florence-2 image review
- optional ECC end-to-end encrypted text mail
- keyword extraction plus classification
- fuzzy mail/contact search
- brute-force protection
- anti-abuse rate limiting
- cryptographic protection for sensitive database fields and queued job payloads
- phishing / suspicious mail heuristics
- structured audit logs
- reproducible tests, protocol docs, and threat model docs

## Main Design Principle

Request handlers should accept authenticated user intent quickly and safely, while slower work is pushed into controlled background processing.

That means we separate:

- request authentication and validation
- transactional state changes
- outgoing delivery
- incoming processing
- attachment hashing and deduplication
- smart analysis like phishing scoring and quick reply generation
- safe image analysis and transform metadata
- ECC public-key discovery and ciphertext envelopes for optional end-to-end mail

This is important because concurrent mail send/receive behavior becomes unstable if every slow step runs inline in the same request path.

## Architecture

### Components

#### Client

The client is a CLI/TUI-style process responsible for:

- register / login
- composing mail
- viewing inbox, sent, drafts
- uploading attachments
- showing smart suggestions
- executing quick actions

#### Domain Server

Each domain server is responsible for:

- authenticating users
- issuing and validating sessions
- verifying authenticated requests
- storing mailbox metadata and attachment references
- managing outgoing and incoming delivery state
- validating recall and quick actions

#### Background Workers

Workers handle slower or retriable tasks:

- outgoing relay delivery
- inbound processing
- attachment dedup / hashing
- phishing scoring
- quick reply generation
- local attachment review

The current implementation uses a SQLite-backed job queue plus bounded background workers for local delivery, cross-domain relay delivery, and inbound inbox insertion.

### Two Isolated Domains

Example local domains:

- `a.test`
- `b.test`

or, if preferred for demos:

- `alpha.mail.local`
- `beta.mail.local`

Each domain has its own storage root, database, logs, and attachments.

Example storage layout:

```text
data/
  domainA/
    users/
    mail/
    attachments/
    logs/
  domainB/
    users/
    mail/
    attachments/
    logs/
```

Server A must never read or write Server B storage directly. Cross-domain delivery only happens through explicit relay endpoints.

## Multi-Thread / Worker Model

The concurrency idea from the README is important and should stay explicit:

### Accept / Request Layer

Request-facing handlers should do the short, security-critical work:

- verify session state
- verify request integrity fields
- validate payload schema and limits
- write transactional mail state
- enqueue slow follow-up work
- return quickly

### Worker Pools

Bounded worker pools handle slower tasks:

#### Delivery Workers

- pull jobs from the outgoing queue
- relay mail to peer domains
- retry transient failures
- prevent duplicate delivery where possible

#### Inbound Workers

- accept validated incoming relay jobs
- perform idempotent inbox insertion
- apply recall state changes safely

#### Attachment Workers

- hash files
- deduplicate physical blobs
- enforce type and size policy
- derive safe preview and attachment-analysis metadata

#### Smart Workers

- extract keywords
- generate quick reply suggestions
- classify suspicious content
- use local-only model backends when enabled

The key idea is that request threads should not do all slow work inline under concurrent load.

## Why Queue-Based Delivery Matters

One send action can involve:

- database writes
- attachment I/O
- remote relay latency
- retries
- phishing checks
- quick reply generation

If a request thread waits on all of that directly, the system becomes fragile under load.

So the intended flow is:

1. authenticate and validate the request
2. write mail state transactionally
3. enqueue delivery / analysis work
4. return a fast response such as `queued`
5. let workers complete the slower steps

This is the multithreaded / concurrent systems idea the README was emphasizing.

## Protocol Model

### Client -> Server

The shipped demo configuration uses loopback HTTP on `127.0.0.1`. The same server entry point also supports optional TLS certificates, so the protocol can run over HTTPS when configured.

After login, the system uses a session plus authenticated request metadata. The combined design target is:

- opaque session token or session id
- short TTL with rolling refresh
- optional refresh token if needed later
- request id
- sequence number
- timestamp
- nonce
- request MAC / HMAC over a canonical request body

This gives us layered protection:

- optional TLS protects the channel when enabled
- session state proves authenticated context
- per-request MAC protects the action and helps detect tampering or replay

### Server -> Server Relay

Cross-domain delivery is handled through dedicated relay endpoints, not through public user endpoints.

Relay requests should include:

- source domain
- message id
- timestamp
- nonce
- recipient list
- signed or otherwise authenticated relay metadata

This helps prevent open-relay behavior, forged delivery, duplicate delivery, and replayed relay requests.

## Security Model

### Authentication

- passwords are never stored in plaintext
- password hashing should use Argon2id
- failed login attempts are throttled and temporarily locked out
- authentication errors should avoid leaking whether an account exists

### Session Security

- session tokens are cryptographically random
- local demo traffic runs on loopback HTTP by default; deployments should enable HTTPS/TLS
- sessions expire and refresh on valid activity
- logout / revocation can be added as a follow-up if not in the first MVP cut

### Post-Login Request Integrity

The README requirements extend the PDF here: authenticated requests should support integrity and replay protection using:

- nonce
- timestamp
- sequence number
- HMAC over canonical request content

This is especially useful for security-sensitive actions like:

- send mail
- recall
- attachment access
- quick action execution

### Why TLS And HMAC Both Exist

This was a key point in the earlier README and should remain explicit:

- when TLS is enabled, TLS protects the transport channel
- session state proves authenticated context
- HMAC protects the individual authenticated action

In short:

> When enabled, TLS protects the channel, and HMAC protects the action.

### Abuse Prevention

- login brute-force throttling
- send rate limiting
- upload size and upload rate limits
- protection against duplicate submission where practical

### Attachments

Attachments are a major trust boundary in this project:

- all file types can be stored and relayed through normal mailbox flows
- upload size and upload rate limits reduce storage and availability abuse
- filenames do not control storage paths
- image preview, image AI review, and image transforms are only enabled for verified image bytes
- generic files can still be attached and downloaded, but they do not enter image-only analysis paths
- attachment access is protected through mailbox ownership or mailbox-link checks
- physical blobs are deduplicated by content hash
- compressed-copy replacement is limited to user-owned editable drafts so immutable mail history is preserved

### Phishing / Suspicious Mail

The initial implementation uses lightweight heuristics rather than a full ML pipeline:

- urgent credential/payment language
- multiple links
- mismatched reply identity where available
- suspicious wording patterns

Messages can be flagged and labeled without blocking all delivery.

### Recall Rules

Recall succeeds only when:

- the requester is the original sender
- the message exists
- the recall request is authenticated
- the message is still in a recallable state
- the receiver-side verification accepts the state transition

### Logging

Security-relevant events should be logged:

- register / login success and failure
- lockout
- send / relay / recall
- attachment upload and access
- quick action execution

Logs should avoid storing secrets or plaintext passwords.

## Layered Threat Model Summary

This system does not assume one generic "hacker". It models attackers against multiple trust boundaries:

- client <-> server
- server A <-> server B
- user <-> stored mailbox data
- authenticated request layer <-> background workers
- smart / LLM features <-> sensitive mailbox content

That means the design must protect confidentiality, integrity, availability, and correct authorization across several components, not only the login page.

### Attacker Classes By Trust Level

- `External anonymous internet attacker`: probes public endpoints, brute-forces login, abuses registration, uploads malformed input, or tries denial-of-service.
- `Authenticated malicious user`: has a valid mailbox account and abuses drafts, recall, groups, attachments, IDs, sequencing, or smart features from inside the application.
- `Insider / operator attacker`: has database, log, backup, or admin access and tries to read or tamper with stored mail, tokens, or relay configuration.
- `Compromised client attacker`: steals passwords, session material, drafts, or plaintext from the user device before or after transport protection.
- `Compromised peer server`: a malicious or compromised remote domain abuses inter-server delivery, relay trust, retry logic, or sender identity assumptions.

### Attacker Capabilities

- `Passive observer`: listens to client-server or server-server traffic and learns credentials, metadata, or message content if transport security fails.
- `Active network attacker`: modifies or replays traffic, tampers with bodies or headers, and tries to desynchronize state.
- `Credential attacker`: focuses on password guessing, stuffing, phishing, and session theft.
- `Content attacker`: sends malicious text to trick users or poison smart suggestions.
- `Attachment attacker`: uploads oversized files, fake images, parser bombs, or dangerous filenames.
- `Storage attacker`: targets databases, blobs, queues, backups, and logs.
- `Availability / race attacker`: floods send paths, workers, storage, or concurrent state transitions.
- `AI prompt attacker`: uses malicious email content to manipulate summarization, quick replies, or model context.

### Highest-Priority Attackers For This Repo

1. `Authenticated malicious user`
2. `Active network / replay attacker`
3. `Compromised peer server`
4. `Insider with storage or log access`
5. `Attachment attacker`
6. `AI prompt-injection attacker`
7. `Availability and race attacker`

These are the most realistic attackers for this feature set because the system includes drafts, groups, recall, attachments, inter-domain relay, queue-backed processing, and smart/LLM assistance.

## Threats Explicitly Considered

This repo explicitly designs for or tests:

- brute-force login, credential stuffing pressure, and session theft
- replay, reordering, and tampering of authenticated state-changing requests
- malicious authenticated-user abuse of groups, drafts, recall, attachments, and message identifiers
- insider or storage-operator access to mailbox data, logs, queued jobs, and secrets
- rogue or compromised peer-domain servers in cross-domain delivery
- phishing content, social engineering, and prompt injection against smart features
- malicious attachments, fake-image uploads, oversized files, and storage exhaustion
- availability pressure, queue exhaustion, concurrency bugs, and send/recall races
- privacy leaks through logs, context sharing, or overly broad smart-module prompts
- configuration and secret-management mistakes that weaken otherwise correct code

See `docs/threat_model.md` for the full attacker -> goal -> entry point -> concrete attack -> defense mapping.

## Mail Lifecycle

Mail should use explicit states, not just `sent=true/false`.

Example lifecycle:

```text
DRAFT
  -> QUEUED
  -> SENDING
  -> DELIVERED
  -> READ
  -> RECALL_REQUESTED
  -> RECALLED
  -> RECALL_FAILED
```

This matters because queueing, retries, relay, and recall are all multi-step operations.

## Example End-to-End Flow

### Alice Sends One Cross-Domain Mail To Bob

1. Alice logs in to domain A.
2. The server verifies the password hash and creates a secure session.
3. Alice submits a send request.
4. The request layer verifies:
   - session validity
   - timestamp / nonce / sequence requirements
   - HMAC / MAC integrity
   - rate limits
5. The server writes:
   - the sender sent-mail row
   - recipient metadata
   - queue / delivery state
6. The request returns quickly.
7. A delivery worker relays the message to domain B.
8. Domain B validates the relay request.
9. An inbound worker writes the message into Bob's inbox.
10. Bob refreshes inbox and sees the message.

This separation is central to the design because it keeps correctness and responsiveness under concurrent activity.

## Smart Features

The intelligent layer is advisory only.

It may:

- suggest replies
- extract keywords
- classify messages
- support fuzzy search
- flag suspicious messages

It may not:

- execute privileged actions automatically
- bypass user confirmation
- mutate account state without explicit server-side validation

This keeps smart functionality useful without turning it into a trusted authority.

## LLM Risk Must Be Explicit

The smart module is not just a feature. It is its own threat surface.

Incoming email is attacker-controlled input, so any summarization, smart review, drafting, quick reply, or image-analysis request must be treated as if it is processing hostile content. The main LLM-specific risks in this system are:

- prompt injection inside email subject, body, attachment OCR, or extracted metadata
- cross-message or cross-user context leakage
- accidental disclosure of secrets, tokens, or previous mailbox content through model prompts or outputs
- unsafe action suggestions that pressure the user into sending, recalling, or trusting the wrong content
- privacy leakage to model backends, logs, traces, or cached prompt history
- availability abuse through repeated expensive model calls
- model or dependency compromise in the smart-analysis pipeline

The current design response is:

- keep smart features advisory only
- never allow the model to execute privileged actions directly
- validate every state-changing action again on the server
- bound model context to the current task instead of giving the model broad mailbox access
- prefer local-only smart backends for sensitive analysis
- avoid storing raw secrets in prompts, logs, or database fields
- isolate image-only AI paths from generic file attachments

In short:

> The LLM is treated as an untrusted assistant, not as a security boundary.

## Repository Direction

The repo is being built around this Python layout:

```text
secure-email/
  README.md
  pyproject.toml
  common/
    config.py
    crypto.py
    schemas.py
    text_features.py
    utils.py
  server/
    main.py
    auth.py
    mailbox.py
    relay.py
    workers.py
    attachments.py
    rate_limit.py
    phishing.py
    logging.py
    storage.py
  client/
    cli.py
    api.py
    ui.py
    quick_reply.py
  web/
    index.html
    styles.css
    app.js
  configs/
    domainA.yaml
    domainB.yaml
  scripts/
    start_domain_a.ps1
    start_domain_b.ps1
    run_demo.ps1
    stress_test.py
  docs/
    protocol.md
    threat_model.md
    test_report.md
  tests/
    functional/
    security/
    concurrency/
    integration/
```

The final implementation can stay lightweight, but it should preserve these boundaries.

## Implementation Plan

### Phase 1: Skeleton, Auth, Storage

- start both domain servers
- create isolated storage roots
- implement register / login
- hash passwords with Argon2id
- issue secure sessions
- add login lockout / throttling

### Phase 2: Mail, Relay, Attachments

- compose and send mail
- store inbox / sent / drafts
- support cross-domain relay
- add image attachments with validation
- prove domain storage isolation

### Phase 3: Security Features

- request integrity checks with nonce / timestamp / sequence / HMAC
- send rate limiting
- recall verification
- safe quick action tokens
- audit logging

### Phase 4: Smart Features, Search, Docs, Demo

- keyword extraction and classification
- fuzzy search
- quick reply suggestions
- phishing heuristics
- protocol documentation
- threat model
- test report
- demo and reproducible scripts

## Testing Goals

### Functional

- register and login
- local send and receive
- cross-domain send and receive
- drafts
- sent mailbox
- attachments
- group send
- recall
- quick replies and quick actions

### Security

- wrong-password lockout
- send rate limit
- invalid attachment rejection
- unauthorized attachment download rejection
- forged recall rejection
- tampered action token rejection
- replay protection rejection
- suspicious mail flagging

### Concurrency

- many users send at once
- one user sends many mails at once
- simultaneous send and inbox polling
- attachment upload under concurrency
- send/recall race behavior

## Concurrency Demo Scenarios

The README should still explicitly cover the two stress cases you added:

### Scenario A: 100 Different Users Each Send 1 Mail

This stresses:

- request handler throughput
- transaction safety
- queue insertion
- worker scheduling
- remote inbox insertion

Expected outcome:

- no crashes
- no duplicate message IDs
- all mails either delivered or traceably queued / retried
- sent and inbox counts stay consistent

### Scenario B: 1 User Sends 100 Mails

This stresses:

- same-user rate limiting
- sequence handling
- duplicate / replay rejection
- queue throughput
- sent-folder consistency

Expected outcome:

- no invalid duplicate processing
- rate-limit behavior is enforced
- request integrity checks still hold
- the system remains responsive

## Demo Flow

1. Start server A and server B.
2. Open `http://127.0.0.1:8443/` and `http://127.0.0.1:9443/` in the browser.
3. Register `alice@a.test` and `bob@b.test`.
4. Login as Alice and Bob in their respective domain windows.
5. Upload an image attachment.
6. Send a cross-domain message to Bob.
7. Open Bob's inbox in the browser.
8. Show suspicious mail detection or smart suggestions.
9. Execute a safe quick action.
10. Trigger recall on an unread message.
11. Run brute-force and rate-limit tests.

## Demo And Stress Scripts

The intended demo / test flow should still include:

- normal two-domain demo startup
- cross-domain send demo
- brute-force demo
- rate-limit demo
- suspicious mail demo
- many-users concurrency demo
- one-user burst-send demo

Example script direction:

```text
scripts/
  start_domain_a.ps1
  start_domain_b.ps1
  run_demo.ps1
  stress_test.py --mode many_users --users 100 --mails 1
  stress_test.py --mode one_user --users 1 --mails 100
```

A saved local run of these two assignment-sized stress scenarios is included in `docs/stress_test_results.md`.

## References Behind The Design

The design choices come from the PDF research plus the README direction and are informed by:

- RFC 5321 / RFC 5322 / MIME concepts
- TLS basics
- Argon2id password storage guidance
- OWASP guidance for session management, authentication, uploads, input validation, logging, and XSS
- NIST-aligned thinking for throttling and verifier protection

## Status

This is a security-conscious educational / interview-focused prototype.

Its value is in showing:

- clear threat modeling
- strong isolation boundaries
- careful handling of authenticated actions
- concurrency-aware design
- testability and explainability

The current codebase now includes queued background delivery workers, sender-visible delivery state, and worker-backed inbound processing so the README architecture is reflected in the running MVP as well.

It does not claim to replace mature production mail infrastructure.
