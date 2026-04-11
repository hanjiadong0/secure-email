# Smart Secure Email System

A local, security-aware email prototype with two isolated domains, cross-domain delivery, image attachments, recall, quick actions, quick replies, local-Ollama and optional local-Hugging-Face smart features, attachment preview and analysis, encrypted-at-rest mailbox storage, and reproducible tests.

This project combines the PDF deep-research plan with the current README direction:

- the PDF defines the MVP scope, security baseline, interview-ready explanations, and four-day delivery plan
- the README adds stronger concurrency, queueing, replay protection, and post-login request integrity requirements

The result is a local secure mail system that is meant to feel like a small real distributed system, not just a mailbox CRUD app.

## Scope

This is not a production SMTP/IMAP server and it does not use a full mailserver like Postfix or Dovecot as the core implementation.

Instead, the project builds its own small mail protocol over HTTPS/JSON while staying conceptually aligned with:

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
- attachment preview, risk analysis, and safe local transforms
- mail recall with verification rules
- quick actions with safe server-side validation
- quick replies and lightweight smart suggestions
- local LLM smart analysis through Ollama or optional local Hugging Face models
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

Transport is HTTPS.

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

- TLS protects the channel
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
- all session traffic stays on HTTPS
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

- TLS protects the transport channel
- session state proves authenticated context
- HMAC protects the individual authenticated action

In short:

> TLS protects the channel, HMAC protects the action.

### Abuse Prevention

- login brute-force throttling
- send rate limiting
- upload size and upload rate limits
- protection against duplicate submission where practical

### Attachments

Attachments are image-only for the MVP:

- allowlist: `.png`, `.jpg`, `.jpeg`
- validate magic bytes, not just filename
- maximum size limit
- safe generated storage names
- access control through mailbox ownership
- physical deduplication by content hash

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

## Threats Explicitly Considered

The earlier README was intentionally fine-tuned around security review thinking. The merged version should keep that depth.

This project explicitly considers:

- brute-force login
- replay attacks
- duplicate request retry
- forged recall
- tampered authenticated requests
- spam / mass-send abuse
- phishing and suspicious mail
- attachment access bypass
- open-relay abuse
- storage isolation failure between domains
- concurrency-induced inconsistent states
- prompt injection against smart features
- privacy leaks through logs, context sharing, or attachments
- secret/configuration mistakes

## Expanded Security Concerns

### Authentication And Session Risks

Relevant concerns include:

- weak password storage
- plaintext password logging
- predictable or long-lived session secrets
- session theft or reuse
- missing expiration or revocation behavior
- user enumeration through different auth errors

Expected mitigations:

- Argon2id password hashing
- HTTPS-only transport
- short-lived session state with rotation/refresh policy
- generic auth failures where useful
- rate limiting and lockout

### Authorization And Resource Ownership

Authentication alone is not enough. We also need strict ownership checks for:

- inbox access
- sent/draft access
- attachment download
- recall requests
- quick actions
- group operations

This is where insecure direct object reference risks show up, especially with predictable message IDs or attachment IDs.

### Transport And Relay Risks

Client-to-server and server-to-server traffic are both security-sensitive.

Relevant concerns include:

- credential theft in transit
- man-in-the-middle attacks
- forged relay requests
- replayed relay delivery
- routing mail to the wrong endpoint
- open-relay behavior
- accepting mail for domains a server does not own

Expected mitigations:

- HTTPS/TLS
- authenticated relay endpoints
- timestamp / nonce / replay controls
- strict recipient-domain ownership checks
- logging of relay decisions

### Storage Isolation Risks

Storage isolation is a security property, not just an implementation detail.

Relevant concerns include:

- one domain reading another domain's mailbox state
- shared attachment namespaces without access control
- mixed logs or exports
- cross-domain leakage through admin tooling or debug helpers

Expected mitigations:

- per-domain storage roots
- domain-scoped queries
- separate attachment namespaces or identifiers
- careful administrative boundaries

### Attachment Handling Risks

Attachments remain a major attack surface.

Relevant concerns include:

- arbitrary upload
- oversized file DoS
- path traversal through filenames
- content-type spoofing
- unauthorized download
- dangerous response handling

Expected mitigations:

- size limits
- filename independence from user input
- magic-byte validation
- ownership checks on download
- safe content-disposition and content-type handling

### Input Validation And Business Logic Risks

Not all vulnerabilities are cryptographic. Many are logic errors.

Relevant concerns include:

- malformed email identities
- invalid recipient lists
- oversized body/subject fields
- forged or stale recall requests
- duplicate delivery during retries
- partial cross-domain failures
- inconsistent recall semantics across domains

Expected mitigations:

- strict schema validation
- explicit state transitions
- idempotent processing where possible
- careful negative tests for edge cases

### Logging, Privacy, And Data Minimization

Security logging helps with defense, but logs can become a leak.

Relevant concerns include:

- logging secrets or passwords
- logging excessive message content
- leaking tokens into logs
- unbounded log growth
- retention of recalled or sensitive content longer than intended

Expected mitigations:

- structured audit logs
- redaction / minimization
- bounded retention
- logging security-relevant events without dumping secrets

### Smart Feature And Prompt Injection Risks

The previous README was right to call this out in detail: email content is attacker-controlled text.

Relevant concerns include:

- prompt injection from malicious messages
- over-sharing mailbox history to smart components
- treating model output as authoritative
- wrong-thread quick reply context
- privacy loss when sending user content to external AI providers

Expected mitigations:

- advisory-only smart features
- minimal-context design
- no autonomous privileged actions
- output filtering and validation
- keeping smart systems outside privileged execution paths

### Replay, Duplication, And Concurrency Risks

Distributed delivery and concurrent clients create their own security problems.

Relevant concerns include:

- reusing an old signed request
- accepting duplicate relay jobs
- sequence confusion in one session
- send/recall races
- inconsistent sent/inbox state under concurrent load

Expected mitigations:

- request IDs
- nonces
- timestamps
- sequence tracking
- duplicate detection
- idempotent receiver handling

### Configuration And Secret Management Risks

Security often fails at the configuration layer.

Relevant concerns include:

- hard-coded secrets
- committed credentials
- insecure defaults
- wrong peer-domain mappings
- debug mode or weak TLS settings in the wrong environment

Expected mitigations:

- environment-based secret management
- config validation
- safe defaults
- explicit local-dev versus secure-demo documentation

### Testing And Verification Risks

A system is not meaningfully secure if only happy paths are tested.

Security testing should cover:

- forged relay requests
- tampered request MACs
- replayed requests
- unauthorized attachment access
- duplicate delivery
- malformed smart-feature inputs
- isolation failures between domains

The README and the future `docs/threat_model.md` should stay aligned on these points.

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
