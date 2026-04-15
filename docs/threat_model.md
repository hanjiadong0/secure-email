# Threat Model

## 1. Modeling Approach

This email system is not modeled against one generic "hacker". It is modeled against several trust boundaries:

- client <-> domain server
- domain A <-> domain B
- authenticated request layer <-> background workers
- user <-> stored mailbox and attachment data
- smart / LLM features <-> sensitive mailbox content

That matters because the system must protect more than login:

- confidentiality of credentials, mail, attachments, and secrets
- integrity of authenticated requests, relay traffic, recall operations, and mailbox state
- availability of login, send, upload, search, queue, and worker paths
- authorization correctness across inbox, sent, drafts, groups, attachments, and quick actions
- accountability through audit logs and replay detection

## 2. Assets

Primary assets:

- user credentials and password hashes
- session tokens, session keys, nonces, and sequence state
- mailbox contents: inbox, sent, drafts, groups, and quick-action state
- attachment blobs and attachment-analysis metadata
- relay trust configuration and peer-domain mappings
- audit logs and security evidence
- queued background-delivery payloads
- smart-module prompts, context, and outputs
- ECC public keys, client-held private keys, and E2E envelopes

## 3. Trust Boundaries

- `client <-> domain server`: browser or CLI requests cross from user-controlled input into privileged server logic
- `domain A <-> domain B`: relay traffic crosses from one security domain into another
- `request layer <-> workers`: authenticated user actions are converted into queued background jobs
- `mailbox metadata <-> attachment storage`: message state and stored files are related but must be authorized separately
- `smart features <-> mailbox data`: attacker-controlled mail text reaches summarization, classification, and drafting logic
- `runtime <-> storage/logs/backups`: sensitive values may exist at rest and must not be treated like public metadata

## 4. Security Objectives

- `Confidentiality`: prevent disclosure of passwords, session state, mail bodies, attachments, secrets, and smart-context data
- `Integrity`: prevent tampering with authenticated requests, relay operations, recall state, attachment links, and quick actions
- `Availability`: keep login, send, inbox refresh, queue workers, and storage usable under pressure
- `Authorization`: ensure users, peer servers, and actions can access only the resources they own or are allowed to operate on
- `Accountability`: log security-relevant events without leaking secrets

## 5. Attacker Taxonomy

### By Trust Level

- `External anonymous internet attacker`: has no account and attacks public endpoints
- `Authenticated malicious user`: has a valid account and abuses application-level features
- `Insider / operator attacker`: has administrative, database, log, backup, or debug access
- `Compromised client attacker`: controls the user device or browser session
- `Compromised peer server`: controls or compromises the remote mail domain in cross-domain delivery

### By Capability

- `Passive observer`: sniffs traffic and metadata
- `Active network attacker`: modifies, replays, blocks, or reorders traffic
- `Credential attacker`: brute-forces, stuffs, phishes, or steals tokens
- `Content attacker`: sends malicious email bodies to fool users or poison smart features
- `Attachment attacker`: abuses upload, parsing, preview, or transform paths
- `Storage attacker`: targets databases, blobs, logs, backups, and secrets
- `Availability attacker`: floods endpoints, queues, disk, CPU, or thread pools
- `Concurrency attacker`: exploits races, duplicate submissions, stale reads, or inconsistent state
- `Cryptographic attacker`: targets keys, randomness, validation, rotation, or crypto placement
- `AI prompt attacker`: injects instructions or context-poisoning content into model inputs

### By Security Objective

- `Confidentiality attacker`: wants to read protected data
- `Integrity attacker`: wants to alter or forge state
- `Availability attacker`: wants the system to fail or degrade
- `Authorization attacker`: wants access to another user's resources or privileges

## 6. Detailed Threat Tables

### 6.1 External, Network, Credential, and Peer-Server Attackers

| Attacker | Goal | Entry Points | Concrete Attack | Current Defenses |
| --- | --- | --- | --- | --- |
| External anonymous internet attacker | Break in, enumerate accounts, abuse the system, or consume resources | Register, login, send, upload, relay, and smart endpoints | Port probing, malformed JSON, username enumeration, brute-force login, spam-style API abuse | Schema validation, Argon2id, login lockout, rate limits, authenticated relay endpoints, audit logging |
| Passive network eavesdropper | Read credentials, mail, attachments, or metadata | Client-server traffic and server-server relay traffic | Sniff passwords, tokens, message bodies, attachments, or domain metadata | HTTPS/TLS, optional ECC E2E mail for text messages, relay authentication, encrypted-at-rest storage for stolen DB copies |
| Active network attacker / MITM | Modify or replay privileged requests and relay traffic | Authenticated client requests and relay requests | Header tampering, body substitution, replay, reordering, fake relay submission, packet injection | Request ID, session ID, sequence number, timestamp, nonce, body MAC, relay HMAC, recipient-domain ownership checks |
| Credential attacker | Take over a mailbox and use it as an identity pivot | Login flow, phishing content, stolen browser sessions | Brute force, password spraying, credential stuffing, phishing, token theft | Argon2id password hashes, lockout, throttling, session expiry, suspicious-mail labeling, audit logs |
| Rogue or compromised peer server | Abuse cross-domain trust and delivery | Relay endpoint, peer-domain map, retry logic | Forge sender identity, flood a remote domain, send malformed relay payloads, abuse retry or recall assumptions | Explicit peer-domain map, relay authentication secret, domain checks, per-domain storage isolation, logging of relay decisions |

### 6.2 Authenticated, Insider, Storage, Availability, and Crypto Attackers

| Attacker | Goal | Entry Points | Concrete Attack | Current Defenses |
| --- | --- | --- | --- | --- |
| Authenticated malicious user | Abuse features from inside the app | Send, drafts, groups, recall, attachments, search, smart compose | Group spam, oversized or repeated sends, IDOR attempts, tampered message IDs, replayed old requests, recall abuse | Owner-based queries, attachment-link checks, send rate limits, signed request freshness, recall validation, action-token binding |
| Insider / administrator / operator | Read or alter sensitive state silently | DB files, logs, backups, configs, runtime access | Read stored mail, steal password hashes, dump tokens, alter relay rules, bypass limits, inspect logs | Field-level encryption at rest, encrypted secret storage, encrypted queued payloads, audit logs, domain data separation |
| Compromised client / endpoint attacker | Impersonate the user or steal plaintext | Browser session, local machine, clipboard, keystrokes | Keylogging, token theft, reading drafts before encryption, stealing attachments, copying mailbox views | Server-side controls reduce replay and token abuse, but endpoint compromise remains high risk; E2E private keys stay on client for text mail |
| Database / storage attacker | Extract mailbox data or cross domains through storage | SQLite databases, attachment store, job queue, backups | Read mail tables, dump attachment blobs, inspect queued jobs, attempt cross-domain reads | Per-domain storage roots, field encryption, encrypted job payloads, attachment-link authorization, no direct cross-domain filesystem delivery |
| Availability attacker | Make the service slow or unavailable | Login, send, upload, search, smart endpoints, queue, disk | Mail flood, large-attachment flood, repeated smart calls, queue poisoning, disk fill-up | Login/send/upload rate limits, bounded worker pools, queue-backed delivery, size limits, separate domains, tests for concurrent send paths |
| Concurrency / race attacker | Trigger inconsistent distributed state | Send, recall, delivery workers, attachment replacement, session sequencing | Double-send races, recall-after-delivery conflicts, duplicate inbox insertion, stale attachment references, sequence races | Sequence tracking, duplicate detection, idempotent handling where possible, explicit mail lifecycle states, concurrency tests |
| Cryptographic / key attacker | Defeat trust by stealing or misusing keys | Session secrets, relay secret, TLS keys, E2E material, randomness | Secret theft, weak randomness, bad rotation, fallback abuse, storing keys beside ciphertext | Random session tokens, body MAC, encrypted secret storage, client-held ECC private keys for E2E text mail, no privileged action based only on model output |
| Supply-chain / dependency attacker | Compromise the system through libraries or tools | HTTP framework, crypto libs, image handling, model runtimes | Vulnerable framework exploit, unsafe image parser path, compromised dependency update | Keep dependency surface relatively small, prefer local smart backends, validate input at app layer, run tests on security-sensitive flows |

### 6.3 Content, Attachment, and AI Attackers

| Attacker | Goal | Entry Points | Concrete Attack | Current Defenses |
| --- | --- | --- | --- | --- |
| Mail content attacker / phishing attacker | Trick the user or manipulate downstream logic | Incoming email subject, body, reply-to, links, quick replies | Credential phishing, urgency pressure, malicious links, social-engineering admin requests | Heuristic phishing scoring, suspicious classification, inbox warning labels, no autonomous privileged actions from mail content |
| Malicious attachment attacker | Exploit file handling or exhaust storage | Attachment upload, preview, transform, compression, download | Oversized uploads, fake images, parser bombs, dangerous filenames, disguised executables | Upload size limits, filename-independent storage, byte-level image validation, image-only transforms, authorization checks on access |
| AI / LLM-specific attacker | Poison smart features or leak sensitive context | Smart review, compose assist, quick replies, summarization | Prompt injection in email text, exfiltration attempts, forced expensive prompts, context bleed, unsafe model suggestions | Advisory-only smart features, local-only model policy by default, bounded context, prompt handling of untrusted content, server-side validation on every state-changing action |

### 6.4 Explicit LLM Risk Breakdown

The LLM risk is important enough to call out separately instead of hiding it inside a generic "smart feature" bullet. In this system, the model processes attacker-controlled content from incoming mail, so the LLM path must be treated as a hostile-input boundary.

| LLM Risk | What It Looks Like In This Project | Why It Matters | Current Response |
| --- | --- | --- | --- |
| Prompt injection from incoming mail | An attacker sends text such as "ignore previous instructions", "reveal earlier mail", or manipulative reply content | The model may produce unsafe summaries, misleading quick replies, or privacy-breaking outputs | Treat mail as untrusted input, keep prompts task-bounded, avoid giving the model raw mailbox history by default |
| Cross-user or cross-message context bleed | A compose or summary call accidentally includes the wrong prior draft, another user's text, or unrelated mailbox context | This becomes a confidentiality failure even if the HTTP/API layer is correct | Scope model context to the current user and current task, do not reuse global model conversation state across accounts |
| Secret leakage through prompts, logs, or traces | Tokens, passwords, relay secrets, or hidden metadata appear in prompts, debug logs, or persisted smart-job payloads | A model or log compromise can expose far more than one email body | Encrypt secrets at rest, avoid placing secrets in prompts, keep logging minimal, and separate security secrets from smart-module context |
| Unsafe automation pressure | The model recommends sending money, trusting a link, or taking a risky quick action | The model can amplify social engineering even without direct tool execution | Keep the model advisory only, require explicit user action, and revalidate every state-changing action server-side |
| Hallucinated or overconfident analysis | The smart review falsely marks phishing as safe, or invents details in summaries or draft replies | Users may trust confident but wrong guidance | Present model output as assistance rather than truth, keep heuristic checks alongside the model, and show evidence/reasons where possible |
| Expensive-call abuse / smart-path DoS | An attacker sends many prompts, large messages, or repeated smart-compose requests to exhaust local model capacity | Availability suffers even if core mail functions are correct | Rate-limit smart endpoints, bound prompt size, keep delivery separate from model execution, and use queue-backed processing where needed |
| Model-backend privacy leakage | A remote provider or compromised local model stack receives sensitive mail content | Confidentiality is weakened outside the main mailbox storage path | Prefer local Ollama-style backends for sensitive tasks, minimize prompt data, and keep backend choice explicit in documentation and status views |
| Tool or action escalation through the model | The model is ever trusted to recall, delete, or execute a quick action without a normal auth path | This would turn LLM mistakes into integrity failures | Do not grant the LLM direct authority; all privileged actions must go through authenticated server endpoints with normal checks |
| Attachment-analysis prompt contamination | OCR or image captions from uploaded attachments feed malicious text into later smart decisions | A non-text attachment can still become an injection carrier | Restrict image-AI to verified images, keep attachment analysis isolated from action execution, and avoid trusting captions as commands |

## 7. Highest-Priority Attackers For This Project

The most important attackers for this specific feature set are:

1. `Authenticated malicious user`
2. `Active network / replay attacker`
3. `Compromised peer server`
4. `Insider with storage or log access`
5. `Attachment attacker`
6. `AI prompt-injection attacker`
7. `Availability / race attacker`

These are prioritized because the system includes:

- authenticated state-changing APIs
- drafts, recall, groups, and quick actions
- cross-domain server-to-server relay
- queued background delivery
- attachment storage and image-only AI paths
- smart / LLM-assisted features

## 8. Mapping To Current Defenses

Current implementation choices that directly answer this threat model:

- `Passwords`: Argon2id hashing and login lockout
- `Authenticated request integrity`: request ID, session ID, sequence number, timestamp, nonce, and body MAC
- `Relay integrity`: authenticated peer-domain relay with domain ownership checks
- `Authorization`: owner-based mailbox and attachment access, sender-bound recall checks, recipient-bound one-time action tokens
- `Storage`: per-domain storage roots, encrypted-at-rest sensitive fields, encrypted secret storage, encrypted queued payloads
- `Attachments`: size limits, filename-independent storage, byte-level validation for image-only analysis and transforms
- `Smart features`: advisory only, bounded context, local-only smart policy where configured, no autonomous privileged actions, hostile-input treatment for incoming mail text
- `Availability`: queue-backed delivery, bounded workers, rate limits, concurrency tests
- `E2E confidentiality`: client-held ECC private keys for optional text-only end-to-end encrypted mail

## 9. Residual Risk And Next Improvements

Residual risk remains in areas that are realistic for an educational prototype:

- a compromised client device can still read plaintext before or after transport protection
- a trusted peer server can still deliver malicious but correctly authenticated content
- current protections do not replace enterprise DDoS infrastructure
- attachment controls reduce parser and path risk, but they are not a full malware-scanning pipeline
- insider risk is reduced by encryption and logging, but runtime administrators still have strong power
- smart features are bounded and advisory, but prompt injection and model mistakes cannot be reduced to zero
- any future move from local-only models toward remote API models would increase privacy and data-governance risk
- stronger LLM hardening would still benefit from prompt-isolation tests, cross-user-context regression tests, and explicit smart-module audit events
- E2E mode is currently text-only, so attachments remain outside end-to-end protection
- key rotation, certificate lifecycle tooling, and stronger operational hardening are still follow-up work

## 10. Short Interview Summary

One strong way to explain the model is:

> We do not assume only one hacker. We separate attackers by trust boundary: unauthenticated outsider, authenticated malicious user, insider, compromised client, and malicious peer server. Then we map each one to confidentiality, integrity, availability, and authorization risks across login, mailbox storage, attachments, inter-server relay, and smart/LLM features.

That is a stronger engineering story than saying the system is secure only because it uses encryption.
