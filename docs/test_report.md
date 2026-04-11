# Test Report

## Intended Coverage

### Functional

- register / login
- local send
- cross-domain send
- inbox / sent / drafts
- attachment upload/download
- recall
- group send
- quick reply display
- quick action execution

### Security

- brute-force lockout
- rate limiting
- request MAC rejection on tamper
- replay rejection
- fake attachment rejection
- unauthorized attachment access rejection
- forged recall rejection
- relay MAC rejection

### Concurrency

- many users send concurrently
- one user sends many mails
- simultaneous send plus inbox polling
- attachment upload concurrency

## Execution Notes

Local verification completed in a repo-local virtual environment on 2026-04-11.

Command used:

```powershell
.\.venv\Scripts\python -m pytest -q
```

Result:

```text
11 passed in 9.93s
```

Covered by the current automated suite:

- login lockout after repeated bad passwords
- register confirmation mismatch rejection
- browser web root/static asset serving
- signed authenticated requests
- replay rejection on duplicate signed request
- invalid attachment rejection
- cross-domain queued send with worker-backed relay delivery
- CC delivery across local and remote recipients
- suspicious-mail/phishing flagging
- attachment deduplication behavior
- concurrent multi-client send and receive acceptance
- recall on unread cross-domain mail
- tampered quick-action token rejection
- send rate limiting

Known gaps still worth extending:

- TLS certificate handling is demo-oriented and not yet covered by automated tests
- larger-scale performance benchmarking is still better handled by the stress script than by unit tests
