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
- prompt-injection language flagging
- fake attachment rejection
- unauthorized attachment access rejection
- forged recall rejection
- relay MAC rejection
- local-only model policy blocking remote Ollama endpoints

### Concurrency

- many users send concurrently
- one user sends many mails
- simultaneous send plus inbox polling
- attachment upload concurrency

## Execution Notes

Local verification completed in a repo-local virtual environment on 2026-04-14.

Command used:

```powershell
.\.venv\Scripts\python -m pytest -q
```

Result:

```text
45 passed in 29.01s
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
- prompt/script-injection language flagging
- attachment deduplication behavior
- attachment analysis metadata generation
- attachment transform route behavior
- Florence-2 attachment-review integration path
- encrypted-at-rest database field storage
- local Ollama smart-module enrichment path
- local Hugging Face smart-module enrichment path
- local-only policy fallback when a non-local model endpoint is configured
- ECC public-key publication and cross-domain key resolution
- ECC end-to-end encrypted cross-domain text mail with local decryption
- concurrent multi-client send and receive acceptance
- recall on unread cross-domain mail
- tampered quick-action token rejection
- send rate limiting
- common-English stopword filtering in keyword extraction

Additional reproducible assignment-sized stress scenarios were executed with:

```powershell
.\.venv\Scripts\python.exe scripts\generate_stress_results.py
```

Saved results:

- `100 different users each send 1 mail`: `100/100` accepted and `100/100` delivered
- `1 user attempts 100 mails`: `30` accepted, `70` rate-limited, service remained healthy

See [docs/stress_test_results.md](./stress_test_results.md) and [docs/stress_test_results.json](./stress_test_results.json) for the full recorded output.

Known gaps still worth extending:

- TLS certificate handling is demo-oriented and not yet covered by automated tests
- larger-scale performance benchmarking is still better handled by the stress script than by unit tests
