# Audit Logging and Anomaly Alerting

## Audit Logging

The project already records structured audit events in each domain's local log directory.

Current implementation:
- Security audit log file: `data/<domain>/logs/security.jsonl`
- Writer: [server/storage.py](../server/storage.py)
- Wrapper: [server/logging.py](../server/logging.py)

Typical audit events include:
- register
- login success and failure
- mail sent
- relay incoming
- recall requested
- attachment upload
- quick action execution
- worker/job completion and failure

## Anomaly Alerting

Basic anomaly alerting is now implemented as a second structured log stream.

Current implementation:
- Alert log file: `data/<domain>/logs/alerts.jsonl`
- Writer: [server/storage.py](../server/storage.py)
- Alert routing: [server/logging.py](../server/logging.py)

Current alert-producing events include:
- `login_lockout`
- `login_rate_limited`
- `send_rate_limited`
- `upload_rate_limited`
- `request_replay_rejected`
- `request_mac_failed`
- `relay_replay_rejected`
- `relay_mac_failed`
- `job_failed`
- `suspicious_mail_detected`

## Why This Helps

This is useful because the audit log is a complete event history, while the alert log highlights events that should trigger operator attention.

Examples:
- repeated login abuse
- repeated replay attempts
- suspicious mail reaching a user inbox
- worker failures in the delivery pipeline

## Current Scope

This is still a lightweight local anomaly-alerting mechanism, not a production SIEM integration.

Future extensions:
- threshold-based aggregation
- email or desktop notifications
- dashboard view of active alerts
- dead-letter queue monitoring
- retention policy and alert suppression
