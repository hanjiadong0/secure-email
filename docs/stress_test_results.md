# Stress Test Results

Generated at: `2026-04-14T13:49:07+00:00`

This document records an actual local run of the assignment-sized stress scenarios using two temporary isolated domains created in-process through the same FastAPI application and relay code paths as the main project.

Command:

```powershell
.\.venv\Scripts\python.exe scripts\generate_stress_results.py
```

## Scenario A

`100 different users each send 1 mail`

- Attempted sends: `100`
- Accepted sends: `100`
- Rejected sends: `0`
- Receiver inbox new messages: `100`
- Peak polled inbox size during concurrent receive: `20`
- Duration: `11.2 s`
- Result: `pass`

Interpretation:
The multi-client path completed without a server crash, and the receiver mailbox accumulated the expected new messages while inbox polling happened at the same time.

## Scenario B

`1 user attempts 100 mails`

- Attempted sends: `100`
- Accepted sends: `30`
- Rate-limited responses: `70`
- Other failures: `0`
- Receiver inbox new messages: `30`
- Service still healthy after burst: `True`
- Duration: `4.97 s`
- Result: `pass`

Interpretation:
This scenario is expected to trigger anti-abuse protection. The important success condition is that the service remains healthy and that rate limiting activates instead of allowing unlimited same-user flooding.

## Raw JSON

See [stress_test_results.json](./stress_test_results.json) for the machine-readable version of this run.