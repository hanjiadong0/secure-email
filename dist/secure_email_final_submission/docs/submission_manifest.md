# Submission Manifest

This repository is packaged for final submission as a clean hand-in bundle with the required code, configuration, documentation, test artifacts, and presentation materials.

## Main Structure

- `client/`
  Client-side logic and CLI/TUI support.
- `common/`
  Shared schemas, crypto helpers, config loading, and utility code.
- `server/`
  Authentication, mailbox, relay, attachment, smart-module, security-lab, and worker logic.
- `web/`
  Browser mailbox UI and independent security-lab website.
- `configs/`
  Dual-domain example configuration.
- `scripts/`
  Startup, demo, stress-test, screenshot, security-lab, and packaging scripts.
- `tests/`
  Functional, security, attachment, smart-module, and evidence-generation tests.
- `docs/`
  Protocol, threat model, test report, presentation, lecture notes, PoC notes, E2E design, audit/alerting notes, P2P exploration, screenshots, and security-lab evidence.

## Assignment Mapping

- `server/client 源码`
  `server/`, `client/`, `common/`, `web/`
- `启动脚本与配置（双域名示例）`
  `scripts/start_domain_a.ps1`, `scripts/start_domain_b.ps1`, `scripts/run_demo.ps1`, `configs/`
- `协议说明（消息格式、鉴权流程）`
  `docs/protocol.md`
- `测试脚本与结果`
  `tests/`, `scripts/stress_test.py`, `scripts/generate_stress_results.py`, `docs/test_report.md`, `docs/stress_test_results.md`, `docs/test_frontend_screenshots/`, `docs/security_lab_evidence/`
- `威胁模型与防护说明`
  `docs/threat_model.md`, `README.md`, `docs/alerting_and_audit.md`, `docs/end_to_end_encryption_design.md`
- `展示材料`
  `docs/secure_email_presentation.pdf`, `docs/secure_email_code_lecture.pdf`

## Packaging Notes

- The final zip excludes runtime caches, virtual environments, temporary test data, and duplicate build artifacts.
- Security-lab evidence keeps the final JSON and PNG outputs, but drops temporary simulated domain folders.
- LaTeX auxiliary files are omitted from the packaged submission.
