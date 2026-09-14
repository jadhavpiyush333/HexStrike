# Changelog

## 1.0.0 — Final hardened release

- Completed CLI-first automated assessment workflow.
- Added adaptive service-aware orchestration.
- Added normalized findings, correlation, confidence and risk scoring.
- Added asset inventory and attack-surface analysis.
- Added persistent assessment history and JSON/HTML export.
- Added optional local Ollama/Gemma enrichment.
- Added MCP scanner/status/result/analysis tools.
- Added `doctor`, `config validate`, and deterministic `self-test` commands.
- Hardened target parsing, IPv6 handling, command execution and configuration validation.
- Added configurable ScanX command arguments through `SCANX_BIN` and `SCANX_ARGS`.
- Added deterministic hardening tests; release test suite passes.

### Environment dependency note

External scanner executables are intentionally not bundled. Their availability is checked by `hexstrike doctor`. ScanX command syntax varies by distribution, so its invocation is configurable rather than fabricated.
