# HexStrike + ScanX — Finalization Phases 8–12

## Phase 8 — Adaptive orchestration
Nmap establishes the initial service inventory. The engine then derives web endpoints and domain applicability instead of blindly running every tool against every target.

## Phase 9 — Persistent evidence and history
Every scan and assessment is stored as JSON under `data/results/`. The CLI can inspect historical records without an API or dashboard.

## Phase 10 — Intelligence and risk
Findings are normalized, correlated across scanners, deduplicated, assigned confidence, and converted into asset inventory, attack-surface metrics, risk score, and remediation priorities.

## Phase 11 — AI/MCP integration
The project exposes MCP tools and supports optional local Ollama enrichment. Ollama is never required for the core scanner pipeline; deterministic analysis remains the fallback.

## Phase 12 — Operations and delivery
Adds doctor/config validation, scanner health, versioning, optional JSON/HTML export, tests, packaging, and documentation. Normal `assess` remains terminal-first and does not generate a report automatically.
