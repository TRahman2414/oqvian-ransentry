# OQVIAN RANSENTRY — Master Plan

## Goal

Build a polished, runnable local showcase of early warning from file activity plus backup readiness context. The product should show a trustworthy investigation workflow, not claim to detect or stop all ransomware.

## Customer problem and demo audience

The demo is designed for a general business audience: small and midsize businesses, service providers, and teams responsible for shared business files. It shows how file-integrity changes, bursts of modifications/renames/deletions, and a backup warning can be presented together with evidence. All displayed organization, files, events, people, and backup service state are fictional.

## Product boundaries

**Working locally:** filesystem observation of the fixed disposable demo root; event normalization; SHA-256 baseline and verification; deterministic R001–R007 rules; incident correlation/deduplication; analyst notes/status; audit events; repeatable scenarios; safe restore/reset; dashboard fed by persisted backend state.

**Clearly simulated:** backup failure/disablement, endpoint isolation, account restriction, emergency containment, approval, and production notifications.

**Out of scope:** production endpoint agents, remote/multi-tenant monitoring, real backup connectors, antivirus/EDR claims, ransomware payloads or encryption, restore of customer data, destructive cleanup, cloud services, LLM decisions, and automated actions against real systems.

## System workflow

1. Seed a fictional Meridian workspace inside the application-owned demo root.
2. Capture a baseline of eligible small regular files with relative path, size, modification time, and streaming SHA-256.
3. Start one managed Watchdog observer; callbacks are queued and normalized/coalesced before database writes.
4. Evaluate baseline changes and deterministic operation windows, preserving event IDs and rule-hit evidence.
5. Generate separately labeled fictional backup events when a presenter selects a scenario.
6. Correlate eligible file-operation hits and backup warnings for the same demo root within 60 seconds.
7. Create or update a deduplicated local incident with an explanation generated from stored rule results.
8. Present the timeline, changed paths, rule thresholds, score components, and simulated backup state.
9. Let an analyst add notes and move the incident through New, Acknowledged, Investigating, Escalated, Resolved, and Reopened.
10. Show response previews as simulated actions requiring explicit human confirmation; do not issue host commands.
11. Restore only known demo fixtures, rebuild the baseline, and verify a clean state.

## Detection defaults

All values are configurable demo heuristics, not universal ransomware thresholds or probabilities.

| Rule | Condition | Initial contribution |
|---|---|---:|
| R001 | 20 distinct files modified in 10 seconds | +20 |
| R002 | 15 distinct files renamed/moved in 10 seconds | +25 |
| R003 | 10 distinct files deleted in 10 seconds | +25 |
| R004 | One or more baseline differences | Informational by default |
| R005 | Simulated backup disabled, failed, or unavailable | +20; unexpected disablement +30 |
| R006 | R001/R002/R003 and R005 for same root within 60 seconds | +35 correlation context |
| R007 | Fictional approved maintenance window | documented priority adjustment; evidence remains visible |

Scores are clamped to 0–100 and do not double-count one rule hit. Informational 0–29; Low 30–49; Medium 50–69; High 70–84; Critical 85–100. Critical should require correlated evidence, not one ordinary file edit.

## Architecture

- **Backend:** Python 3.11+, FastAPI, Pydantic, SQLAlchemy, SQLite, Watchdog, standard-library hashing, Pytest.
- **Frontend:** React, TypeScript, Vite, Tailwind CSS. The dashboard uses real local API state.
- **Persistence:** SQLite with bounded demo history and explicit demo-run lineage.
- **Observer:** one lifecycle-managed service, bounded callback queue, coalescing, explicit health/error state, idempotent start/stop, clean shutdown.
- **Scenario simulator:** fixed enumerated actions over known fixture names only; no arbitrary paths, shell commands, encryption, or real backup/service operations.
- **API:** health/system, monitoring lifecycle, files/events, baseline/verification, backup events, rules/hits, incidents/notes, demo runs/reset, dashboard summary/activity.

## Reliability improvements over the brief

1. Treat filesystem watcher delivery as best-effort and expose overflow/error/restart health rather than promise complete OS coverage.
2. Periodically reconcile the demo root against the baseline so missed callbacks do not silently hide integrity changes.
3. Keep separate raw observer notifications and normalized logical events; deduplicate with bounded time windows and stable run IDs.
4. Use a bounded queue with observable backpressure/drop counters; never block Watchdog callbacks on database work.
5. Hash via no-follow file descriptors, with size/count caps and before/after stat checks to detect files changing mid-hash.
6. Fail closed on symlinks, path traversal, root identity changes, unexpected files, and reset attempts outside the fixed owned tree.
7. Make reset idempotent, marker-guarded, limited to known fixture paths, and preserve unrelated user-created files by refusing unsafe cleanup.
8. Persist a small audit trail for baseline changes, monitor lifecycle, scenario actions, and incident workflow.
9. Ensure scenario reruns have explicit IDs and idempotency keys, preventing duplicate active cases.
10. Use UTC timestamps, a versioned event schema, API pagination/limits, and an error state that does not misrepresent missing telemetry as healthy.

## UI direction

Use the approved light editorial operations-console concept: warm ivory/stone surfaces, ink-blue typography, muted slate data, restrained orange warnings, and muted teal health states. Emphasize event provenance, timestamp, distinct-file counts, and rule explanations. The layout and palette are a design decision for broad business audiences, not personal customization.

Required pages: Overview; File Activity; Integrity; Backup Health; Incidents; Detection Rules; Demo Control. Every action must call the API and display success/error state. All simulated states must carry visible “SIMULATED” labeling.

## Build phases and gates

1. **Safety foundation:** separate project, fixed root ownership marker, fixture generator, safe path/file primitives, SQLite.
2. **First vertical slice:** actual Watchdog callbacks for harmless modifications to 20+ distinct demo files; normalized/persisted events; R001 hit and one persistent evidence-linked incident; replay deduplication. This is the mandatory gate before UI polishing.
3. **Integrity and watcher reliability:** create/verify baseline, report modified/created/missing/moved/unreadable, lifecycle/restart/queue health, periodic reconciliation.
4. **Behavior and correlation:** R002–R007, simulated backup events, explanations, scoring and deduplication.
5. **Incident API and audit:** notes/status/assignment and simulated-response preview state.
6. **Dashboard:** approved UI direction connected to actual backend data.
7. **Scenarios and reset:** three reproducible scenarios; restore only owned fixtures and verify clean baseline.
8. **Verification and showcase:** unit and end-to-end file watcher tests, run scripts, docs, responsive visual review, measured resource use where practical.

## Agent plan and verified readiness

Codex owns integration and safety. Antigravity is a candidate for UI review/implementation, OpenCode for isolated components/docs, and Kilo for focused tests/review. No agent is considered ready from installation alone: require an exact-session no-edit response, report actual model identity, assign non-overlapping files, and review all delegated work. Current bridge inventory has a healthy Antigravity session attached to OQVIAN VULNORBIT and a generic Cybersecurity OpenCode session; neither is a RANSENTRY-specific session. Kilo CLI is installed/configured, but no successful RANSENTRY task response has yet been verified. A fresh Antigravity session must attach the bridge before native delivery is trusted.

## Definition of done

- Runs on localhost on an ordinary laptop, without Docker/GPU/cloud/paid APIs.
- Actual observed filesystem activity inside the safe demo workspace is persisted and analyzed.
- R001 requires 20 distinct modifications in 10 seconds and has a test for 19 non-triggering modifications.
- R002/R003 windows count distinct paths and preserve source/destination evidence.
- Baseline comparison and integrity statuses are correct; symlinks/path escape are rejected.
- Simulated backup events are visible as simulation, and R006 correlates only within the same root/window.
- A single normal edit does not claim ransomware or produce a critical incident.
- Reprocessing/scenario rerun does not multiply an active case.
- Analyst state and audit events persist.
- Reset touches only explicitly owned fixtures and verifies restoration.
- All visible UI controls are functional and the dashboard reads backend state.
- Automated unit and actual filesystem integration tests pass.
- Run/presenter docs state the demo limits clearly.

