# Architecture

## Data path

Fixed owned demo root → Watchdog callback → bounded in-memory queue → coalescing/normalization worker → SQLite file event → integrity and rule evaluation → deduplicated rule hit/incident → local FastAPI → React dashboard.

Fictional backup warnings enter through scenario endpoints with `source_mode=simulated`; they are never mixed indistinguishably with observed filesystem data. Incident evidence points to persisted file-event, integrity-result, and backup-event IDs.

## Main components

- `backend/app/safety.py`: fixed root verification, no-follow descriptor operations, streaming hash limits, and bounded known-file reset helpers.
- `backend/app/watcher.py`: Watchdog lifecycle, bounded queue, per-path callback coalescing, and event persistence worker.
- `backend/app/detection.py`: R001–R003 sliding windows, distinct-path counting, simulated backup correlation, case deduplication, and explainable demo scoring.
- `backend/app/main.py`: FastAPI routes, scenario controller, analyst workflow, audit events, baseline checks, and SQLite access.
- `backend/app/models.py` and `db.py`: SQLAlchemy models and SQLite session setup.
- `frontend/`: responsive React pages driven by API responses.

## Reliability boundaries

Watchdog notification delivery is best effort. The system exposes observer state, callback queue saturation, errors, and coalesced-event counts. Periodic baseline reconciliation is a planned improvement and is not implemented in this demo. Hash calculations are bounded, streamed, no-follow, and run outside the API event loop. The root path and safety marker are verified before reads/writes/reset. A changed root identity or unsafe path stops mutation and reports an error.

## Persistence and growth

SQLite stores events, baselines, rule hits, incidents, evidence links, notes, audit entries, and scenario runs. Timestamp, event, status, and run fields are indexed; list endpoints impose pagination limits. Demo reset is scoped to known fixture files and demo tables, and preserves unrecognized workspace files.

