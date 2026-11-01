# System Functionality and Workflow

## Functional areas

### Monitoring and event intake

The monitor observes only the fixed application-owned `demo_workspace/monitored_files` directory. It records create, modify, delete, move/rename, and relevant observer error events with UTC observed/processed timestamps, root ID, relative source/destination paths, event type, source mode (`watcher` or `scenario`), and scenario-run ID when applicable. The API never accepts a filesystem path to watch or mutate.

### Integrity and baseline

Capture a versioned baseline containing relative path, size, mtime, streaming SHA-256, baseline ID, and capture time. Verification reports Unchanged, Modified, Created after baseline, Missing, Moved/Renamed (when evidence supports association), or Unable to verify. Hashing uses file-size limits, no-follow opens, stable-stat checks, and bounded work off the event loop. A single change is an integrity finding, not a ransomware verdict.

### Detection and correlation

R001–R003 use sliding windows and distinct paths; R004 derives integrity changes; R005 is a simulated backup warning; R006 links qualifying file activity to a backup warning for the same demo root within 60 seconds; R007 marks fictional approved maintenance while preserving all evidence. Thresholds and rule hits are returned by the API so the UI can display the same rules the backend executes.

### Incidents and evidence

An incident contains a stable correlation key, title, priority, demo score, status, first/last seen UTC times, triggered rule IDs, file count, evidence references, and explanation assembled from actual stored rule hits. Repeated raw callbacks and scenario replays are deduplicated. Incident detail presents a chronological evidence timeline, affected relative paths, backup event provenance, score breakdown, and limitations.

### Analyst workflow

Operators can acknowledge, investigate, escalate, resolve, reopen, assign a fictional analyst, and add notes. Every workflow mutation records an audit event. A response action can be previewed and marked “approved for demonstration,” but remains a database-only simulation; no process isolation, account changes, service changes, or host commands execute.

### Demonstration controller

The presenter can choose a normal single-file change, suspicious modification burst, or file activity plus simulated backup warning. The simulator acts only on allowlisted demo fixtures under a verified root marker. Reset stops monitoring, restores only known fixture files, clears demo-generated data by run lineage, recaptures the baseline, restarts monitoring only when explicitly requested, and verifies the resulting state.

## API surface (planned)

- `GET /api/health`, `GET /api/system/status`
- `GET /api/monitor/status`, `POST /api/monitor/start`, `POST /api/monitor/stop`
- `GET /api/files`, `GET /api/file-events`, `GET /api/file-events/{id}`
- `GET /api/integrity/status`, `POST /api/integrity/baseline`, `POST /api/integrity/verify`, `GET /api/integrity/results`
- `GET /api/backup/status`, `GET /api/backup/events`, `POST /api/demo/backup-event`
- `GET /api/rules`, `GET /api/rule-hits`, `POST /api/detection/evaluate`
- `GET /api/incidents`, `GET /api/incidents/{id}`, `PATCH /api/incidents/{id}`, `POST /api/incidents/{id}/notes`
- `GET /api/demo/scenarios`, `POST /api/demo/scenarios/{id}/run`, `GET /api/demo/runs/{id}`, `POST /api/demo/reset`
- `GET /api/dashboard/summary`, `GET /api/dashboard/activity`

## UI pages

1. **Overview:** watcher health, file counts, integrity deltas, open cases, activity chart, correlated incident.
2. **File Activity:** normalized event stream with filters and evidence drawer.
3. **Integrity:** baseline metadata, inventory, changed/missing/created/unverifiable items, verification action.
4. **Backup Health:** Meridian Backup Service state/timeline with a permanent simulated-data label.
5. **Incidents:** investigation queue and detailed timeline, rule explanations, notes, status changes, audit history.
6. **Detection Rules:** R001–R007 thresholds, windows, score inputs, false-positive limitations.
7. **Demo Control:** scenario selection, monitor lifecycle, baseline, simulated backup warning, reset and clean-state verification.

