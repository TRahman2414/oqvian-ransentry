# OQVIAN RANSENTRY

**Ransomware early warning and file integrity monitoring demo**

OQVIAN RANSENTRY is a local-first defensive demonstration. It watches an application-owned folder of fictional disposable files, identifies integrity changes and unusual file-operation bursts, and correlates those signals with clearly labeled simulated backup events. Analysts can inspect the evidence and use a simulated response preview.

It is not antivirus, EDR, a ransomware recovery product, or a production protection service. The demo never encrypts files, changes real backup services, or runs containment against a real machine.

## Demo capabilities

- A managed local Watchdog observer for the fixed demo workspace.
- SHA-256 baselines and integrity comparison.
- Explainable file-operation burst detection (R001–R003), plus simulated backup warning correlation (R005–R006).
- SQLite events, rule hits, incidents, notes, and audit history.
- Safe, repeatable synthetic file activity and backup scenarios.
- Dashboard pages for overview, activity, integrity, backup health, incidents, rules, and demo control.
- Analyst workflow with response previews that require explicit human approval and remain simulated.

## Run locally

Requirements: Python 3.11+ with `uv`, and Node.js 20+ with npm. No cloud account, Docker, GPU, or paid API is required. From the repository root:

```bash
./scripts/bootstrap.sh
./scripts/start-dev.sh
```

Open the dashboard at <http://127.0.0.1:4184>. The local API is at <http://127.0.0.1:8011> and its schema UI is at <http://127.0.0.1:8011/docs>. Both servers bind to loopback.

The demo creates a SQLite database in the ignored `data/` directory and watches only the fixed `demo_workspace/monitored_files/` folder. Its records are fictional. “Reset demo” restores known fixture files and clears demo-generated events; it preserves unrecognized files.

To run the implementation checks:

```bash
cd backend && uv run pytest
cd ../frontend && npm run build
```

See [docs/DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md) for a short walkthrough and [docs/SAFETY_BOUNDARIES.md](docs/SAFETY_BOUNDARIES.md) for the limits of the showcase.

See [MASTER_PLAN.md](MASTER_PLAN.md), [docs/SYSTEM_WORKFLOW.md](docs/SYSTEM_WORKFLOW.md), and [docs/SAFETY_BOUNDARIES.md](docs/SAFETY_BOUNDARIES.md).

