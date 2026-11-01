# Test Report

## Latest local verification

- `cd backend && uv run pytest`: **9 passed**. Includes a real Watchdog burst against disposable fixture files, evidence-linked incident creation, simulated backup correlation, safe reset after rename/delete scenarios, single-edit handling, path/symlink rejection, idempotent monitor lifecycle, and the 19/20 distinct-file threshold.
- `cd frontend && npm run build`: **passed** with TypeScript project checks and Vite production bundle.

The Python run reports one upstream Starlette deprecation warning about using `httpx` with `TestClient`; it does not fail the suite.

## Limits of this verification

These checks demonstrate expected behavior on the local demo environment. They do not measure production event-delivery guarantees, ransomware detection accuracy, host recovery, backup integration, or performance on a customer server. Watchdog notifications are best-effort; queue drops and monitor errors are surfaced in health state. Periodic reconciliation remains future work and is not claimed as implemented.

