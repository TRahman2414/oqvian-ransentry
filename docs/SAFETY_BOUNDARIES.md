# Safety Boundaries

- The only monitored/mutable folder is the application-owned disposable demo workspace, protected by a marker file and canonical-root/inode checks.
- No arbitrary path is accepted through the UI or API. Simulator actions resolve fixed fixture IDs, never user-provided path strings.
- Reject symlink components and symlink files. Do not recursively follow links. Use no-follow file opens and re-check root identity before writes/reset.
- Only small, known `.txt`, `.csv`, and `.json` fixtures are eligible. Bound file count, individual size, total size, event queue, retained history, and API response size.
- No encryption, ransom note creation, command execution, real backup operations, process termination, endpoint isolation, account restriction, or security-control changes.
- Backup events, response previews, approval, and maintenance context are explicitly simulated.
- Watcher attribution does not identify the responsible process; UI and docs must not imply it does.
- Watchdog event delivery is best-effort. Report observer errors, queue saturation, and reconciliation discrepancies; do not claim complete OS event coverage.
- Reset operates only on known files under a verified owned tree. If a root marker/inode check fails, refuse reset and preserve evidence.
- Scores are transparent demo priorities, not calibrated ransomware probabilities. Correlation is an investigation lead, not proof of compromise.

