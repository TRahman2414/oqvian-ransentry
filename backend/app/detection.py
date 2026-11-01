from __future__ import annotations

import json
import hashlib
import math
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import BackupEvent, FileEvent, Incident, RuleHit

RULES = [
    {"id": "R001", "name": "Rapid File Modification Burst", "threshold": 20, "window_seconds": 10, "event_type": "file.modified", "weight": 20},
    {"id": "R002", "name": "Mass Rename Activity", "threshold": 15, "window_seconds": 10, "event_type": "file.moved", "weight": 25},
    {"id": "R003", "name": "Rapid Deletion Burst", "threshold": 10, "window_seconds": 10, "event_type": "file.deleted", "weight": 25},
]


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def priority_for(score: int) -> str:
    if score >= 85:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 50:
        return "Medium"
    if score >= 30:
        return "Low"
    return "Informational"


def evaluate_event(db: Session, event: FileEvent) -> list[RuleHit]:
    created: list[RuleHit] = []
    if event.is_directory:
        return created
    for rule in RULES:
        if event.event_type != rule["event_type"]:
            continue
        end = event.observed_at
        start = end - timedelta(seconds=rule["window_seconds"])
        rows = db.scalars(select(FileEvent).where(
            FileEvent.event_type == rule["event_type"],
            FileEvent.observed_at >= start,
            FileEvent.observed_at <= end,
            FileEvent.is_directory.is_(False),
        ).order_by(FileEvent.observed_at.asc())).all()
        distinct = {r.destination_path or r.relative_path for r in rows}
        if len(distinct) < rule["threshold"]:
            continue
        run_id = event.scenario_run_id or "observed"
        # One persistent hit per deterministic scenario run. For live observed
        # events, a UTC 10-second bucket bounds repeat aggregation.
        window_id = event.scenario_run_id or math.floor(end.timestamp() / 10)
        hit_key = f"{rule['id']}:{run_id}:{window_id}"
        hit = db.scalar(select(RuleHit).where(RuleHit.hit_key == hit_key))
        if hit is None:
            hit = RuleHit(
                rule_id=rule["id"], hit_key=hit_key,
                window_start=min(r.observed_at for r in rows), window_end=end,
                distinct_file_count=len(distinct),
                explanation=f"{len(distinct)} distinct file paths had {rule['event_type'].split('.')[1]} events within {rule['window_seconds']} seconds (demo threshold: {rule['threshold']}).",
                evidence_event_ids=json.dumps(sorted({r.id for r in rows})),
            )
            db.add(hit)
            db.flush()
            create_or_update_incident(db, hit, rows, None)
            created.append(hit)
        else:
            hit.window_start = min(r.observed_at for r in rows)
            hit.window_end = end
            hit.distinct_file_count = len(distinct)
            hit.explanation = f"{len(distinct)} distinct file paths had {rule['event_type'].split('.')[1]} events within {rule['window_seconds']} seconds (demo threshold: {rule['threshold']})."
            hit.evidence_event_ids = json.dumps(sorted({r.id for r in rows}))
            create_or_update_incident(db, hit, rows, None)
    return created


def create_or_update_incident(db: Session, hit: RuleHit | None, rows: list[FileEvent], backup: BackupEvent | None) -> Incident | None:
    if hit is None and backup is None:
        return None
    hit_rows: list[RuleHit] = []
    if hit is not None:
        start = hit.window_end - timedelta(seconds=60)
        hit_rows = db.scalars(select(RuleHit).where(RuleHit.window_end >= start, RuleHit.window_end <= hit.window_end).order_by(RuleHit.window_end.asc())).all()
    elif backup is not None:
        start = backup.occurred_at - timedelta(seconds=60)
        hit_rows = db.scalars(select(RuleHit).where(RuleHit.window_end >= start, RuleHit.window_end <= backup.occurred_at).order_by(RuleHit.window_end.asc())).all()
    eligible = [h for h in hit_rows if h.rule_id in {"R001", "R002", "R003"}]
    has_backup = backup is not None or (eligible and db.scalar(select(BackupEvent.id).where(
        BackupEvent.occurred_at >= min(h.window_end for h in eligible),
        BackupEvent.occurred_at <= max(h.window_end for h in eligible) + timedelta(seconds=60),
        BackupEvent.source_mode == "simulated",
    )) is not None)
    if backup is not None and not eligible:
        return None
    rule_ids = {h.rule_id for h in hit_rows}
    if has_backup:
        rule_ids.add("R005")
        rule_ids.add("R006")
    score = min(100, sum(next((int(r["weight"]) for r in RULES if r["id"] == rid), 0) for rid in rule_ids)
                + (30 if backup and backup.status == "unexpectedly_disabled" else (20 if has_backup else 0))
                + (35 if has_backup else 0))
    rule_list = sorted(rule_ids)
    evidence_ids = sorted({int(value) for h in hit_rows for value in json.loads(h.evidence_event_ids or "[]")})
    if hit is not None:
        evidence_ids.extend(r.id for r in rows if r.id not in evidence_ids)
    if backup is not None:
        title = "Suspicious File Activity with Backup Protection Warning"
        key = f"correlated:{min(evidence_ids or [0])}:{backup.event_key}"
        explanation = f"{', '.join(rule_list)} matched for the demo workspace. {backup.explanation} This is a review lead, not confirmation of ransomware."
    else:
        title = "Unusual File Activity Burst"
        key = f"file-activity:{hit.hit_key if hit else 'unknown'}"
        explanation = "; ".join(h.explanation for h in hit_rows)
        if has_backup:
            title = "Suspicious File Activity with Backup Protection Warning"
            key = f"correlated:{min(evidence_ids or [0])}:{','.join(rule_list)}"
            explanation += ". A simulated backup warning occurred within the configured correlation window; this is not confirmation of ransomware."
    incident = db.scalar(select(Incident).where(Incident.correlation_key == key))
    if has_backup and incident is None and evidence_ids:
        # Promote the existing file-burst investigation rather than opening a
        # second case when correlated backup evidence arrives shortly later.
        for candidate in db.scalars(select(Incident).where(Incident.status != "Resolved")).all():
            if set(json.loads(candidate.evidence_event_ids or "[]")) & set(evidence_ids):
                incident = candidate
                break
    timestamp = backup.occurred_at if backup else (hit.window_end if hit else utcnow())
    if incident is None:
        incident = Incident(correlation_key=key, title=title, priority=priority_for(score), score=score,
                            status="New", first_seen=timestamp, last_seen=timestamp,
                            rule_ids=json.dumps(rule_list), evidence_event_ids=json.dumps(sorted(set(evidence_ids))),
                            explanation=explanation)
        db.add(incident)
    else:
        if has_backup:
            incident.title = title
            incident.correlation_key = key
        incident.last_seen = max(incident.last_seen, timestamp)
        incident.score = max(incident.score, score)
        incident.priority = priority_for(incident.score)
        incident.rule_ids = json.dumps(sorted(set(json.loads(incident.rule_ids or "[]")) | rule_ids))
        incident.evidence_event_ids = json.dumps(sorted(set(json.loads(incident.evidence_event_ids or "[]")) | set(evidence_ids)))
        incident.explanation = explanation
        incident.updated_at = utcnow()
    db.flush()
    return incident

