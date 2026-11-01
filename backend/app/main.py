from __future__ import annotations

import json
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field
from sqlalchemy import delete, select

from .db import Base, SessionLocal, engine
from .detection import RULES, create_or_update_incident, evaluate_event, priority_for
from .models import AuditEvent, BackupEvent, BaselineFile, FileEvent, Incident, IntegrityResult, RuleHit, utcnow
from .safety import (DEMO_ROOT, MAX_FILE_BYTES, UnsafeDemoRoot, checked_path, iter_regular_files,
                     rename_demo_file, sha256_file, unlink_demo_file, verify_demo_root, write_demo_file)
from .watcher import monitor


class IncidentPatch(BaseModel):
    status: str | None = Field(default=None, pattern="^(New|Acknowledged|Investigating|Escalated|Resolved|Reopened)$")
    assigned_analyst: str | None = Field(default=None, max_length=80)


class NoteRequest(BaseModel):
    content: str = Field(min_length=1, max_length=2000)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    Base.metadata.create_all(bind=engine)
    ensure_seed_files()
    yield
    monitor.stop()


app = FastAPI(title="OQVIAN RANSENTRY", version="0.1.0", description="Local-first file-integrity and ransomware early-warning demo", lifespan=lifespan)


def ensure_seed_files() -> None:
    root = verify_demo_root()
    for folder in ("finance", "hr", "operations", "reports", "archives"):
        (root / folder).mkdir(exist_ok=True)
    if any(path for path in iter_regular_files()):
        return
    for i in range(1, 129):
        area = ("finance", "hr", "operations", "reports", "archives")[(i - 1) % 5]
        name = f"record_{i:03d}.txt"
        write_demo_file(f"{area}/{name}", f"Fictional Meridian Business Services demo record {i:03d}.\nCategory: {area}.\nNot real customer data.\n", create=True)


def audit(db, entity_type: str, entity_id: str, action: str, details: dict) -> None:
    db.add(AuditEvent(entity_type=entity_type, entity_id=entity_id, action=action, details=json.dumps(details)))


def event_json(event: FileEvent) -> dict:
    return {"id": event.id, "event_type": event.event_type, "relative_path": event.relative_path,
            "destination_path": event.destination_path, "observed_at": event.observed_at.isoformat() + ("Z" if event.observed_at.tzinfo is None else ""),
            "source_mode": event.source_mode, "scenario_run_id": event.scenario_run_id, "is_directory": event.is_directory}


def incident_json(incident: Incident) -> dict:
    return {"id": incident.id, "title": incident.title, "priority": incident.priority, "score": incident.score,
            "status": incident.status, "first_seen": incident.first_seen.isoformat(), "last_seen": incident.last_seen.isoformat(),
            "assigned_analyst": incident.assigned_analyst, "rule_ids": json.loads(incident.rule_ids or "[]"), "evidence_event_ids": json.loads(incident.evidence_event_ids or "[]"),
            "explanation": incident.explanation}


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "product": "OQVIAN RANSENTRY", "mode": "local defensive demo", "source_data": "fictional fixtures"}


@app.get("/api/system/status")
def system_status() -> dict:
    try:
        verify_demo_root()
        root_ok, root_error = True, None
    except UnsafeDemoRoot as exc:
        root_ok, root_error = False, str(exc)
    with SessionLocal() as db:
        return {"product": "OQVIAN RANSENTRY", "mode": "local demo", "database": "ready", "demo_root_valid": root_ok,
                "demo_root_error": root_error, "monitor": monitor.status(),
                "file_count": len(iter_regular_files()) if root_ok else 0,
                "open_incidents": len(db.scalars(select(Incident).where(Incident.status != "Resolved")).all()),
                "backup_source_mode": "simulated"}


@app.get("/api/monitor/status")
def monitor_status() -> dict:
    return monitor.status()


@app.post("/api/monitor/start")
def monitor_start() -> dict:
    try:
        result = monitor.start()
    except (UnsafeDemoRoot, OSError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    with SessionLocal() as db:
        audit(db, "monitor", "demo-root", "started", result)
        db.commit()
    return result


@app.post("/api/monitor/stop")
def monitor_stop() -> dict:
    result = monitor.stop()
    with SessionLocal() as db:
        audit(db, "monitor", "demo-root", "stopped", result)
        db.commit()
    return result


@app.get("/api/files")
def files() -> list[dict]:
    try:
        result = []
        for path in iter_regular_files():
            relative = path.relative_to(DEMO_ROOT).as_posix()
            stat = path.stat(follow_symlinks=False)
            result.append({"relative_path": relative, "file_size": stat.st_size,
                           "modified_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
                           "too_large_to_hash": stat.st_size > MAX_FILE_BYTES})
        return sorted(result, key=lambda r: r["relative_path"])
    except UnsafeDemoRoot as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/api/file-events")
def file_events(limit: int = 100) -> list[dict]:
    limit = max(1, min(limit, 500))
    with SessionLocal() as db:
        return [event_json(row) for row in db.scalars(select(FileEvent).order_by(FileEvent.observed_at.desc()).limit(limit)).all()]


@app.get("/api/file-events/{event_id}")
def file_event_detail(event_id: int) -> dict:
    with SessionLocal() as db:
        row = db.get(FileEvent, event_id)
        if not row:
            raise HTTPException(status_code=404, detail="File event not found")
        return event_json(row)


def _capture_baseline() -> dict:
    root = verify_demo_root()
    baseline_id = str(uuid.uuid4())
    captured = utcnow()
    files_to_hash = iter_regular_files()
    with SessionLocal() as db:
        rows = []
        for path in files_to_hash:
            digest, info = sha256_file(path)
            rows.append(BaselineFile(baseline_id=baseline_id, relative_path=path.relative_to(root).as_posix(),
                                     file_size=info.st_size, modified_at=datetime.fromtimestamp(info.st_mtime, timezone.utc).replace(tzinfo=None),
                                     sha256=digest, captured_at=captured))
        db.add_all(rows)
        audit(db, "baseline", baseline_id, "captured", {"file_count": len(rows)})
        db.commit()
    return {"baseline_id": baseline_id, "file_count": len(rows), "captured_at": captured.isoformat() + "Z"}


@app.post("/api/integrity/baseline")
async def baseline() -> dict:
    try:
        return await run_in_threadpool(_capture_baseline)
    except (UnsafeDemoRoot, OSError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


def _verify_integrity() -> dict:
    with SessionLocal() as db:
        latest = db.scalars(select(BaselineFile).order_by(BaselineFile.captured_at.desc())).first()
        if not latest:
            raise HTTPException(status_code=409, detail="Capture a baseline first")
        baseline_id = latest.baseline_id
        expected = {r.relative_path: r for r in db.scalars(select(BaselineFile).where(BaselineFile.baseline_id == baseline_id)).all()}
        current_paths = {}
        for path in iter_regular_files():
            rel = path.relative_to(DEMO_ROOT).as_posix()
            try:
                digest, info = sha256_file(path)
                current_paths[rel] = (digest, info.st_size)
            except (UnsafeDemoRoot, OSError):
                current_paths[rel] = (None, None)
        statuses = []
        for rel in sorted(set(expected) | set(current_paths)):
            old, now = expected.get(rel), current_paths.get(rel)
            if old is None:
                status, old_hash, new_hash = "created_after_baseline", None, now[0]
            elif now is None:
                status, old_hash, new_hash = "missing", old.sha256, None
            elif now[0] is None:
                status, old_hash, new_hash = "unable_to_verify", old.sha256, None
            elif old.sha256 != now[0]:
                status, old_hash, new_hash = "modified", old.sha256, now[0]
            else:
                status, old_hash, new_hash = "unchanged", old.sha256, now[0]
            db.add(IntegrityResult(baseline_id=baseline_id, relative_path=rel, result_status=status,
                                   expected_hash=old_hash, observed_hash=new_hash))
            statuses.append({"relative_path": rel, "status": status, "expected_hash": old_hash, "observed_hash": new_hash})
        audit(db, "baseline", baseline_id, "verified", {"changed_count": sum(x["status"] != "unchanged" for x in statuses)})
        db.commit()
        return {"baseline_id": baseline_id, "checked_count": len(statuses), "results": statuses,
                "changed_count": sum(x["status"] != "unchanged" for x in statuses)}


@app.post("/api/integrity/verify")
async def verify_integrity() -> dict:
    try:
        return await run_in_threadpool(_verify_integrity)
    except (UnsafeDemoRoot, OSError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/api/integrity/status")
def integrity_status() -> dict:
    with SessionLocal() as db:
        latest = db.scalars(select(BaselineFile).order_by(BaselineFile.captured_at.desc())).first()
        if not latest:
            return {"baseline_id": None, "file_count": 0, "captured_at": None}
        count = len(db.scalars(select(BaselineFile).where(BaselineFile.baseline_id == latest.baseline_id)).all())
        return {"baseline_id": latest.baseline_id, "file_count": count, "captured_at": latest.captured_at.isoformat()}


@app.get("/api/integrity/results")
def integrity_results(limit: int = 200) -> list[dict]:
    with SessionLocal() as db:
        rows = db.scalars(select(IntegrityResult).order_by(IntegrityResult.evaluated_at.desc()).limit(max(1, min(limit, 500)))).all()
        return [{"id": r.id, "relative_path": r.relative_path, "status": r.result_status, "expected_hash": r.expected_hash,
                 "observed_hash": r.observed_hash, "evaluated_at": r.evaluated_at.isoformat()} for r in rows]


@app.get("/api/rules")
def rules() -> list[dict]:
    return RULES + [
        {"id": "R004", "name": "File Integrity Anomaly", "threshold": "baseline difference", "window_seconds": None, "weight": 0},
        {"id": "R005", "name": "Backup Health Warning", "threshold": "simulated failed/disabled/unavailable", "window_seconds": None, "weight": 20},
        {"id": "R006", "name": "File Activity + Backup Correlation", "threshold": "qualifying burst plus backup warning", "window_seconds": 60, "weight": 0},
        {"id": "R007", "name": "Approved Maintenance Context", "threshold": "fictional maintenance window", "window_seconds": None, "weight": -10},
    ]


@app.get("/api/rule-hits")
def rule_hits(limit: int = 100) -> list[dict]:
    with SessionLocal() as db:
        rows = db.scalars(select(RuleHit).order_by(RuleHit.window_end.desc()).limit(max(1, min(limit, 500)))).all()
        return [{"id": r.id, "rule_id": r.rule_id, "window_start": r.window_start.isoformat(), "window_end": r.window_end.isoformat(),
                 "distinct_file_count": r.distinct_file_count, "explanation": r.explanation,
                 "evidence_event_ids": json.loads(r.evidence_event_ids or "[]")} for r in rows]


@app.get("/api/incidents")
def incidents(limit: int = 100) -> list[dict]:
    with SessionLocal() as db:
        return [incident_json(r) for r in db.scalars(select(Incident).order_by(Incident.updated_at.desc()).limit(max(1, min(limit, 500)))).all()]


@app.get("/api/incidents/{incident_id}")
def incident_detail(incident_id: int) -> dict:
    with SessionLocal() as db:
        row = db.get(Incident, incident_id)
        if not row:
            raise HTTPException(status_code=404, detail="Incident not found")
        item = incident_json(row)
        item["events"] = [event_json(e) for e in db.scalars(select(FileEvent).where(FileEvent.id.in_(json.loads(row.evidence_event_ids or "[]"))).order_by(FileEvent.observed_at)).all()] if row.evidence_event_ids != "[]" else []
        item["audit"] = [{"action": a.action, "timestamp": a.timestamp.isoformat(), "details": json.loads(a.details or "{}")} for a in db.scalars(select(AuditEvent).where(AuditEvent.entity_id == str(row.id)).order_by(AuditEvent.timestamp)).all()]
        return item


@app.patch("/api/incidents/{incident_id}")
def patch_incident(incident_id: int, payload: IncidentPatch) -> dict:
    with SessionLocal() as db:
        row = db.get(Incident, incident_id)
        if not row:
            raise HTTPException(status_code=404, detail="Incident not found")
        previous = row.status
        if payload.status is not None:
            row.status = payload.status
        details = {"previous_status": previous, "status": row.status, "assigned_analyst": payload.assigned_analyst}
        row.updated_at = utcnow()
        audit(db, "incident", str(row.id), "workflow_updated", details)
        db.commit()
        return incident_json(row)


@app.post("/api/incidents/{incident_id}/notes")
def add_note(incident_id: int, payload: NoteRequest) -> dict:
    with SessionLocal() as db:
        row = db.get(Incident, incident_id)
        if not row:
            raise HTTPException(status_code=404, detail="Incident not found")
        audit(db, "incident", str(row.id), "note_added", {"note": payload.content})
        db.commit()
        return {"ok": True, "incident_id": incident_id}


@app.get("/api/backup/status")
def backup_status() -> dict:
    with SessionLocal() as db:
        event = db.scalars(select(BackupEvent).order_by(BackupEvent.occurred_at.desc())).first()
        return {"service": "Meridian Backup Service", "status": event.status if event else "healthy",
                "source_mode": "simulated", "last_event": event.occurred_at.isoformat() if event else None}


@app.get("/api/backup/events")
def backup_events(limit: int = 100) -> list[dict]:
    with SessionLocal() as db:
        rows = db.scalars(select(BackupEvent).order_by(BackupEvent.occurred_at.desc()).limit(max(1, min(limit, 500)))).all()
        return [{"id": r.id, "status": r.status, "previous_status": r.previous_status, "occurred_at": r.occurred_at.isoformat(),
                 "source_mode": r.source_mode, "explanation": r.explanation} for r in rows]


def _add_backup_warning(status: str = "unexpectedly_disabled", run_id: str | None = None) -> dict:
    if status not in {"failed", "unavailable", "unexpectedly_disabled"}:
        raise HTTPException(status_code=422, detail="Unsupported simulated backup event")
    now = utcnow()
    event_key = f"simulated:{run_id or uuid.uuid4()}:{status}"
    explanation = f"Fictional Meridian Backup Service reports {status.replace('_', ' ')}. No real backup service was contacted or changed."
    with SessionLocal() as db:
        event = db.scalar(select(BackupEvent).where(BackupEvent.event_key == event_key))
        if event is None:
            event = BackupEvent(event_key=event_key, status=status, previous_status="healthy", occurred_at=now,
                                source_mode="simulated", explanation=explanation, scenario_run_id=run_id)
            db.add(event)
            db.flush()
        incident = create_or_update_incident(db, None, [], event)
        audit(db, "backup", event_key, "simulated_warning_created", {"status": status})
        db.commit()
        return {"id": event.id, "status": event.status, "source_mode": event.source_mode,
                "incident_id": incident.id if incident else None, "explanation": event.explanation}


@app.post("/api/demo/backup-event")
def add_backup_warning(status: str = "unexpectedly_disabled") -> dict:
    return _add_backup_warning(status)


@app.get("/api/dashboard/summary")
def dashboard_summary() -> dict:
    with SessionLocal() as db:
        events = db.scalars(select(FileEvent)).all()
        cases = db.scalars(select(Incident).order_by(Incident.updated_at.desc())).all()
        changes = db.scalars(select(IntegrityResult).where(IntegrityResult.result_status != "unchanged")).all()
        return {"tenant": "Meridian Business Services", "watcher": monitor.status(), "files_monitored": len(iter_regular_files()),
                "integrity_changes": len(changes), "open_incidents": sum(i.status != "Resolved" for i in cases),
                "file_events": len(events), "backup_source_mode": "simulated", "demo_data": True,
                "latest_incident": incident_json(cases[0]) if cases else None}


@app.get("/api/dashboard/activity")
def dashboard_activity(limit: int = 30) -> dict:
    with SessionLocal() as db:
        events = db.scalars(select(FileEvent).order_by(FileEvent.observed_at.desc()).limit(max(1, min(limit, 100)))).all()
        backups = db.scalars(select(BackupEvent).order_by(BackupEvent.occurred_at.desc()).limit(max(1, min(limit, 100)))).all()
        return {"file_events": [event_json(e) for e in events], "backup_events": [{"id": b.id, "status": b.status,
                "occurred_at": b.occurred_at.isoformat(), "source_mode": b.source_mode, "explanation": b.explanation} for b in backups]}


@app.get("/api/demo/scenarios")
def scenarios() -> list[dict]:
    return [
        {"id": "single-change", "name": "Ordinary single-file edit", "description": "One known disposable file changes; remains informational.", "simulated": False},
        {"id": "modification-burst", "name": "Modification burst", "description": "Twenty-four disposable files are modified in a controlled burst.", "simulated": False},
        {"id": "burst-and-backup-warning", "name": "File burst + backup warning", "description": "Actual local fixture modifications plus a separate simulated backup warning.", "simulated": True},
        {"id": "mass-rename", "name": "Mass rename burst", "description": "Fifteen known disposable fixtures are renamed and safely restored by reset.", "simulated": False},
        {"id": "deletion-burst", "name": "Deletion burst", "description": "Ten known disposable fixtures are deleted and recreated by reset.", "simulated": False},
    ]


def _run_scenario(scenario_id: str) -> dict:
    if scenario_id not in {"single-change", "modification-burst", "burst-and-backup-warning", "mass-rename", "deletion-burst"}:
        raise HTTPException(status_code=404, detail="Unknown demo scenario")
    verify_demo_root()
    run_id = str(uuid.uuid4())
    monitor.start()
    monitor.active_scenario_run_id = run_id
    count = 1 if scenario_id == "single-change" else (15 if scenario_id == "mass-rename" else (10 if scenario_id == "deletion-burst" else 24))
    changed = []
    for i in range(count):
        area = ("finance", "hr", "operations", "reports", "archives")[i % 5]
        relative = f"{area}/record_{i + 1:03d}.txt"
        path = checked_path(relative)
        if not path.exists() or path.is_symlink():
            raise HTTPException(status_code=409, detail=f"Expected demo fixture missing or unsafe: {relative}")
        if scenario_id == "mass-rename":
            destination = checked_path(relative + ".demo-renamed")
            if destination.exists() or destination.is_symlink():
                raise HTTPException(status_code=409, detail="A known demo rename target already exists; reset first.")
            rename_demo_file(relative, relative + ".demo-renamed")
        elif scenario_id == "deletion-burst":
            unlink_demo_file(relative)
        else:
            write_demo_file(relative, f"Demo scenario observation {run_id[:8]}\n", append=True)
        changed.append(relative)
    # Let OS callbacks arrive, then wait for their actual persistence.
    import time
    time.sleep(0.35)
    monitor.flush()
    monitor.active_scenario_run_id = None
    backup = _add_backup_warning("unexpectedly_disabled", run_id) if scenario_id == "burst-and-backup-warning" else None
    with SessionLocal() as db:
        audit(db, "scenario", run_id, "completed", {"scenario_id": scenario_id, "changed_files": changed, "backup_simulated": bool(backup)})
        db.commit()
        run_event_ids = {e.id for e in db.scalars(select(FileEvent).where(FileEvent.scenario_run_id == run_id)).all()}
        current = None
        for candidate in db.scalars(select(Incident).order_by(Incident.updated_at.desc())).all():
            if run_event_ids.intersection(json.loads(candidate.evidence_event_ids or "[]")):
                current = candidate
                break
        return {"run_id": run_id, "scenario_id": scenario_id, "changed_files": changed, "backup_event": backup,
                "incident": incident_json(current) if current else None, "monitor": monitor.status()}


@app.post("/api/demo/scenarios/{scenario_id}/run")
async def run_scenario(scenario_id: str) -> dict:
    try:
        return await run_in_threadpool(_run_scenario, scenario_id)
    except (UnsafeDemoRoot, OSError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/api/demo/reset")
def reset_demo() -> dict:
    monitor.stop()
    try:
        verify_demo_root()
        root = verify_demo_root()
        # Restore only fixed, expected demo fixture paths. Never delete arbitrary files.
        changed = 0
        for i in range(1, 129):
            area = ("finance", "hr", "operations", "reports", "archives")[(i - 1) % 5]
            relative = f"{area}/record_{i:03d}.txt"
            path = checked_path(relative)
            moved_path = checked_path(relative + ".demo-renamed")
            if not path.exists() and moved_path.exists() and not moved_path.is_symlink():
                rename_demo_file(relative + ".demo-renamed", relative)
            expected = f"Fictional Meridian Business Services demo record {i:03d}.\nCategory: {area}.\nNot real customer data.\n"
            write_demo_file(relative, expected, create=True)
            changed += 1
        with SessionLocal() as db:
            db.execute(delete(FileEvent))
            db.execute(delete(BaselineFile))
            db.execute(delete(IntegrityResult))
            db.execute(delete(BackupEvent))
            db.execute(delete(RuleHit))
            db.execute(delete(Incident))
            audit(db, "demo", "reset", "restored_known_fixtures", {"file_count": changed, "root": str(root)})
            db.commit()
        result = _capture_baseline()
        return {"status": "restored", "restored_file_count": changed, "baseline": result, "unrecognized_files_preserved": True}
    except (UnsafeDemoRoot, OSError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/api/demo/runs/{run_id}")
def demo_run(run_id: str) -> dict:
    with SessionLocal() as db:
        events = db.scalars(select(FileEvent).where(FileEvent.scenario_run_id == run_id).order_by(FileEvent.observed_at)).all()
        backup = db.scalar(select(BackupEvent).where(BackupEvent.scenario_run_id == run_id))
        return {"run_id": run_id, "events": [event_json(e) for e in events], "backup_event_id": backup.id if backup else None}

