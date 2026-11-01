from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.detection import evaluate_event
from app.db import SessionLocal
from app.models import FileEvent, Incident, RuleHit
from app.safety import DEMO_ROOT, UnsafeDemoRoot, checked_path
from app.watcher import monitor


def test_health_and_system_are_local_demo(client):
    health = client.get("/api/health").json()
    assert health["product"] == "OQVIAN RANSENTRY"
    assert health["source_data"] == "fictional fixtures"
    status = client.get("/api/system/status").json()
    assert status["demo_root_valid"] is True
    assert status["monitor"]["state"] == "stopped"


def test_baseline_captures_only_demo_fixture_files(client):
    response = client.post("/api/integrity/baseline")
    assert response.status_code == 200
    data = response.json()
    assert data["file_count"] == 128
    verify = client.post("/api/integrity/verify").json()
    assert verify["checked_count"] == 128
    assert verify["changed_count"] == 0


def test_real_watchdog_burst_creates_one_evidence_linked_incident(client):
    client.post("/api/integrity/baseline")
    result = client.post("/api/demo/scenarios/modification-burst/run")
    assert result.status_code == 200, result.text
    body = result.json()
    assert len(body["changed_files"]) == 24
    assert body["monitor"]["state"] == "active"
    assert body["monitor"]["events_dropped"] == 0
    with SessionLocal() as db:
        events = db.scalars(select(FileEvent).where(FileEvent.scenario_run_id == body["run_id"])).all()
        hits = db.scalars(select(RuleHit).where(RuleHit.rule_id == "R001")).all()
        cases = db.scalars(select(Incident)).all()
        assert len({e.relative_path for e in events if e.event_type == "file.modified"}) >= 20
        assert hits and hits[0].distinct_file_count >= 20
        assert len(cases) == 1
        assert cases[0].evidence_event_ids != "[]"


def test_backup_warning_correlates_without_duplicate_case(client):
    result = client.post("/api/demo/scenarios/burst-and-backup-warning/run")
    assert result.status_code == 200, result.text
    payload = result.json()
    assert payload["backup_event"]["source_mode"] == "simulated"
    assert payload["incident"]["title"] == "Suspicious File Activity with Backup Protection Warning"
    assert "R006" in payload["incident"]["rule_ids"]
    with SessionLocal() as db:
        assert len(db.scalars(select(Incident)).all()) == 1


def test_mass_rename_and_delete_scenarios_are_resettable(client):
    renamed = client.post("/api/demo/scenarios/mass-rename/run")
    assert renamed.status_code == 200, renamed.text
    assert renamed.json()["changed_files"]
    reset = client.post("/api/demo/reset")
    assert reset.status_code == 200, reset.text
    assert reset.json()["restored_file_count"] == 128
    assert not list(DEMO_ROOT.rglob("*.demo-renamed"))
    deleted = client.post("/api/demo/scenarios/deletion-burst/run")
    assert deleted.status_code == 200, deleted.text
    reset = client.post("/api/demo/reset")
    assert reset.status_code == 200
    assert len(client.get("/api/files").json()) == 128


def test_single_file_change_is_not_a_ransomware_incident(client):
    result = client.post("/api/demo/scenarios/single-change/run")
    assert result.status_code == 200
    assert result.json()["incident"] is None
    assert client.get("/api/incidents").json() == []


def test_modification_rule_requires_twenty_distinct_paths(client):
    client.post("/api/demo/reset")
    observed = datetime.now(timezone.utc).replace(tzinfo=None)
    with SessionLocal() as db:
        for i in range(18):
            event = FileEvent(dedupe_key=f"threshold-{i}", event_type="file.modified",
                              relative_path=f"finance/record_{i + 1:03d}.txt", observed_at=observed,
                              source_mode="test", scenario_run_id="threshold-check", is_directory=False)
            db.add(event)
        db.flush()
        below = FileEvent(dedupe_key="threshold-19", event_type="file.modified",
                          relative_path="finance/record_019.txt", observed_at=observed + timedelta(milliseconds=1),
                          source_mode="test", scenario_run_id="threshold-check", is_directory=False)
        db.add(below)
        db.flush()
        assert evaluate_event(db, below) == []
        latest = FileEvent(dedupe_key="threshold-20", event_type="file.modified",
                           relative_path="finance/record_020.txt", observed_at=observed + timedelta(milliseconds=2),
                           source_mode="test", scenario_run_id="threshold-check", is_directory=False)
        db.add(latest)
        db.flush()
        assert len(evaluate_event(db, latest)) == 1
        db.commit()


def test_path_traversal_and_symlink_are_rejected():
    try:
        checked_path("../../README.md")
    except UnsafeDemoRoot:
        pass
    else:
        raise AssertionError("path traversal accepted")
    link = DEMO_ROOT / "unsafe-link"
    try:
        link.symlink_to(DEMO_ROOT.parent)
        try:
            checked_path("unsafe-link/README.md")
        except UnsafeDemoRoot:
            pass
        else:
            raise AssertionError("symlink traversal accepted")
    finally:
        if link.is_symlink():
            link.unlink()


def test_monitor_start_stop_is_idempotent(client):
    assert client.post("/api/monitor/start").json()["state"] == "active"
    assert client.post("/api/monitor/start").json()["state"] == "active"
    assert client.post("/api/monitor/stop").json()["state"] == "stopped"

