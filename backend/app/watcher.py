from __future__ import annotations

import queue
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from .db import SessionLocal
from .detection import evaluate_event
from .models import FileEvent
from .safety import DEMO_ROOT, UnsafeDemoRoot, verify_demo_root

CAPACITY = 4096
COALESCE_SECONDS = 0.45


class MonitorService:
    def __init__(self) -> None:
        self._queue: queue.Queue[dict] = queue.Queue(maxsize=CAPACITY)
        self._observer: Observer | None = None
        self._worker: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.RLock()
        self.state = "stopped"
        self.error: str | None = None
        self.accepted = 0
        self.dropped = 0
        self.coalesced = 0
        self.active_scenario_run_id: str | None = None

    def status(self) -> dict:
        with self._lock:
            return {"state": self.state, "root": "demo_workspace/monitored_files", "source_mode": "local watcher",
                    "queue_depth": self._queue.qsize(), "queue_capacity": CAPACITY,
                    "events_accepted": self.accepted, "events_dropped": self.dropped,
                    "events_coalesced": self.coalesced, "error": self.error}

    def start(self) -> dict:
        with self._lock:
            if self._observer and self._observer.is_alive():
                return self.status()
            root = verify_demo_root()
            self._stop.clear()
            self.error = None
            self.state = "starting"
            self._worker = threading.Thread(target=self._consume, name="ransentry-events", daemon=True)
            self._worker.start()
            self._observer = Observer(timeout=1)
            self._observer.schedule(_Handler(self), str(root), recursive=True)
            self._observer.start()
            self.state = "active"
            return self.status()

    def stop(self) -> dict:
        with self._lock:
            observer = self._observer
            self._observer = None
            self.state = "stopping" if observer else "stopped"
        if observer:
            observer.stop()
            observer.join(timeout=5)
        self._stop.set()
        if self._worker and self._worker.is_alive():
            self._worker.join(timeout=5)
        with self._lock:
            self.state = "stopped"
        return self.status()

    def submit(self, payload: dict) -> None:
        payload["scenario_run_id"] = self.active_scenario_run_id
        try:
            self._queue.put_nowait(payload)
            self.accepted += 1
        except queue.Full:
            self.dropped += 1

    def _consume(self) -> None:
        last_seen: dict[tuple, float] = {}
        while not self._stop.is_set() or not self._queue.empty():
            try:
                item = self._queue.get(timeout=0.2)
            except queue.Empty:
                continue
            key = (item["event_type"], item["relative_path"], item.get("destination_path"))
            now = time.monotonic()
            if now - last_seen.get(key, -10) < COALESCE_SECONDS:
                self.coalesced += 1
                self._queue.task_done()
                continue
            last_seen[key] = now
            # Expire keys so the bounded normalizer cannot grow for the lifetime of the service.
            if len(last_seen) > 2048:
                last_seen = {k: v for k, v in last_seen.items() if now - v < COALESCE_SECONDS * 4}
            try:
                with SessionLocal() as db:
                    event = FileEvent(dedupe_key=item["dedupe_key"], event_type=item["event_type"],
                                      relative_path=item["relative_path"], destination_path=item.get("destination_path"),
                                      observed_at=item["observed_at"], source_mode="watcher", is_directory=item["is_directory"],
                                      scenario_run_id=item.get("scenario_run_id"))
                    db.add(event)
                    db.flush()
                    evaluate_event(db, event)
                    db.commit()
            except Exception as exc:  # Keep the observer alive; expose the fault.
                self.error = f"Event processing error: {type(exc).__name__}"
            finally:
                self._queue.task_done()

    def flush(self, timeout: float = 5.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._queue.unfinished_tasks == 0:
                return True
            time.sleep(0.025)
        return self._queue.unfinished_tasks == 0


class _Handler(FileSystemEventHandler):
    def __init__(self, service: MonitorService) -> None:
        self.service = service
        self.root = verify_demo_root()

    def on_any_event(self, event: FileSystemEvent) -> None:
        kind = event.event_type
        if kind in {"opened", "closed", "closed_no_write"}:
            return
        mapping = {"created": "file.created", "modified": "file.modified", "deleted": "file.deleted", "moved": "file.moved"}
        if kind not in mapping:
            return
        src = Path(event.src_path)
        dst = Path(getattr(event, "dest_path", "")) if kind == "moved" else None
        try:
            src_rel = src.relative_to(self.root).as_posix()
            if src_rel.startswith("../") or src_rel == "." or src_rel == ".ransentry-root":
                return
            dst_rel = dst.relative_to(self.root).as_posix() if dst else None
            if dst_rel and (dst_rel.startswith("../") or dst_rel == ".ransentry-root"):
                return
            if src.is_symlink() or (dst and dst.is_symlink()):
                return
        except (ValueError, OSError):
            return
        observed = datetime.now(timezone.utc).replace(tzinfo=None)
        # A short event-time bucket makes duplicate native callbacks idempotent.
        bucket = int(observed.timestamp() / COALESCE_SECONDS)
        dedupe = f"{mapping[kind]}:{src_rel}:{dst_rel or ''}:{bucket}"
        self.service.submit({"event_type": mapping[kind], "relative_path": src_rel, "destination_path": dst_rel,
                             "observed_at": observed, "is_directory": event.is_directory, "dedupe_key": dedupe})


monitor = MonitorService()

