from __future__ import annotations

import os
import tempfile
from pathlib import Path

os.environ["RANSENTRY_DB"] = str(Path(tempfile.gettempdir()) / f"ransentry-test-{os.getpid()}.sqlite3")

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        test_client.post("/api/demo/reset")
        yield test_client
        test_client.post("/api/demo/reset")

