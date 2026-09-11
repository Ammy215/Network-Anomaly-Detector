"""Timing middleware -- per-endpoint server time, without leaking the URL.

The privacy claims matter more than the timing itself: this log line is
written for every request in production, into Render's retained logs.
Note the root-logger token redactor does NOT cover these assertions --
logger-level filters only apply to records created on that logger, not to
ones propagated up from netsentinel.timing -- so they test the middleware.
"""
import logging
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app import main
from app.main import app
from app.services import supabase_client

client = TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def timing_log(caplog):
    caplog.set_level(logging.INFO, logger="netsentinel.timing")
    return caplog


def timing_lines(caplog):
    return [r.getMessage() for r in caplog.records if r.name == "netsentinel.timing"]


def test_logs_route_template_not_path_ids(timing_log):
    client.get("/api/flows/7c1a9e55-secret-looking-id/score")
    lines = timing_lines(timing_log)
    assert len(lines) == 1
    assert "GET /api/flows/{flow_id}/score 401" in lines[0]
    assert "7c1a9e55" not in lines[0]


def test_query_string_token_never_logged(timing_log):
    client.get("/api/capture/stream?token=eyJhbGciOiJFUzI1NiJ9.SENTINEL.sig")
    lines = timing_lines(timing_log)
    assert len(lines) == 1
    assert "/api/capture/stream" in lines[0]
    assert "SENTINEL" not in lines[0]
    assert "token" not in lines[0]


def test_unmatched_path_is_not_echoed(timing_log):
    client.get("/wp-admin/setup-config.php")
    lines = timing_lines(timing_log)
    assert lines == [lines[0]] and "GET unmatched 404" in lines[0]
    assert "wp-admin" not in lines[0]


def test_render_liveness_checks_are_not_logged(timing_log):
    client.get("/api/health")
    assert timing_lines(timing_log) == []


def test_readiness_is_logged_with_duration(timing_log):
    main._ready_cache.update(at=None, ok=False)
    with patch.object(supabase_client, "get_active_model_version", return_value=None):
        client.get("/api/health/ready")
    main._ready_cache.update(at=None, ok=False)
    (line,) = timing_lines(timing_log)
    method, route, status, ms = line.removeprefix("TIMING ").split()
    assert (method, route, status) == ("GET", "/api/health/ready", "503")
    assert ms.endswith("ms") and float(ms[:-2]) >= 0
