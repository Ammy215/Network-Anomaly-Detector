"""/api/health/ready -- the readiness check the external uptime monitor hits.

/api/health only proves the process is up. These pin that /ready actually
fails on the conditions that leave the process up but the app broken, and
that it never tells an unauthenticated caller which one it was.
"""
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app import main
from app.main import app
from app.services import supabase_client
from app.services.ml.scoring import resolve_artifact_path

client = TestClient(app)


@pytest.fixture(autouse=True)
def fresh_cache():
    main._ready_cache.update(at=None, ok=False)
    yield
    main._ready_cache.update(at=None, ok=False)


@pytest.fixture
def artifact(tmp_path):
    path = tmp_path / "bundle.joblib"
    path.write_bytes(b"not loaded by the readiness check")
    return str(path)


def get_ready(version=None, raises=None):
    kwargs = {"side_effect": raises} if raises else {"return_value": version}
    with patch.object(supabase_client, "get_active_model_version", **kwargs) as mocked:
        return client.get("/api/health/ready"), mocked


def test_ok_when_database_reachable_and_artifact_present(artifact):
    r, _ = get_ready({"id": "v1", "artifact_path": artifact})
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_degraded_when_database_unreachable():
    r, _ = get_ready(raises=ConnectionError("paused project"))
    assert r.status_code == 503
    assert r.json() == {"status": "degraded"}


def test_degraded_when_no_active_model():
    r, _ = get_ready(None)
    assert r.status_code == 503


def test_degraded_when_artifact_missing_on_disk(tmp_path):
    r, _ = get_ready({"id": "v1", "artifact_path": str(tmp_path / "gone.joblib")})
    assert r.status_code == 503


def test_failure_detail_is_logged_not_returned(caplog):
    r, _ = get_ready(raises=RuntimeError("https://example.supabase.co key=sb_secret_abc"))
    assert r.status_code == 503
    assert "sb_secret_abc" not in r.text
    assert "supabase" not in r.text.lower()
    assert "database check failed" in caplog.text


def test_result_is_cached_so_callers_cannot_drive_database_load(artifact):
    version = {"id": "v1", "artifact_path": artifact}
    with patch.object(supabase_client, "get_active_model_version", return_value=version) as mocked:
        for _ in range(5):
            assert client.get("/api/health/ready").status_code == 200
    assert mocked.call_count == 1


def test_cache_expires(artifact):
    # Ages the cached entry rather than patching time.monotonic, which is
    # the global time module's -- anyio's thread pool calls it too.
    version = {"id": "v1", "artifact_path": artifact}
    with patch.object(supabase_client, "get_active_model_version", return_value=version) as mocked:
        client.get("/api/health/ready")
        main._ready_cache["at"] -= main.READY_CACHE_SECONDS + 1
        client.get("/api/health/ready")
    assert mocked.call_count == 2


def test_liveness_endpoint_still_never_touches_the_database():
    # Render's internal checker hits /api/health every ~5s.
    with patch.object(supabase_client, "get_active_model_version") as mocked:
        assert client.get("/api/health").status_code == 200
    mocked.assert_not_called()


def test_windows_style_artifact_path_resolves_like_scoring_does(artifact):
    # The production bug this shared resolver exists for: a model trained
    # on Windows stores a backslash path the Linux container must still find.
    windows_style = artifact.replace("/", "\\")
    assert resolve_artifact_path(windows_style).exists()
