"""Regression tests for the Phase 13 performance fixes.

1. list_flows()'s score lookup is scoped to the actual filtered/sorted
   result set (chunked .in_()), not the whole table.
2. Investigation cache is checked before the flow is re-fetched, and
   before the role/rate-limit gate that only matters on a cache miss.
3. A request declaring an absurd Content-Length is rejected before any
   body is read.

Real end-to-end evidence (actual before/after latency against the
running app) is in docs/PERFORMANCE-NOTES.md; these pin the logic so it
can't silently regress.
"""
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.config import settings
from app.services import supabase_client
from app.services.auth import CurrentUser


# ---------------------------------------------------------------- fix 1
class _FakeInQuery:
    def __init__(self, recorder, known_ids):
        self._recorder = recorder
        self._known_ids = known_ids
        self._values = []

    def select(self, *_a, **_k):
        return self

    def eq(self, *_a, **_k):
        return self

    def in_(self, _field, values):
        self._recorder.append(list(values))
        self._values = values
        return self

    def execute(self):
        data = [
            {"flow_id": v, "anomaly_score": 90.0, "is_anomalous": True, "top_features": []}
            for v in self._values
            if v in self._known_ids
        ]
        return SimpleNamespace(data=data)


class _FakeClient:
    def __init__(self, recorder, known_ids):
        self._recorder = recorder
        self._known_ids = known_ids

    def table(self, _name):
        return _FakeInQuery(self._recorder, self._known_ids)


def test_scores_for_flow_ids_chunks_under_the_safe_batch_size():
    """7 ids at batch_size=3 must produce 3 calls (3+3+1), never one
    giant .in_() -- that's the PostgREST URL/body-size cliff this
    replaces the old whole-table pagination to avoid.
    """
    flow_ids = [f"id-{i}" for i in range(7)]
    calls = []
    with patch.object(supabase_client, "get_client", return_value=_FakeClient(calls, set(flow_ids))):
        result = supabase_client._scores_for_flow_ids("model-x", flow_ids, batch_size=3)

    assert len(calls) == 3
    assert [len(c) for c in calls] == [3, 3, 1]
    assert set().union(*calls) == set(flow_ids)
    assert set(result.keys()) == set(flow_ids)


def test_scores_for_flow_ids_empty_input_makes_no_calls():
    calls = []
    with patch.object(supabase_client, "get_client", return_value=_FakeClient(calls, set())):
        result = supabase_client._scores_for_flow_ids("model-x", [], batch_size=400)
    assert calls == []
    assert result == {}


def test_scores_for_all_paginates_by_range_with_no_id_enumeration():
    """The whole-table path must never call .in_() -- that's the whole
    point of using it only when there's no smaller set to scope to.
    """
    class _FakeRangeQuery:
        def __init__(self, recorder, pages):
            self._recorder = recorder
            self._pages = pages
        def select(self, *_a, **_k):
            return self
        def eq(self, *_a, **_k):
            return self
        def in_(self, *_a, **_k):
            raise AssertionError("_scores_for_all must not call .in_()")
        def range(self, start, end):
            self._recorder.append((start, end))
            idx = len(self._recorder) - 1
            return self
        def execute(self):
            idx = len(self._recorder) - 1
            return SimpleNamespace(data=self._pages[idx])

    class _FakeRangeClient:
        def __init__(self, recorder, pages):
            self._recorder = recorder
            self._pages = pages
        def table(self, _name):
            return _FakeRangeQuery(self._recorder, self._pages)

    # two full pages of 3, then a short final page of 1 -> loop stops
    pages = [
        [{"flow_id": f"id-{i}", "anomaly_score": 1.0, "is_anomalous": False, "top_features": []} for i in range(3)],
        [{"flow_id": f"id-{i}", "anomaly_score": 1.0, "is_anomalous": False, "top_features": []} for i in range(3, 6)],
        [{"flow_id": "id-6", "anomaly_score": 1.0, "is_anomalous": False, "top_features": []}],
    ]
    calls = []
    with patch.object(supabase_client, "get_client", return_value=_FakeRangeClient(calls, pages)):
        result = supabase_client._scores_for_all("model-x", batch_size=3)

    assert len(calls) == 3
    assert len(result) == 7


def test_scores_for_flow_ids_never_exceeds_documented_safe_ceiling():
    """400 was chosen with real margin below PostgREST's confirmed
    ~600-id failure point -- pin the default so it can't silently creep
    back up toward that cliff.
    """
    import inspect
    sig = inspect.signature(supabase_client._scores_for_flow_ids)
    assert sig.parameters["batch_size"].default <= 500


# ---------------------------------------------------------------- fix 2
def _investigate_module():
    from app.routers import investigate
    return investigate


def test_cached_investigation_skips_flow_refetch_role_check_and_rate_limit():
    """A cache hit must return immediately -- no flow re-fetch, no role
    gate, no rate-limit charge -- even for fetch=true from a viewer, who
    would otherwise be refused. Before this fix, the full flow lookup
    (and the role/rate-limit checks) ran unconditionally first, costing
    ~3 extra round-trips (measured: ~800ms vs ~200ms) on every cache hit,
    and silently burning a rate-limit token for an LLM call that was
    never going to happen.
    """
    investigate = _investigate_module()
    fake_row = {
        "classification": {}, "retrieved_chunks": [], "investigation": {}, "self_check": {},
        "classify_model": "m1", "explain_model": "m2", "self_check_model": "m3",
        "fetched_at": "2026-01-01T00:00:00Z",
    }
    viewer = CurrentUser(id="u1", email="viewer@example.com", role="viewer")

    with patch.object(investigate.supabase_client, "get_cached_investigation", return_value=fake_row), \
         patch.object(investigate.supabase_client, "get_flow_for_investigation") as mock_flow, \
         patch.object(investigate.rate_limit, "enforce") as mock_rl:
        result = investigate.investigate_flow(
            flow_id="flow-123",
            body=investigate.InvestigateRequest(fetch=True),
            request=MagicMock(),
            current_user=viewer,
        )

    assert result["cached"] is True
    mock_flow.assert_not_called()
    mock_rl.assert_not_called()


def test_uncached_fetch_still_enforces_role_gate():
    """Regression guard: reordering must not weaken the real gate on an
    actual cache MISS -- a viewer with fetch=true and nothing cached
    must still be refused before any flow lookup happens.
    """
    investigate = _investigate_module()
    viewer = CurrentUser(id="u1", email="viewer@example.com", role="viewer")

    with patch.object(investigate.supabase_client, "get_cached_investigation", return_value=None), \
         patch.object(investigate.supabase_client, "get_flow_for_investigation") as mock_flow:
        with pytest.raises(HTTPException) as excinfo:
            investigate.investigate_flow(
                flow_id="flow-123",
                body=investigate.InvestigateRequest(fetch=True),
                request=MagicMock(),
                current_user=viewer,
            )

    assert excinfo.value.status_code == 403
    mock_flow.assert_not_called()


def test_uncached_peek_still_reaches_the_flagged_flow_gate():
    """fetch=false with nothing cached must still do the real lookup and
    the is_anomalous gate -- only the CACHED path was reordered.
    """
    investigate = _investigate_module()
    viewer = CurrentUser(id="u1", email="viewer@example.com", role="viewer")

    with patch.object(investigate.supabase_client, "get_cached_investigation", return_value=None), \
         patch.object(investigate.supabase_client, "get_flow_for_investigation", return_value=None) as mock_flow:
        with pytest.raises(HTTPException) as excinfo:
            investigate.investigate_flow(
                flow_id="flow-123",
                body=investigate.InvestigateRequest(fetch=False),
                request=MagicMock(),
                current_user=viewer,
            )

    assert excinfo.value.status_code == 404
    mock_flow.assert_called_once_with("flow-123")


# ---------------------------------------------------------------- fix 3
def test_oversized_content_length_rejected_before_body_read():
    from app.main import app
    client = TestClient(app)
    huge = settings.max_request_body_bytes + 1
    r = client.post("/api/auth/login-event", headers={"content-length": str(huge)})
    assert r.status_code == 413


def test_normal_sized_request_is_not_affected():
    from app.main import app
    client = TestClient(app)
    r = client.get("/api/health")
    assert r.status_code == 200


def test_non_numeric_content_length_does_not_crash_the_middleware():
    from app.main import app
    client = TestClient(app)
    r = client.get("/api/health", headers={"content-length": "not-a-number"})
    assert r.status_code == 200
