"""Regression tests for the two defects found during pre-deployment
planning and fixed before the readiness pass ran.

D1 - the `global` rate-limit bucket was only ever charged inside
     enforce() on three spend endpoints, so it protected nothing else
     despite the docs claiming otherwise; the `capture` bucket was
     declared but never wired to anything.
D2 - upsert_flow_verdict() read-then-wrote, so two concurrent first-time
     verdicts could both include created_by and the loser's write
     silently re-attributed the row.

Full evidence lives in docs/PRE-DEPLOYMENT-READINESS.md.
"""
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from app.services import rate_limit, supabase_client


# ---------------------------------------------------------------- D1
def test_enforce_charges_only_its_own_bucket_not_global():
    """global is charged centrally in auth now, so enforce() must not
    also charge it -- otherwise every spend request costs two global
    hits and the cap is silently half what it says.
    """
    rate_limit.reset()
    rate_limit.enforce("upload", "user-1")

    assert len(rate_limit._hits[("upload", "user-1")]) == 1
    assert ("global", "user-1") not in rate_limit._hits
    rate_limit.reset()


def test_global_bucket_is_charged_for_every_authenticated_request():
    """The point of D1's fix: the global cap must apply to ordinary read
    endpoints too, not just the three that call enforce(). It is charged
    in user_from_raw_token(), which both the header and the SSE
    `?token=` auth paths pass through.
    """
    from app.services import auth

    rate_limit.reset()
    claims = {"sub": "user-1", "email": "u@example.com"}
    with patch.object(auth, "_decode_token", return_value=claims), \
         patch.object(auth.supabase_client, "get_user_profile", return_value={"role": "viewer"}):
        auth.user_from_raw_token("token-abc")

    assert len(rate_limit._hits[("global", "user-1")]) == 1
    rate_limit.reset()


def test_global_cap_rejects_before_costing_a_database_lookup():
    """A caller already over the cap should get 429 without paying for a
    Supabase round-trip to fetch their profile.
    """
    from app.services import auth

    rate_limit.reset()
    max_requests, _ = rate_limit.LIMITS["global"]
    for _ in range(max_requests):
        rate_limit.enforce("global", "user-1")

    claims = {"sub": "user-1", "email": "u@example.com"}
    with patch.object(auth, "_decode_token", return_value=claims), \
         patch.object(auth.supabase_client, "get_user_profile") as mock_profile:
        with pytest.raises(HTTPException) as excinfo:
            auth.user_from_raw_token("token-abc")

    assert excinfo.value.status_code == 429
    mock_profile.assert_not_called()
    rate_limit.reset()


def test_capture_endpoints_actually_enforce_the_capture_bucket():
    """The `capture` bucket existed in LIMITS from Phase 12 but no router
    ever called it. Pin the wiring, not just the constant.
    """
    import inspect

    from app.routers import capture

    start_src = inspect.getsource(capture.start_capture)
    stop_src = inspect.getsource(capture.stop_capture)
    assert 'rate_limit.enforce("capture"' in start_src
    assert 'rate_limit.enforce("capture"' in stop_src


def test_dead_dependency_factory_is_gone():
    """`rate_limit()` was a dependency factory no router used, and its
    import of auth was what forced the global bucket to live in the wrong
    place. It should not come back.
    """
    assert not hasattr(rate_limit, "rate_limit")


# ---------------------------------------------------------------- D4
def test_jwks_fetch_failure_is_503_not_401():
    """A key-server outage is not the caller's fault. Returning 401 sends
    a user with a perfectly valid session off to re-authenticate, which
    cannot fix a server-side connectivity problem.
    """
    import jwt as jwtlib

    from app.services import auth

    boom = jwtlib.PyJWKClientConnectionError("Fail to fetch data from the url")
    fake_client = MagicMock()
    fake_client.get_signing_key_from_jwt.side_effect = boom

    with patch.object(auth, "_jwks_client", return_value=fake_client):
        with pytest.raises(HTTPException) as excinfo:
            auth._decode_token("any.token.here")

    assert excinfo.value.status_code == 503
    assert "temporarily unavailable" in excinfo.value.detail.lower()


def test_unknown_signing_key_stays_401():
    """PyJWKClientConnectionError is a SUBCLASS of PyJWKClientError, so the
    ordering of the except blocks matters: a key set we successfully
    fetched that simply has no matching kid is a bad token, not an
    outage, and must stay 401.
    """
    import jwt as jwtlib

    from app.services import auth

    no_kid = jwtlib.PyJWKClientError("Unable to find a signing key that matches")
    fake_client = MagicMock()
    fake_client.get_signing_key_from_jwt.side_effect = no_kid

    with patch.object(auth, "_jwks_client", return_value=fake_client):
        with pytest.raises(HTTPException) as excinfo:
            auth._decode_token("any.token.here")

    assert excinfo.value.status_code == 401


def test_expired_token_still_401():
    import jwt as jwtlib

    from app.services import auth

    fake_client = MagicMock()
    fake_client.get_signing_key_from_jwt.return_value = SimpleNamespace(key="k")
    # _decode_token builds `issuer=f"{_project_url()}/auth/v1"` as a plain
    # function argument, which Python evaluates eagerly even though
    # jwt.decode itself is mocked below -- so without a real SUPABASE_URL
    # (e.g. in CI, with no .env) this test would crash on _project_url()'s
    # own 500 before jwt.decode ever ran. Mocked here so the test verifies
    # the actual thing it's about (401 vs 503), independent of env config.
    with patch.object(auth, "_jwks_client", return_value=fake_client), \
         patch.object(auth, "_project_url", return_value="https://project.supabase.co"), \
         patch.object(jwtlib, "decode", side_effect=jwtlib.ExpiredSignatureError("expired")):
        with pytest.raises(HTTPException) as excinfo:
            auth._decode_token("any.token.here")

    assert excinfo.value.status_code == 401


def test_jwks_cache_and_timeout_are_tuned_away_from_defaults():
    """Pin the two constants: the 300s default meant the network path ran
    every 5 minutes, and the 30s default let one blip block a request for
    half a minute.
    """
    from app.services import auth

    assert auth.JWKS_CACHE_SECONDS >= 900
    assert auth.JWKS_FETCH_TIMEOUT_SECONDS <= 15


# ---------------------------------------------------------------- D5
def test_query_token_is_redacted_from_log_records():
    """The SSE endpoint takes its bearer token in the URL, and uvicorn's
    access logger writes the full request line -- so without this filter a
    live credential lands in the log in plaintext.
    """
    import logging as _logging

    from app.main import _RedactQueryTokenFilter

    f = _RedactQueryTokenFilter()
    secret = "eyJhbGciOiJFUzI1NiIsImtpZCI6IjY1MTdlOTYzIiwidHlwIjoiSldUIn0.abc.def"
    rec = _logging.LogRecord("uvicorn.access", _logging.INFO, __file__, 1, "%s - \"%s %s %s\" %d", None, None)
    rec.args = ("127.0.0.1:1", "GET", f"/api/capture/stream?token={secret}", "HTTP/1.1", 200)

    f.filter(rec)
    joined = " ".join(str(a) for a in rec.args)
    assert secret not in joined
    assert "token=[REDACTED]" in joined
    # the rest of the request line must survive -- this is a redaction, not a drop
    assert "/api/capture/stream" in joined
    assert "200" in joined


def test_redaction_leaves_unrelated_records_untouched():
    import logging as _logging

    from app.main import _RedactQueryTokenFilter

    f = _RedactQueryTokenFilter()
    rec = _logging.LogRecord("uvicorn.access", _logging.INFO, __file__, 1, "%s - \"%s %s %s\" %d", None, None)
    rec.args = ("127.0.0.1:1", "GET", "/api/flows?source_file=capture1.pcapng", "HTTP/1.1", 200)
    f.filter(rec)
    assert "capture1.pcapng" in " ".join(str(a) for a in rec.args)


# ---------------------------------------------------------------- D2
def _fake_client(insert_raises=None, insert_data=None, update_data=None, recorder=None):
    class _Q:
        def __init__(self):
            self._payload = None
        def insert(self, payload):
            self._payload = payload
            if recorder is not None:
                recorder["insert_payload"] = payload
            if insert_raises is not None:
                raise insert_raises
            return self
        def update(self, payload):
            self._payload = payload
            if recorder is not None:
                recorder["update_payload"] = payload
            return self
        def select(self, *_a, **_k):
            return self
        def eq(self, *_a, **_k):
            return self
        def limit(self, *_a, **_k):
            return self
        def execute(self):
            if recorder is not None and "update_payload" in recorder and self._payload is recorder.get("update_payload"):
                return SimpleNamespace(data=update_data or [])
            return SimpleNamespace(data=insert_data or [])

    class _C:
        def table(self, _name):
            return _Q()

    return _C()


def test_first_writer_inserts_and_owns_created_by():
    row = {"flow_id": "f1", "verdict": "benign", "created_by": "a@x.com"}
    with patch.object(supabase_client, "get_client",
                      return_value=_fake_client(insert_data=[row])):
        result, previous = supabase_client.upsert_flow_verdict("f1", "benign", None, "a@x.com")
    assert previous is None
    assert result["created_by"] == "a@x.com"


def test_concurrent_loser_updates_without_touching_created_by():
    """The core of D2: when the insert loses the PK race, the fallback
    UPDATE must not contain created_by, or it re-attributes the row.
    """
    dup = Exception('duplicate key value violates unique constraint "flow_verdicts_pkey"')
    recorder = {}
    previous_row = {"flow_id": "f1", "verdict": "true_positive", "created_by": "first@x.com"}

    with patch.object(supabase_client, "get_client",
                      return_value=_fake_client(insert_raises=dup, update_data=[previous_row], recorder=recorder)), \
         patch.object(supabase_client, "get_flow_verdict", return_value=previous_row):
        _result, previous = supabase_client.upsert_flow_verdict("f1", "benign", None, "second@x.com")

    assert "created_by" not in recorder["update_payload"]
    assert "created_at" not in recorder["update_payload"]
    assert recorder["update_payload"]["updated_by"] == "second@x.com"
    # The loser must still SEE a previous row, so the audit entry records
    # the overwrite -- the old code reported previous=None here.
    assert previous == previous_row


def test_non_duplicate_write_error_is_raised_not_swallowed():
    """A genuine failure must not be quietly converted into an update."""
    boom = Exception("connection reset by peer")
    with patch.object(supabase_client, "get_client",
                      return_value=_fake_client(insert_raises=boom)):
        with pytest.raises(Exception, match="connection reset"):
            supabase_client.upsert_flow_verdict("f1", "benign", None, "a@x.com")


@pytest.mark.parametrize("exc,expected", [
    (Exception('duplicate key value violates unique constraint'), True),
    (Exception("SQLSTATE 23505"), True),
    (Exception("connection reset by peer"), False),
    (Exception("permission denied"), False),
])
def test_duplicate_key_classification(exc, expected):
    assert supabase_client._is_duplicate_key_error(exc) is expected


def test_duplicate_key_detected_from_structured_apierror():
    """postgrest-py surfaces a dict rather than a typed exception."""
    exc = Exception({"code": "23505", "message": "duplicate key"})
    assert supabase_client._is_duplicate_key_error(exc) is True
