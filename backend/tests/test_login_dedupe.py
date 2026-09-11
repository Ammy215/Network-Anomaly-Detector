"""One audit login row per Supabase session, however often the client asks.

supabase-js emits SIGNED_IN on every tab refocus and in every open tab, so
/api/auth/login-event is called many times per real sign-in (a live
two-tab test wrote 9 rows for zero sign-ins). The dedupe itself is a
partial unique index in Postgres -- these tests pin the application side:
that a unique violation reads as "already recorded", that nothing else is
swallowed, and that the session_id really comes from the verified token.
"""
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from postgrest.exceptions import APIError

from app.services import auth, supabase_client
from app.services.auth import CurrentUser, get_current_user, log_login, user_from_raw_token

SESSION = "0b6f1c9e-4a2d-4c1b-9d7e-2f3a8b5c6d10"
USER = CurrentUser(id="user-1", email="analyst@example.com", role="analyst", session_id=SESSION)


def unique_violation():
    return APIError({"code": "23505", "message": "duplicate key value violates unique constraint "
                     "\"audit_log_login_session_uniq\""})


class FakeAuditTable:
    """Behaves like the partial unique index: a second login row for the
    same session_id is rejected with SQLSTATE 23505."""

    def __init__(self):
        self.rows = []
        self._pending = None

    def table(self, name):
        assert name == supabase_client.AUDIT_LOG_TABLE
        return self

    def insert(self, row):
        self._pending = row
        return self

    def execute(self):
        row = self._pending
        if row["action"] == "login" and row.get("session_id") and any(
            r["action"] == "login" and r.get("session_id") == row["session_id"] for r in self.rows
        ):
            raise unique_violation()
        self.rows.append(row)
        return MagicMock(data=[row])


@pytest.fixture
def fake_db():
    db = FakeAuditTable()
    with patch.object(supabase_client, "get_client", return_value=db):
        yield db


def fake_request():
    req = MagicMock()
    req.client.host = "198.51.100.20"
    req.headers = {}
    return req


# ------------------------------------------------------ insert_login_event
def test_first_login_for_a_session_is_recorded(fake_db):
    assert supabase_client.insert_login_event("user-1", "a@example.com", SESSION, "198.51.100.20") is True
    (row,) = fake_db.rows
    assert row["action"] == "login" and row["session_id"] == SESSION


def test_repeat_calls_for_same_session_write_nothing(fake_db):
    # The live two-tab test: 9 calls, one session.
    results = [supabase_client.insert_login_event("user-1", "a@example.com", SESSION, None) for _ in range(9)]
    assert results == [True] + [False] * 8
    assert len(fake_db.rows) == 1


def test_a_new_sign_in_is_a_new_session_and_is_recorded(fake_db):
    supabase_client.insert_login_event("user-1", "a@example.com", SESSION, None)
    assert supabase_client.insert_login_event("user-1", "a@example.com", "another-session", None) is True
    assert len(fake_db.rows) == 2


def test_errors_other_than_unique_violation_are_not_swallowed():
    client = MagicMock()
    client.table.return_value.insert.return_value.execute.side_effect = APIError(
        {"code": "42703", "message": "column \"session_id\" does not exist"}
    )
    with patch.object(supabase_client, "get_client", return_value=client):
        with pytest.raises(APIError):
            supabase_client.insert_login_event("user-1", "a@example.com", SESSION, None)


# --------------------------------------------------------------- log_login
def test_log_login_uses_session_dedupe(fake_db):
    assert log_login(fake_request(), USER) is True
    assert log_login(fake_request(), USER) is False
    assert len(fake_db.rows) == 1
    assert fake_db.rows[0]["ip_address"] == "198.51.100.20"


def test_token_without_session_id_still_records_rather_than_dropping():
    no_session = USER.model_copy(update={"session_id": None})
    with patch.object(auth, "log_audit") as legacy, \
         patch.object(supabase_client, "insert_login_event") as deduped:
        assert log_login(fake_request(), no_session) is True
    legacy.assert_called_once()
    deduped.assert_not_called()


def test_database_failure_is_an_audit_gap_warning_not_a_500(caplog):
    with patch.object(supabase_client, "insert_login_event", side_effect=RuntimeError("db down")):
        assert log_login(fake_request(), USER) is False
    assert "AUDIT GAP" in caplog.text


# ------------------------------------------------- session_id provenance
def _user_from_payload(payload):
    with patch.object(auth, "_decode_token", return_value=payload), \
         patch.object(auth.rate_limit, "enforce"), \
         patch.object(supabase_client, "get_user_profile", return_value={"role": "analyst"}):
        return user_from_raw_token("verified-elsewhere")


def test_session_id_is_taken_from_the_verified_token():
    user = _user_from_payload({"sub": "user-1", "email": "a@example.com", "session_id": SESSION})
    assert user.session_id == SESSION


@pytest.mark.parametrize("claim", [None, "", 12345, ["a"], {"id": "x"}])
def test_missing_or_non_string_session_claim_becomes_none(claim):
    payload = {"sub": "user-1", "email": "a@example.com"}
    if claim is not None:
        payload["session_id"] = claim
    assert _user_from_payload(payload).session_id is None


def test_session_id_is_not_exposed_by_auth_me():
    from app.main import app
    app.dependency_overrides[get_current_user] = lambda: USER
    try:
        body = TestClient(app).get("/api/auth/me").json()
    finally:
        app.dependency_overrides.clear()
    assert body == {"id": "user-1", "email": "analyst@example.com", "role": "analyst"}
