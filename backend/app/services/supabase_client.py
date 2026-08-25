from datetime import datetime
from functools import lru_cache

from supabase import Client, create_client

from app.config import settings

FLOWS_TABLE = "flows"
FLOW_FEATURES_TABLE = "flow_features"
HOST_PROFILES_TABLE = "host_profiles"
MODEL_VERSIONS_TABLE = "model_versions"
FLOW_SCORES_TABLE = "flow_scores"


@lru_cache
def get_client() -> Client:
    if not settings.supabase_url or not settings.supabase_service_role_key:
        raise RuntimeError(
            "SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY are not set in backend/.env — "
            "create a Supabase project and fill these in before uploading a PCAP."
        )
    url = settings.supabase_url
    if not url.startswith("http"):
        url = f"https://{url}"
    return create_client(url, settings.supabase_service_role_key)


def _iso(value):
    return value.isoformat() if isinstance(value, datetime) else value


def insert_flows(flows: list[dict]) -> list[dict]:
    if not flows:
        return []

    rows = [
        {**flow, "started_at": _iso(flow["started_at"]), "ended_at": _iso(flow["ended_at"])}
        for flow in flows
    ]
    result = get_client().table(FLOWS_TABLE).insert(rows).execute()
    return result.data


def insert_flow_features(features: list[dict]) -> list[dict]:
    """Each row must include flow_id. Upsert (not plain insert) so this is
    safe to re-run for a flow that already has a feature row, since
    flow_id is the table's primary key.
    """
    if not features:
        return []
    result = get_client().table(FLOW_FEATURES_TABLE).upsert(features, on_conflict="flow_id").execute()
    return result.data


def replace_host_profiles(profiles: list[dict]) -> list[dict]:
    """Full recompute, not an incremental update -- deletes everything and
    inserts the freshly computed set. See host_profiles.py for why that's
    the right call at this data scale.
    """
    client = get_client()
    client.table(HOST_PROFILES_TABLE).delete().gte("flow_count", 0).execute()
    if not profiles:
        return []
    rows = [
        {**p, "first_seen": _iso(p["first_seen"]), "last_seen": _iso(p["last_seen"])}
        for p in profiles
    ]
    result = client.table(HOST_PROFILES_TABLE).insert(rows).execute()
    return result.data


def list_flows(limit: int = 500) -> list[dict]:
    """Capped, most-recent-first -- for display (the frontend table). Not
    safe to use for aggregates: see list_all_flows().

    Anomaly scores from the latest primary model are merged in where they
    exist; flows scored by no model simply come back without score fields,
    so the table still renders before any model has been trained.
    """
    rows = [
        _flatten_features(row)
        for row in (
            get_client()
            .table(FLOWS_TABLE)
            .select("*, flow_features(*)")
            .order("started_at", desc=True)
            .limit(limit)
            .execute()
        ).data
    ]

    version = get_active_model_version()
    if not version:
        return rows

    scores = (
        get_client()
        .table(FLOW_SCORES_TABLE)
        .select("flow_id, anomaly_score, is_anomalous, top_features")
        .eq("model_version_id", version["id"])
        .in_("flow_id", [r["id"] for r in rows])
        .execute()
    ).data
    by_flow = {s["flow_id"]: s for s in scores}

    for row in rows:
        score = by_flow.get(row["id"])
        if score:
            row["anomaly_score"] = score["anomaly_score"]
            row["is_anomalous"] = score["is_anomalous"]
            row["top_features"] = score["top_features"]
    return rows


def list_flow_scores(flow_id: str) -> list[dict]:
    """All model versions' scores for one flow -- the detail view."""
    result = (
        get_client()
        .table(FLOW_SCORES_TABLE)
        .select("*, model_versions(algorithm, variant, threshold, created_at)")
        .eq("flow_id", flow_id)
        .execute()
    )
    return result.data


def list_all_flows(batch_size: int = 1000) -> list[dict]:
    """Every flow, paginated -- for full aggregates (host_profiles) where
    silently dropping rows past a display cap would produce wrong stats,
    not just an incomplete list. No feature embedding: aggregate math only
    needs the raw flow columns.
    """
    client = get_client()
    rows: list[dict] = []
    start = 0
    while True:
        page = (
            client.table(FLOWS_TABLE)
            .select("*")
            .range(start, start + batch_size - 1)
            .execute()
        ).data
        rows.extend(page)
        if len(page) < batch_size:
            break
        start += batch_size
    return rows


def list_all_flows_with_features(batch_size: int = 1000) -> list[dict]:
    """Every flow joined to its Phase 2 feature row, flattened, paginated.

    Used by training, which must see the whole table -- a display cap here
    would silently train on a subset and produce quietly wrong models.
    """
    client = get_client()
    rows: list[dict] = []
    start = 0
    while True:
        page = (
            client.table(FLOWS_TABLE)
            .select("*, flow_features(*)")
            .range(start, start + batch_size - 1)
            .execute()
        ).data
        rows.extend(_flatten_features(row) for row in page)
        if len(page) < batch_size:
            break
        start += batch_size
    return rows


def insert_model_version(version: dict) -> dict:
    """Insert-only, never updated -- a model is never silently replaced.
    Retraining adds a new row; old versions and their scores survive.
    """
    result = get_client().table(MODEL_VERSIONS_TABLE).insert(version).execute()
    return result.data[0] if result.data else {}


def list_model_versions() -> list[dict]:
    result = (
        get_client()
        .table(MODEL_VERSIONS_TABLE)
        .select("*")
        .order("created_at", desc=True)
        .execute()
    )
    return result.data


def get_model_version(version_id: str) -> dict | None:
    result = (
        get_client()
        .table(MODEL_VERSIONS_TABLE)
        .select("*")
        .eq("id", version_id)
        .execute()
    )
    return result.data[0] if result.data else None


def insert_flow_scores(rows: list[dict], batch_size: int = 500) -> int:
    """Upsert on (flow_id, model_version_id) so re-scoring the same flows
    with the same model version is idempotent rather than a PK violation.
    """
    if not rows:
        return 0
    client = get_client()
    written = 0
    for start in range(0, len(rows), batch_size):
        chunk = rows[start:start + batch_size]
        result = (
            client.table(FLOW_SCORES_TABLE)
            .upsert(chunk, on_conflict="flow_id,model_version_id")
            .execute()
        )
        written += len(result.data or [])
    return written


# Fallback only. The shipped model is whichever model_versions row has
# is_active = true -- the database is the single source of truth, and a
# partial unique index there guarantees at most one. These constants are
# used only if nothing has been marked active yet, so a fresh install
# still renders something sensible instead of failing.
DISPLAY_ALGORITHM = "isolation_forest"
DISPLAY_VARIANT = "behavioural_only"


def get_active_model_version() -> dict | None:
    """The model actually shipped to users.

    Selection is explicit and recorded in the database, never inferred
    from insertion order. Two algorithms can score the very same flow
    completely differently (see docs/ML-MODEL-NOTES.md), so an unlabelled
    score is genuinely ambiguous -- an analyst has to be able to tell
    whose judgement they are acting on.
    """
    client = get_client()
    active = client.table(MODEL_VERSIONS_TABLE).select("*").eq("is_active", True).limit(1).execute()
    if active.data:
        return active.data[0]

    fallback = (
        client.table(MODEL_VERSIONS_TABLE)
        .select("*")
        .eq("algorithm", DISPLAY_ALGORITHM)
        .eq("variant", DISPLAY_VARIANT)
        .order("created_at", desc=True)
        .order("id", desc=True)
        .limit(1)
        .execute()
    )
    return fallback.data[0] if fallback.data else None


def set_active_model_version(version_id: str) -> dict | None:
    """Marks one version active, clearing any previous one.

    Deactivate-then-activate, because the partial unique index refuses to
    let two rows be active simultaneously.
    """
    client = get_client()
    client.table(MODEL_VERSIONS_TABLE).update({"is_active": False}).eq("is_active", True).execute()
    result = (
        client.table(MODEL_VERSIONS_TABLE)
        .update({"is_active": True})
        .eq("id", version_id)
        .execute()
    )
    return result.data[0] if result.data else None


def _flatten_features(row: dict) -> dict:
    """PostgREST embeds the related flow_features row under a nested key.
    Flattened here so the API response stays flat -- callers (the
    frontend) shouldn't need to know about the embedding relationship.
    """
    embedded = row.pop("flow_features", None)
    if isinstance(embedded, list):
        embedded = embedded[0] if embedded else None
    if embedded:
        embedded.pop("flow_id", None)
        row.update(embedded)
    return row
