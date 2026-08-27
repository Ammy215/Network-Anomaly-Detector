from datetime import datetime, timezone
from functools import lru_cache

import httpx
from supabase import Client, ClientOptions, create_client

from app.config import settings

FLOWS_TABLE = "flows"
FLOW_FEATURES_TABLE = "flow_features"
HOST_PROFILES_TABLE = "host_profiles"
MODEL_VERSIONS_TABLE = "model_versions"
FLOW_SCORES_TABLE = "flow_scores"
FLOW_VERDICTS_TABLE = "flow_verdicts"
IP_ENRICHMENTS_TABLE = "ip_enrichments"
INVESTIGATIONS_TABLE = "investigations"

# Mirrors the flow_verdicts.verdict CHECK constraint in supabase_schema.sql
# -- kept here too so the API can reject an invalid value with a clean 422
# instead of a raw Postgres constraint-violation error.
VALID_VERDICTS = ("true_positive", "false_positive", "benign", "unknown")


@lru_cache
def get_client() -> Client:
    """One shared client for the whole process (safe: postgrest-py's HTTP
    client handles its own connection pooling internally).

    HTTP/2 is explicitly disabled here. postgrest-py defaults to
    `httpx.Client(http2=True)`, which multiplexes every request over one
    shared TCP connection -- under real concurrent load (e.g. a page load
    firing /api/flows, /api/verdicts/summary, and /api/flows/source-files
    in parallel, each served in its own FastAPI threadpool thread) that
    connection was observed getting reset mid-request
    (`httpx.RemoteProtocolError: ConnectionTerminated`), 500ing every
    request sharing it. HTTP/1.1 instead pools several independent
    connections, so concurrent requests can't take each other down.
    """
    if not settings.supabase_url or not settings.supabase_service_role_key:
        raise RuntimeError(
            "SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY are not set in backend/.env — "
            "create a Supabase project and fill these in before uploading a PCAP."
        )
    url = settings.supabase_url
    if not url.startswith("http"):
        url = f"https://{url}"
    options = ClientOptions(httpx_client=httpx.Client(http2=False))
    return create_client(url, settings.supabase_service_role_key, options=options)


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


SORT_OPTIONS = ("started_desc", "score_desc", "score_asc")


def list_source_files(batch_size: int = 1000) -> list[str]:
    """Distinct source_file values across every flow, for a filter dropdown."""
    client = get_client()
    seen: set[str] = set()
    start = 0
    while True:
        page = (
            client.table(FLOWS_TABLE)
            .select("source_file")
            .range(start, start + batch_size - 1)
            .execute()
        ).data
        seen.update(row["source_file"] for row in page)
        if len(page) < batch_size:
            break
        start += batch_size
    return sorted(seen)


def _scores_for_model(model_version_id: str, batch_size: int = 1000) -> dict[str, dict]:
    """Every score row for one model, paginated and keyed by flow_id."""
    client = get_client()
    by_flow: dict[str, dict] = {}
    start = 0
    while True:
        page = (
            client.table(FLOW_SCORES_TABLE)
            .select("flow_id, anomaly_score, is_anomalous, top_features")
            .eq("model_version_id", model_version_id)
            .range(start, start + batch_size - 1)
            .execute()
        ).data
        by_flow.update({row["flow_id"]: row for row in page})
        if len(page) < batch_size:
            break
        start += batch_size
    return by_flow


def list_flows(limit: int = 500, source_file: str | None = None, sort: str = "started_desc") -> list[dict]:
    """Capped, most-recent-first by default -- for display (the frontend
    table). Not safe to use for aggregates: see list_all_flows().

    `source_file` and `sort` exist so an analyst can actually find a
    specific flow (e.g. for verdict testing) instead of only ever seeing
    the newest 500 -- a single capture can easily have 1000+ flows sitting
    entirely outside that window. Filtering or sorting by score therefore
    searches a wider slice than the plain default view; this is a
    deliberately simple mechanism, not real server-side pagination (that's
    Phase 8's job).

    Anomaly scores from the active model are merged in where they exist;
    flows scored by no model simply come back without score fields, so
    the table still renders before any model has been trained.
    """
    needs_wide_search = bool(source_file) or sort in ("score_desc", "score_asc")
    client = get_client()

    if needs_wide_search:
        # Supabase enforces a server-side max-rows cap (1000 here)
        # regardless of what `.limit()` asks for -- confirmed: a single
        # 3000-row request for a 1039-row capture silently came back with
        # exactly 1000. Paginating with `.range()` is what actually gets
        # every matching row, same pattern as list_all_flows().
        rows = []
        start = 0
        batch_size = 1000
        while True:
            query = client.table(FLOWS_TABLE).select("*, flow_features(*), flow_verdicts(*)")
            if source_file:
                query = query.eq("source_file", source_file)
            page = (
                query.order("started_at", desc=True)
                .range(start, start + batch_size - 1)
                .execute()
            ).data
            rows.extend(_nest_verdict(_flatten_features(row)) for row in page)
            if len(page) < batch_size:
                break
            start += batch_size
    else:
        query = client.table(FLOWS_TABLE).select("*, flow_features(*), flow_verdicts(*)")
        query = query.order("started_at", desc=True).limit(limit)
        rows = [_nest_verdict(_flatten_features(row)) for row in query.execute().data]

    version = get_active_model_version()
    if version:
        if needs_wide_search:
            # A filter/score-sort can pull 1000+ flow ids -- as an `.in_()`
            # filter that blows past PostgREST's request-size limit
            # (confirmed: fails above ~600 ids with "JSON could not be
            # generated"). Paginating every score row for the model
            # instead sidesteps the URL/body-size cliff entirely.
            by_flow = _scores_for_model(version["id"])
        else:
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

    if sort == "score_desc":
        rows.sort(key=lambda r: (r.get("anomaly_score") is None, -(r.get("anomaly_score") or 0)))
    elif sort == "score_asc":
        rows.sort(key=lambda r: (r.get("anomaly_score") is None, r.get("anomaly_score") or 0))

    return rows if source_file else rows[:limit]


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


def _nest_verdict(row: dict) -> dict:
    """Unlike flow_features, this is kept as a nested `verdict` object,
    not flattened -- flow_verdicts.created_at would otherwise silently
    overwrite the flow's own created_at (insert timestamp) on the same
    key. `row["verdict"]` is None when no analyst has judged this flow yet.
    """
    embedded = row.pop("flow_verdicts", None)
    if isinstance(embedded, list):
        embedded = embedded[0] if embedded else None
    row["verdict"] = (
        {
            "value": embedded["verdict"],
            "note": embedded.get("note"),
            "created_by": embedded.get("created_by"),
            "created_at": embedded.get("created_at"),
            "updated_at": embedded.get("updated_at"),
        }
        if embedded
        else None
    )
    return row


def flow_exists(flow_id: str) -> bool:
    result = get_client().table(FLOWS_TABLE).select("id").eq("id", flow_id).limit(1).execute()
    return bool(result.data)


def get_flow_with_score(flow_id: str) -> dict | None:
    """One flow's src/dst IPs plus its current is_anomalous flag under
    the active model -- what enrichment needs to gate on "only flagged
    flows" and pick the external IP, without pulling in unrelated
    feature/score fields it has no use for.
    """
    result = (
        get_client()
        .table(FLOWS_TABLE)
        .select("id, src_ip, dst_ip")
        .eq("id", flow_id)
        .execute()
    )
    if not result.data:
        return None
    flow = result.data[0]

    version = get_active_model_version()
    score = (
        get_client()
        .table(FLOW_SCORES_TABLE)
        .select("is_anomalous")
        .eq("flow_id", flow_id)
        .eq("model_version_id", version["id"])
        .execute()
        .data
        if version
        else []
    )
    flow["is_anomalous"] = bool(score[0]["is_anomalous"]) if score else False
    return flow


def upsert_flow_verdict(flow_id: str, verdict: str, note: str | None, created_by: str) -> dict:
    """One row per flow -- upsert on flow_id, so re-marking a flow
    overwrites its existing verdict rather than creating a duplicate.

    `created_at` is deliberately never included in this payload: Postgrest
    only overwrites the columns present in an upsert, so on a re-mark the
    original insert timestamp is left untouched; the column default only
    ever fires on first insert.
    """
    row = {
        "flow_id": flow_id,
        "verdict": verdict,
        "note": note,
        "created_by": created_by,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    result = (
        get_client()
        .table(FLOW_VERDICTS_TABLE)
        .upsert(row, on_conflict="flow_id")
        .execute()
    )
    return result.data[0] if result.data else {}


def get_verdict_summary() -> dict:
    """Counts for the analyst-facing summary panel.

    `missed_by_model` is the count that matters most here: verdict =
    true_positive (the analyst's ground-truth judgement, independent of
    whether the model flagged it) where the active model's is_anomalous
    is false -- i.e. a flow the analyst confirms is genuinely anomalous
    that the model did not flag. This is computed by joining against the
    *current* active model's scores, not a stored snapshot, so it always
    reflects whichever model is shipped right now.
    """
    client = get_client()

    total_flows = (
        client.table(FLOWS_TABLE).select("id", count="exact").limit(1).execute()
    ).count or 0

    verdict_rows = client.table(FLOW_VERDICTS_TABLE).select("flow_id, verdict").execute().data

    counts = {v: 0 for v in VALID_VERDICTS}
    for row in verdict_rows:
        if row["verdict"] in counts:
            counts[row["verdict"]] += 1

    missed_by_model = 0
    tp_flow_ids = [row["flow_id"] for row in verdict_rows if row["verdict"] == "true_positive"]
    if tp_flow_ids:
        active = get_active_model_version()
        if active:
            scores = (
                client.table(FLOW_SCORES_TABLE)
                .select("flow_id, is_anomalous")
                .eq("model_version_id", active["id"])
                .in_("flow_id", tp_flow_ids)
                .execute()
            ).data
            missed_by_model = sum(1 for s in scores if not s["is_anomalous"])

    return {
        **counts,
        "not_verdicted": max(total_flows - len(verdict_rows), 0),
        "missed_by_model": missed_by_model,
        "total_flows": total_flows,
    }


def get_cached_enrichment(ip: str) -> dict | None:
    result = (
        get_client()
        .table(IP_ENRICHMENTS_TABLE)
        .select("*")
        .eq("ip", ip)
        .execute()
    )
    return result.data[0] if result.data else None


def get_flow_for_investigation(flow_id: str) -> dict | None:
    """Everything the Phase 7 LLM pipeline needs about one flow: its own
    columns, Phase 2's derived features, and the active model's score plus
    the existing `top_features` attribution -- reused as the LLM's primary
    evidence rather than recomputed.
    """
    result = (
        get_client()
        .table(FLOWS_TABLE)
        .select("*, flow_features(*)")
        .eq("id", flow_id)
        .execute()
    )
    if not result.data:
        return None
    flow = _flatten_features(result.data[0])

    version = get_active_model_version()
    score = (
        get_client()
        .table(FLOW_SCORES_TABLE)
        .select("anomaly_score, raw_score, is_anomalous, top_features")
        .eq("flow_id", flow_id)
        .eq("model_version_id", version["id"])
        .execute()
        .data
        if version
        else []
    )
    if score:
        flow.update(score[0])
    else:
        flow["is_anomalous"] = False
        flow["anomaly_score"] = None
        flow["top_features"] = []
    return flow


def get_cached_investigation(flow_id: str) -> dict | None:
    result = (
        get_client()
        .table(INVESTIGATIONS_TABLE)
        .select("*")
        .eq("flow_id", flow_id)
        .execute()
    )
    return result.data[0] if result.data else None


def upsert_investigation(flow_id: str, result: dict) -> dict:
    """One investigation per flow -- upsert on flow_id, so re-running
    "Investigate" on the same flow overwrites its prior result rather
    than accumulating history, same pattern as `upsert_enrichment`.
    """
    row = {
        "flow_id": flow_id,
        "classification": result["classification"],
        # Stored in full (not just ids) so a cache hit can still show the
        # analyst the exact chunk text a citation claims to quote, without
        # a second round-trip to Chroma.
        "retrieved_chunks": result["retrieved_chunks"],
        "investigation": result["investigation"],
        "self_check": result["self_check"],
        "classify_model": result["classify_model"],
        "explain_model": result["explain_model"],
        "self_check_model": result["self_check_model"],
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }
    upserted = (
        get_client()
        .table(INVESTIGATIONS_TABLE)
        .upsert(row, on_conflict="flow_id")
        .execute()
    )
    return upserted.data[0] if upserted.data else row


def upsert_enrichment(ip: str, providers: dict) -> dict:
    """Upsert on ip -- an IP's cache entry is shared across every flow
    that happens to reference it, and refreshing it after TTL expiry
    overwrites the same row rather than accumulating history.
    """
    row = {
        "ip": ip,
        **{name: result for name, result in providers.items()},
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }
    result = (
        get_client()
        .table(IP_ENRICHMENTS_TABLE)
        .upsert(row, on_conflict="ip")
        .execute()
    )
    return result.data[0] if result.data else row
