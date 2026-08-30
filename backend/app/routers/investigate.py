from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app.services import supabase_client
from app.services.auth import CurrentUser, get_current_user, log_audit
from app.services.llm.groq_client import LLMUnavailableError
from app.services.llm.pipeline import (
    CLASSIFY_MODEL,
    EXPLAIN_MODEL,
    SELF_CHECK_MODEL,
    run_investigation,
)

router = APIRouter(prefix="/api", tags=["investigate"])


class InvestigateRequest(BaseModel):
    # False (default): read-only cache peek, never calls Groq.
    # True: run the full classify/retrieve/explain/self_check pipeline if
    # nothing is cached yet -- this is the "spend quota" action.
    fetch: bool = False


def _shape(row: dict) -> dict:
    return {
        "classification": row["classification"],
        "retrieved_chunks": row["retrieved_chunks"],
        "investigation": row["investigation"],
        "self_check": row["self_check"],
        "models": {
            "classify": row["classify_model"],
            "explain": row["explain_model"],
            "self_check": row["self_check_model"],
        },
        "fetched_at": row["fetched_at"],
    }


@router.post("/flows/{flow_id}/investigate")
def investigate_flow(
    flow_id: str,
    body: InvestigateRequest,
    request: Request,
    current_user: CurrentUser = Depends(get_current_user),
):
    """AI-generated investigation for one flow -- flagged flows only,
    enforced here rather than only hidden in the UI, same boundary as
    Phase 5's enrichment endpoint. Once run, a flow's investigation is
    cached permanently: the flow's own data never changes after scoring,
    so there's no staleness concept to re-check against, unlike
    IP-reputation enrichment -- `fetch` only ever triggers the FIRST run.

    Same read/write split as enrichment: any role can peek a cached result
    (`fetch=False`), only analyst/admin can actually trigger the LLM
    pipeline (`fetch=True`), checked inline since it's one endpoint.
    """
    if body.fetch and current_user.role not in ("analyst", "admin"):
        raise HTTPException(status_code=403, detail="Running a new investigation requires analyst or admin.")

    flow = supabase_client.get_flow_for_investigation(flow_id)
    if not flow:
        raise HTTPException(status_code=404, detail="Flow not found.")
    if not flow["is_anomalous"]:
        raise HTTPException(
            status_code=400,
            detail="Investigation is only available for flagged flows.",
        )

    cached = supabase_client.get_cached_investigation(flow_id)
    if cached:
        return {"cached": True, **_shape(cached)}
    if not body.fetch:
        return {"cached": False}

    try:
        result = run_investigation(flow)
    except LLMUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    stored = supabase_client.upsert_investigation(
        flow_id,
        {
            **result,
            "classify_model": CLASSIFY_MODEL,
            "explain_model": EXPLAIN_MODEL,
            "self_check_model": SELF_CHECK_MODEL,
        },
    )
    log_audit(request, current_user, "investigation_run", detail={"flow_id": flow_id})
    return {"cached": True, **_shape(stored)}
