from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app.services import supabase_client
from app.services.auth import CurrentUser, get_current_user, log_audit
from app.services.enrichment.enrichment_service import get_or_fetch_enrichment
from app.services.enrichment.ip_classification import external_ip_for_flow

router = APIRouter(prefix="/api", tags=["enrichment"])


class EnrichmentRequest(BaseModel):
    # False (default): read-only cache peek, never calls a provider.
    # True: actually spend API quota if the cache is missing or stale.
    fetch: bool = False


@router.post("/flows/{flow_id}/enrichment")
def get_flow_enrichment(
    flow_id: str,
    body: EnrichmentRequest,
    request: Request,
    current_user: CurrentUser = Depends(get_current_user),
):
    """Threat-intel context for one flow -- flagged flows only.

    Enforced here, not just hidden in the UI: a flow that isn't currently
    flagged by the active model gets a 400, never a provider call. This
    is the actual "only flagged indicators get sent externally" boundary
    docs/PHASE-2-PLAN.md's Phase 5 test gate requires.

    Any authenticated role can read a cached result (`fetch=False`) -- a
    viewer's read-only access still includes seeing what's already been
    enriched. Only `fetch=True` actually spends provider quota, so that's
    the one branch restricted to analyst/admin, checked here rather than
    at the route level since one endpoint serves both cases.
    """
    if body.fetch and current_user.role not in ("analyst", "admin"):
        raise HTTPException(status_code=403, detail="Running new enrichment requires analyst or admin.")

    flow = supabase_client.get_flow_with_score(flow_id)
    if not flow:
        raise HTTPException(status_code=404, detail="Flow not found.")
    if not flow["is_anomalous"]:
        raise HTTPException(
            status_code=400,
            detail="Enrichment is only available for flagged flows.",
        )

    ip = external_ip_for_flow(flow)
    if not ip:
        return {
            "applicable": False,
            "reason": (
                "Both source and destination are private/internal IPs -- "
                "no external indicator to enrich."
            ),
        }

    result = get_or_fetch_enrichment(ip, force_fetch=body.fetch)
    if body.fetch:
        log_audit(request, current_user, "enrichment_run", detail={"flow_id": flow_id, "ip": ip})
    return {"applicable": True, **result}
