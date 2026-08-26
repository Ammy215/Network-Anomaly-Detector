from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.services import supabase_client
from app.services.enrichment.enrichment_service import get_or_fetch_enrichment
from app.services.enrichment.ip_classification import external_ip_for_flow

router = APIRouter(prefix="/api", tags=["enrichment"])


class EnrichmentRequest(BaseModel):
    # False (default): read-only cache peek, never calls a provider.
    # True: actually spend API quota if the cache is missing or stale.
    fetch: bool = False


@router.post("/flows/{flow_id}/enrichment")
def get_flow_enrichment(flow_id: str, body: EnrichmentRequest):
    """Threat-intel context for one flow -- flagged flows only.

    Enforced here, not just hidden in the UI: a flow that isn't currently
    flagged by the active model gets a 400, never a provider call. This
    is the actual "only flagged indicators get sent externally" boundary
    docs/PHASE-2-PLAN.md's Phase 5 test gate requires.
    """
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
    return {"applicable": True, **result}
