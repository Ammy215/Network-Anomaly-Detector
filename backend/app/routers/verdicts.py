from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, field_validator

from app.services import supabase_client
from app.services.supabase_client import VALID_VERDICTS

# No import from app.services.ml, scripts.train_models, or
# scripts.activate_model anywhere in this file -- verdicts are recorded
# only. There is no code path here that touches a model artifact, a
# threshold, or model_versions.is_active. See docs/PHASE-2-PLAN.md Phase 4
# ("the system never silently retrains from a click").

router = APIRouter(prefix="/api", tags=["verdicts"])

PLACEHOLDER_ANALYST = "local-analyst"  # single-user placeholder; real auth is Phase 9


class VerdictIn(BaseModel):
    verdict: str
    note: str | None = None

    @field_validator("verdict")
    @classmethod
    def verdict_is_valid(cls, value: str) -> str:
        if value not in VALID_VERDICTS:
            raise ValueError(f"verdict must be one of {VALID_VERDICTS}")
        return value


@router.post("/flows/{flow_id}/verdict")
def set_flow_verdict(flow_id: str, body: VerdictIn):
    """Records the analyst's ground-truth judgement on a flow.

    Deliberately independent of whether the model flagged the flow --
    marking a *not-flagged* flow true_positive is exactly how a missed
    detection gets captured (cross-referenced against is_anomalous at
    summary time), not something this endpoint treats as invalid.
    """
    if not supabase_client.flow_exists(flow_id):
        raise HTTPException(status_code=404, detail="Flow not found.")

    row = supabase_client.upsert_flow_verdict(
        flow_id=flow_id,
        verdict=body.verdict,
        note=body.note,
        created_by=PLACEHOLDER_ANALYST,
    )
    return row


@router.get("/verdicts/summary")
def get_verdicts_summary():
    """Counts only -- recorded for review, never used to retrain or
    adjust the active model's threshold.
    """
    return supabase_client.get_verdict_summary()
