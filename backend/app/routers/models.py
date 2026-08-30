from fastapi import APIRouter, Depends, HTTPException

from app.services import supabase_client
from app.services.auth import CurrentUser, get_current_user

router = APIRouter(prefix="/api", tags=["models"])


@router.get("/models")
def list_models(current_user: CurrentUser = Depends(get_current_user)):
    """The model registry / comparison table.

    Returns every trained version, newest first, with its full metrics --
    including the unflattering ones. Nothing is filtered out to make a
    model look better than it is.
    """
    return {"models": supabase_client.list_model_versions()}


@router.get("/models/{version_id}")
def get_model(version_id: str, current_user: CurrentUser = Depends(get_current_user)):
    version = supabase_client.get_model_version(version_id)
    if not version:
        raise HTTPException(status_code=404, detail="Model version not found.")
    return version


@router.get("/flows/{flow_id}/score")
def get_flow_score(flow_id: str, current_user: CurrentUser = Depends(get_current_user)):
    """Per-flow scores with the features that drove them.

    Never returns a bare "anomalous" verdict -- every score comes with the
    contributing features, so an analyst can judge the reasoning rather
    than trust a number.
    """
    scores = supabase_client.list_flow_scores(flow_id)
    if not scores:
        raise HTTPException(
            status_code=404,
            detail="No scores for this flow. Has a model been trained yet?",
        )
    return {"flow_id": flow_id, "scores": scores}
