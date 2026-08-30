from fastapi import APIRouter, Depends

from app.config import settings
from app.services.auth import CurrentUser, get_current_user

router = APIRouter(prefix="/api/integrations", tags=["integrations"])


@router.get("/status")
def get_integrations_status(current_user: CurrentUser = Depends(get_current_user)):
    """Whether each Phase 11 integration is configured -- booleans only,
    never the actual URL (server-side config never ships to the browser,
    same rule every other API key in this project already follows).
    Read-only visibility, available to every role; there's no action to
    gate here.
    """
    return {
        "mini_siem": {"enabled": bool(settings.mini_siem_webhook_url)},
        "threathunter": {"enabled": bool(settings.threathunter_endpoint_url)},
    }
