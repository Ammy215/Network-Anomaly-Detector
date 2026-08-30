from fastapi import APIRouter, Depends, Request

from app.services.auth import CurrentUser, get_current_user, log_audit

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.get("/me")
def get_me(current_user: CurrentUser = Depends(get_current_user)):
    return current_user


@router.post("/login-event")
def record_login(request: Request, current_user: CurrentUser = Depends(get_current_user)):
    """Supabase Auth handles the actual login directly between the browser
    and Supabase -- this backend never sees it happen. The frontend calls
    this once, right after a successful sign-in, so there's still a real
    server-side audit trail without proxying credentials through here.
    """
    log_audit(request, current_user, "login")
    return {"logged": True}
