from __future__ import annotations

from functools import lru_cache

import jwt
from fastapi import Depends, HTTPException, Request
from jwt import PyJWKClient
from pydantic import BaseModel

from app.config import settings
from app.services import supabase_client


class CurrentUser(BaseModel):
    id: str
    email: str
    role: str


def _project_url() -> str:
    if not settings.supabase_url:
        raise HTTPException(status_code=500, detail="SUPABASE_URL is not set in backend/.env.")
    return settings.supabase_url if settings.supabase_url.startswith("http") else f"https://{settings.supabase_url}"


@lru_cache
def _jwks_client() -> PyJWKClient:
    """One shared client per process. This project's Auth signing keys are
    asymmetric (ES256) -- Supabase's JWKS endpoint only ever publishes
    public keys, never a shared secret, which is what makes verifying a
    token here possible without calling back to Supabase for every
    request. PyJWKClient caches the fetched key set for 5 minutes
    (its default `lifespan`), so this is a local check almost all the
    time, and it also means a signing-key rotation is picked up
    automatically within that window -- no backend restart required,
    unlike a static secret.
    """
    return PyJWKClient(f"{_project_url()}/auth/v1/.well-known/jwks.json")


def _decode_token(token: str) -> dict:
    try:
        signing_key = _jwks_client().get_signing_key_from_jwt(token)
        return jwt.decode(
            token,
            signing_key.key,
            algorithms=["ES256", "RS256"],
            audience="authenticated",
            issuer=f"{_project_url()}/auth/v1",
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired session.") from exc


def get_current_user(request: Request) -> CurrentUser:
    """Verifies the bearer token Supabase Auth issued the logged-in user,
    then looks up their role from user_profiles.

    Role is deliberately not trusted from the token itself: a request-time
    lookup means a dashboard-granted promotion takes effect on the user's
    very next request, not only after their token next refreshes.
    """
    auth_header = request.headers.get("authorization", "")
    if not auth_header.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated.")
    token = auth_header[len("bearer "):].strip()

    payload = _decode_token(token)
    user_id = payload.get("sub")
    email = payload.get("email")
    if not user_id or not email:
        raise HTTPException(status_code=401, detail="Invalid session token.")

    profile = supabase_client.get_user_profile(user_id)
    if not profile:
        raise HTTPException(
            status_code=403,
            detail="No profile found for this account. Sign-up may not have completed correctly.",
        )

    return CurrentUser(id=user_id, email=email, role=profile["role"])


def require_role(*roles: str):
    """Dependency factory: 403s unless the caller's role is one of `roles`.
    Layered on top of get_current_user, so a missing/invalid token still
    401s before the role check ever runs.
    """

    def checker(current_user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if current_user.role not in roles:
            raise HTTPException(
                status_code=403,
                detail=f"This action requires one of: {', '.join(roles)}.",
            )
        return current_user

    return checker


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def log_audit(
    request: Request,
    current_user: CurrentUser,
    action: str,
    detail: dict | None = None,
) -> None:
    supabase_client.insert_audit_log(
        user_id=current_user.id,
        user_email=current_user.email,
        action=action,
        detail=detail,
        ip_address=client_ip(request),
    )
