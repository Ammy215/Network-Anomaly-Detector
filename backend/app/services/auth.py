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


def user_from_raw_token(token: str) -> CurrentUser:
    """Verifies a raw bearer token string and looks up its role, regardless
    of where the token came from (an `Authorization` header, a query
    string). Shared by `get_current_user` (header) and
    `get_current_user_from_query` (SSE -- the browser's `EventSource` can't
    set custom headers, so live capture's stream endpoint authenticates via
    a `?token=` query param instead; see Phase 10 plan for the trade-off).

    Role is deliberately not trusted from the token itself: a request-time
    lookup means a dashboard-granted promotion takes effect on the user's
    very next request, not only after their token next refreshes.
    """
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


def get_current_user(request: Request) -> CurrentUser:
    auth_header = request.headers.get("authorization", "")
    if not auth_header.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated.")
    token = auth_header[len("bearer "):].strip()
    return user_from_raw_token(token)


def get_current_user_from_query(token: str = "") -> CurrentUser:
    # Default keeps `token` optional at the FastAPI-validation layer (which
    # would otherwise 422 a missing query param before this function ever
    # runs) so a missing token gets the same 401 every other unauthenticated
    # request in this app gets, not a differently-shaped validation error.
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    return user_from_raw_token(token)


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
