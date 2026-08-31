from __future__ import annotations

import logging
from functools import lru_cache

import jwt
from fastapi import Depends, HTTPException, Request
from jwt import PyJWKClient
from pydantic import BaseModel

from app.config import settings
from app.services import rate_limit, supabase_client

logger = logging.getLogger("netsentinel.auth")


class CurrentUser(BaseModel):
    id: str
    email: str
    role: str


def _project_url() -> str:
    if not settings.supabase_url:
        raise HTTPException(status_code=500, detail="SUPABASE_URL is not set in backend/.env.")
    return settings.supabase_url if settings.supabase_url.startswith("http") else f"https://{settings.supabase_url}"


# How long a fetched JWKS key set is trusted before it is re-fetched.
# PyJWKClient defaults to 300s, which meant the network path below was
# exercised every five minutes in normal operation -- and each of those
# fetches measured ~1.1s even on a healthy connection. An hour still picks
# up a Supabase signing-key rotation without a restart (rotation is a rare,
# deliberate admin action), while cutting the exposure to a transient
# network failure by ~12x. See docs/PRE-DEPLOYMENT-READINESS.md, D4.
JWKS_CACHE_SECONDS = 3600
# Default is 30s, long enough that one blip blocks a request for half a
# minute. Measured JWKS latency is ~0.8-1.6s, so 10s is ample headroom.
JWKS_FETCH_TIMEOUT_SECONDS = 10


@lru_cache
def _jwks_client() -> PyJWKClient:
    """One shared client per process. This project's Auth signing keys are
    asymmetric (ES256) -- Supabase's JWKS endpoint only ever publishes
    public keys, never a shared secret, which is what makes verifying a
    token here possible without calling back to Supabase for every
    request. The fetched key set is cached (see JWKS_CACHE_SECONDS), so
    this is a local check almost all the time, and a signing-key rotation
    is still picked up automatically within that window -- no backend
    restart required, unlike a static secret.
    """
    return PyJWKClient(
        f"{_project_url()}/auth/v1/.well-known/jwks.json",
        lifespan=JWKS_CACHE_SECONDS,
        timeout=JWKS_FETCH_TIMEOUT_SECONDS,
    )


def _decode_token(token: str) -> dict:
    """Verify a token, distinguishing "this token is bad" from "we could
    not reach the key server".

    Those two are very different and used to be reported identically.
    PyJWKClientConnectionError means the JWKS fetch itself failed -- the
    caller's session may be perfectly valid, and telling them it expired
    sends them to re-authenticate, which cannot help because the fault is
    server-side. That is a 503. A key set we DID fetch but which has no
    matching `kid`, an expired token, a bad signature, a wrong audience --
    those are all genuinely the caller's problem, and stay 401.
    (docs/PRE-DEPLOYMENT-READINESS.md, D4.)
    """
    try:
        signing_key = _jwks_client().get_signing_key_from_jwt(token)
    except jwt.PyJWKClientConnectionError as exc:
        logger.warning("JWKS key-set fetch failed -- returning 503, not 401: %s", exc)
        raise HTTPException(
            status_code=503,
            detail="Authentication service temporarily unavailable. Please retry.",
        ) from exc
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired session.") from exc

    try:
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

    # The cross-endpoint per-user cap, charged here rather than per-route.
    # This is the only place EVERY authenticated request provably passes
    # through -- header auth and the SSE `?token=` path both land here --
    # so it is the one spot where a "global" bucket actually earns that
    # name. Previously the bucket existed but was only ever charged inside
    # enforce() on three spend endpoints, which left /api/flows,
    # /api/admin/*, /api/rag/search and /api/capture/* entirely
    # unthrottled while the docs claimed otherwise (Phase 13.5, D1).
    #
    # Deliberately before the profile lookup: a caller who is already over
    # the cap shouldn't cost a Supabase round-trip to find out.
    rate_limit.enforce("global", user_id)

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
    """Best-effort. Every caller runs this AFTER its side effect has already
    committed, so letting a logging failure raise would 500 a request whose
    write actually succeeded -- the caller would reasonably retry and
    double-apply it. A missing audit row is the lesser harm, but it is a
    real gap, so it is logged at WARNING rather than swallowed silently
    (docs/SECURITY-TESTING-NOTES.md, F11).
    """
    try:
        supabase_client.insert_audit_log(
            user_id=current_user.id,
            user_email=current_user.email,
            action=action,
            detail=detail,
            ip_address=client_ip(request),
        )
    except Exception as exc:
        logger.warning(
            "AUDIT GAP -- failed to record action=%s by user=%s: %s",
            action, current_user.email, exc,
        )
