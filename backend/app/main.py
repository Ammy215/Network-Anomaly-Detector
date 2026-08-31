import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.routers import admin, auth, capture, enrichment, integrations, investigate, models, pcap, rag, verdicts

# Nothing previously configured a level, so the root logger defaulted to
# WARNING and every netsentinel.* logger.info() call (scoring, pcap,
# enrichment) was silently dropped -- not just new to this phase.
logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")

# Phase 12 (F8): the interactive docs publish every route, body schema, and
# role-gated path to anyone who can reach the port, unauthenticated. That's
# a reasonable development convenience and a needless disclosure anywhere
# else, so they're on only in development. This is also the first thing to
# actually read `environment`, which existed in config but was never used.
_is_dev = settings.environment == "development"

app = FastAPI(
    title="NetSentinel API",
    docs_url="/docs" if _is_dev else None,
    redoc_url="/redoc" if _is_dev else None,
    openapi_url="/openapi.json" if _is_dev else None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def reject_oversized_requests(request: Request, call_next):
    """A cheap safety net, not an ingress-size solution (Phase 13, F10
    follow-up). PCAP uploads already have a dedicated 50MB cap
    (max_upload_size_bytes) enforced inside the handler -- but that check
    only runs after Starlette has spooled the whole request body to disk,
    so it bounds what gets PARSED, not what gets ACCEPTED. This rejects by
    Content-Length before any body is read at all, for every route, so an
    absurdly large request (a multi-GB POST to any endpoint, not just
    upload) is turned away immediately instead of being spooled first.

    Deliberately not a complete fix: a client using chunked
    transfer-encoding sends no Content-Length, so this check simply
    doesn't apply to it -- true streaming/chunked enforcement needs a
    background-job upload architecture, which is out of scope for this
    phase (see docs/PERFORMANCE-NOTES.md).
    """
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > settings.max_request_body_bytes:
                return JSONResponse(
                    status_code=413,
                    content={"detail": "Request body too large."},
                )
        except ValueError:
            pass
    return await call_next(request)

app.include_router(pcap.router)
app.include_router(models.router)
app.include_router(verdicts.router)
app.include_router(enrichment.router)
app.include_router(rag.router)
app.include_router(investigate.router)
app.include_router(auth.router)
app.include_router(admin.router)
app.include_router(capture.router)
app.include_router(integrations.router)


@app.get("/api/health")
def health():
    return {"status": "ok"}
