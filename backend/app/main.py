import logging
import re
import time

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.routers import admin, auth, capture, enrichment, integrations, investigate, models, pcap, rag, verdicts
from app.services import supabase_client
from app.services.ml.scoring import resolve_artifact_path

# Nothing previously configured a level, so the root logger defaulted to
# WARNING and every netsentinel.* logger.info() call (scoring, pcap,
# enrichment) was silently dropped -- not just new to this phase.
logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")
logger = logging.getLogger("netsentinel.health")


class _RedactQueryTokenFilter(logging.Filter):
    """Strip `?token=<jwt>` out of anything we log.

    The SSE endpoint (/api/capture/stream) has to take its bearer token in
    the query string because EventSource cannot set headers -- a trade-off
    Phase 10 accepted and Phase 12 documented. What neither checked is
    where that token then *lands*: uvicorn's access logger writes the full
    request line, query string included, so every stream connection was
    writing a live, ~1h-valid credential into the log in plaintext.
    Verified by grepping the log for a token fragment and finding it.

    That is a bigger deal deployed than locally: hosted platforms
    aggregate stdout into retained, searchable log services that are
    often readable by more people than the database is. This does not
    change the URL contract -- it only ensures the credential never
    reaches a log sink. (docs/PRE-DEPLOYMENT-READINESS.md, D5.)
    """

    _PATTERN = re.compile(r"(token=)[^&\s\"']+", re.IGNORECASE)

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.args, tuple):
            record.args = tuple(
                self._PATTERN.sub(r"\1[REDACTED]", a) if isinstance(a, str) else a
                for a in record.args
            )
        if isinstance(record.msg, str) and "token=" in record.msg:
            record.msg = self._PATTERN.sub(r"\1[REDACTED]", record.msg)
        return True


# uvicorn.access is the one that writes the request line; the root logger
# catches anything of ours that ever formats a URL into a message.
_redactor = _RedactQueryTokenFilter()
logging.getLogger("uvicorn.access").addFilter(_redactor)
logging.getLogger().addFilter(_redactor)

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


timing_logger = logging.getLogger("netsentinel.timing")
# Render's internal checker calls this every ~5s -- ~17k lines a day of noise.
_UNTIMED_ROUTES = {"/api/health"}


@app.middleware("http")
async def log_request_timing(request: Request, call_next):
    """Server-side time per endpoint, as deployed (docs/MONITORING.md).

    Logs the route TEMPLATE (`/api/flows/{flow_id}`), never the raw URL:
    no path IDs, and no query string -- which is where the SSE endpoint's
    bearer token lives. Unmatched paths (scanners probing /wp-admin) log
    as "unmatched" rather than echoing whatever they asked for.

    Measures time until the response STARTS. For ordinary JSON endpoints
    that is the whole cost; for streaming responses (live-capture SSE) it
    is only time-to-first-byte, not how long the stream stays open.
    """
    start = time.perf_counter()
    status = 500
    try:
        response = await call_next(request)
        status = response.status_code
        return response
    finally:
        route = request.scope.get("route")
        template = getattr(route, "path", None) or "unmatched"
        if template not in _UNTIMED_ROUTES:
            timing_logger.info(
                "TIMING %s %s %d %.1fms",
                request.method, template, status, (time.perf_counter() - start) * 1000,
            )


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
    """Liveness only: the process is up. Touches nothing, deliberately --
    Render's own health checker calls this every ~5s, so it must stay free.
    """
    return {"status": "ok"}


# How long a readiness result is reused. /ready is unauthenticated and does
# a real database round-trip, so without this anyone could turn it into a
# free Supabase-query generator; the external monitor only calls it hourly.
READY_CACHE_SECONDS = 30
_ready_cache: dict = {"at": None, "ok": False}


def _check_ready() -> bool:
    try:
        version = supabase_client.get_active_model_version()
    except Exception as exc:
        logger.warning("Readiness: database check failed: %s: %s", type(exc).__name__, exc)
        return False
    if not version or not version.get("artifact_path"):
        logger.warning("Readiness: no active model version")
        return False
    if not resolve_artifact_path(version["artifact_path"]).exists():
        logger.warning("Readiness: active model artifact missing on disk")
        return False
    return True


@app.get("/api/health/ready")
def ready():
    """Readiness: can this instance do its actual job -- reach the database
    and score with the shipped model? That catches what /api/health cannot:
    a paused Supabase project, a bad key, or a deploy missing the model
    artifact (all of which leave the process happily "up").

    The response is only ok/degraded, never which check failed -- that
    detail goes to the server log. An unauthenticated endpoint shouldn't
    describe the backend's internals to whoever asks.
    """
    now = time.monotonic()
    if _ready_cache["at"] is None or now - _ready_cache["at"] >= READY_CACHE_SECONDS:
        _ready_cache.update(at=now, ok=_check_ready())
    if _ready_cache["ok"]:
        return {"status": "ok"}
    return JSONResponse(status_code=503, content={"status": "degraded"})
