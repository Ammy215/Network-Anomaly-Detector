import logging
import re

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.routers import admin, auth, capture, enrichment, integrations, investigate, models, pcap, rag, verdicts

# Nothing previously configured a level, so the root logger defaulted to
# WARNING and every netsentinel.* logger.info() call (scoring, pcap,
# enrichment) was silently dropped -- not just new to this phase.
logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")


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
