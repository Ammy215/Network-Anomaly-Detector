import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.routers import admin, auth, capture, enrichment, investigate, models, pcap, rag, verdicts

# Nothing previously configured a level, so the root logger defaulted to
# WARNING and every netsentinel.* logger.info() call (scoring, pcap,
# enrichment) was silently dropped -- not just new to this phase.
logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")

app = FastAPI(title="NetSentinel API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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


@app.get("/api/health")
def health():
    return {"status": "ok"}
