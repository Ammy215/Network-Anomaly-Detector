from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.routers import models, pcap

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


@app.get("/api/health")
def health():
    return {"status": "ok"}
