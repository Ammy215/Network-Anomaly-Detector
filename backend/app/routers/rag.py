from fastapi import APIRouter
from pydantic import BaseModel

from app.services.rag.retriever import retrieve

router = APIRouter(prefix="/api", tags=["rag"])


class SearchRequest(BaseModel):
    query: str
    top_k: int = 5


@router.post("/rag/search")
def search_knowledge_base(body: SearchRequest):
    """Debug/testing endpoint for the Phase 6 retriever -- lets an
    analyst try their own queries directly, rather than only trusting a
    reported eval score. No LLM here yet (Phase 7); this returns raw
    retrieved chunks only.
    """
    return {"query": body.query, "results": retrieve(body.query, top_k=body.top_k)}
