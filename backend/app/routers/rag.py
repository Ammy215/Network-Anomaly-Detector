from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.services.auth import CurrentUser, require_role
from app.services.rag.retriever import retrieve

router = APIRouter(prefix="/api", tags=["rag"])


class SearchRequest(BaseModel):
    query: str
    top_k: int = 5


@router.post("/rag/search")
def search_knowledge_base(body: SearchRequest, current_user: CurrentUser = Depends(require_role("admin"))):
    """Debug/testing endpoint for the Phase 6 retriever -- not part of the
    analyst workflow (Investigation already runs retrieval internally), so
    restricted to admin rather than every authenticated role.
    """
    return {"query": body.query, "results": retrieve(body.query, top_k=body.top_k)}
