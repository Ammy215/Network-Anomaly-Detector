from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.services.auth import CurrentUser, require_role
from app.services.rag.retriever import retrieve

router = APIRouter(prefix="/api", tags=["rag"])


class SearchRequest(BaseModel):
    # Bounded: an unbounded query string is a needless memory/embedding
    # cost, and a negative top_k reaches Chroma and 500s.
    query: str = Field(min_length=1, max_length=1000)
    top_k: int = Field(default=5, ge=1, le=50)


@router.post("/rag/search")
def search_knowledge_base(body: SearchRequest, current_user: CurrentUser = Depends(require_role("admin"))):
    """Debug/testing endpoint for the Phase 6 retriever -- not part of the
    analyst workflow (Investigation already runs retrieval internally), so
    restricted to admin rather than every authenticated role.
    """
    return {"query": body.query, "results": retrieve(body.query, top_k=body.top_k)}
