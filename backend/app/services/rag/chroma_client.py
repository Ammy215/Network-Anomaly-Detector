"""Chroma setup: one persistent local collection, embedded directly in
this process -- no separate server to run alongside the backend and
frontend (see docs/PHASE-2-PLAN.md Phase 6 for the Chroma-vs-Qdrant
reasoning). Data lives on disk under CHROMA_DIR, which is git-ignored,
same as backend/models/ for trained ML artifacts.
"""

from functools import lru_cache
from pathlib import Path

import chromadb
from chromadb.config import Settings
from chromadb.utils import embedding_functions

CHROMA_DIR = Path(__file__).resolve().parents[3] / "data" / "chroma"
COLLECTION_NAME = "netsentinel_knowledge_base"


@lru_cache
def get_embedding_function():
    """Chroma's bundled all-MiniLM-L6-v2, run locally via onnxruntime.

    No API key, no network call after the one-time ~80MB model download
    (cached under the user's home directory by chromadb itself). This is
    the same embedding function used at ingestion time and at query
    time -- it MUST be the same function in both places, or similarity
    scores are meaningless: two texts embedded by different models don't
    share a coordinate space, so "distance" between their vectors
    wouldn't mean anything.
    """
    return embedding_functions.DefaultEmbeddingFunction()


@lru_cache
def get_client() -> chromadb.ClientAPI:
    CHROMA_DIR.mkdir(parents=True, exist_ok=True)
    return chromadb.PersistentClient(
        path=str(CHROMA_DIR),
        # Chroma phones home anonymized usage telemetry by default.
        # Disabled deliberately -- consistent with this project's
        # server-side-only, no-unnecessary-network-calls stance
        # throughout every prior phase.
        settings=Settings(anonymized_telemetry=False),
    )


def get_collection():
    """The single knowledge-base collection, created on first use.

    `hnsw:space: cosine` -- cosine similarity measures the ANGLE between
    two embedding vectors, ignoring their length. That's the right
    measure for sentence embeddings: a vector's magnitude isn't
    meaningful on its own, only its direction relative to other vectors
    is what encodes "how similar are these two ideas."
    """
    return get_client().get_or_create_collection(
        name=COLLECTION_NAME,
        embedding_function=get_embedding_function(),
        metadata={"hnsw:space": "cosine"},
    )
