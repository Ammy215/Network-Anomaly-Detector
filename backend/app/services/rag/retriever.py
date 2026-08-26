"""Retrieval: given a text query, return the top-k most relevant
knowledge-base chunks with their source and similarity score.

The query is embedded with the exact same embedding function used at
ingestion (see chroma_client.get_embedding_function) -- query and corpus
have to share one coordinate space, or "distance between vectors" is
meaningless. Chroma handles this automatically as long as the collection
was created with an embedding function attached, which is the case here.
"""

from app.services.rag.chroma_client import get_collection


def retrieve(query: str, top_k: int = 5) -> list[dict]:
    collection = get_collection()
    if collection.count() == 0:
        return []

    result = collection.query(
        query_texts=[query],
        n_results=min(top_k, collection.count()),
    )

    chunks = []
    ids = result["ids"][0]
    documents = result["documents"][0]
    metadatas = result["metadatas"][0]
    distances = result["distances"][0]

    for chunk_id, text, metadata, distance in zip(ids, documents, metadatas, distances):
        chunks.append({
            "id": chunk_id,
            "text": text,
            "source": metadata.get("source"),
            "title": metadata.get("title"),
            "doc_type": metadata.get("doc_type"),
            "tactic": metadata.get("tactic"),
            "url": metadata.get("url"),
            # Chroma's cosine "distance" is (1 - cosine_similarity), so
            # smaller is more similar. Converted here to a similarity
            # score (1.0 = identical direction, 0.0 = orthogonal/unrelated)
            # since "higher score = more relevant" is the intuitive
            # direction for a caller to read.
            "similarity": round(1.0 - distance, 4),
        })

    return chunks
