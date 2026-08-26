"""Ingests the Phase 6 RAG corpus into the local Chroma collection:
MITRE ATT&CK's filtered Reconnaissance/Discovery techniques, this
project's own protocol-fundamentals notes, and docs/ML-MODEL-NOTES.md.

Idempotent: every chunk gets a deterministic id (e.g. "mitre:T1046:0"),
and upsert() is used instead of add() -- re-running this script updates
existing chunks in place rather than duplicating them. Verified by
running it twice and confirming collection.count() doesn't grow.

Run:  python scripts/ingest_rag_corpus.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.rag.chroma_client import get_collection  # noqa: E402
from app.services.rag.chunking import chunk_markdown, split_long_text  # noqa: E402
from app.services.rag.mitre_source import load_target_techniques  # noqa: E402

DOCS_DIR = Path(__file__).resolve().parents[2] / "docs"
PROTOCOL_NOTES_DIR = DOCS_DIR / "rag-corpus" / "protocol-notes"
MODEL_NOTES_PATH = DOCS_DIR / "ML-MODEL-NOTES.md"


def _mitre_chunks() -> tuple[list[str], list[str], list[dict]]:
    ids, texts, metadatas = [], [], []
    for technique in load_target_techniques():
        pieces = split_long_text(technique["description"])
        for i, piece in enumerate(pieces):
            ids.append(f"mitre:{technique['technique_id']}:{i}")
            # Prefixing the technique name/ID helps a short or generically
            # worded chunk still embed distinctly -- pure body text alone
            # can be ambiguous out of context.
            texts.append(f"{technique['name']} ({technique['technique_id']}): {piece}")
            metadatas.append({
                "source": technique["technique_id"],
                "title": technique["name"],
                "doc_type": "mitre_technique",
                "tactic": technique["tactic"] or "",
                "url": technique["url"] or "",
            })
    return ids, texts, metadatas


def _markdown_file_chunks(path: Path, doc_id: str, doc_type: str) -> tuple[list[str], list[str], list[dict]]:
    ids, texts, metadatas = [], [], []
    text = path.read_text(encoding="utf-8")
    for i, chunk in enumerate(chunk_markdown(text)):
        ids.append(f"{doc_type}:{doc_id}:{i}")
        title = chunk["section"] or doc_id
        texts.append(f"{title}: {chunk['text']}")
        metadatas.append({
            "source": doc_id,
            "title": title,
            "doc_type": doc_type,
            "tactic": "",
            "url": "",
        })
    return ids, texts, metadatas


def main() -> None:
    collection = get_collection()
    before = collection.count()

    all_ids: list[str] = []
    all_texts: list[str] = []
    all_metadatas: list[dict] = []

    mitre_ids, mitre_texts, mitre_meta = _mitre_chunks()
    all_ids += mitre_ids
    all_texts += mitre_texts
    all_metadatas += mitre_meta
    n_techniques = len({m["source"] for m in mitre_meta})
    print(f"MITRE techniques: {n_techniques} techniques, {len(mitre_ids)} chunks")

    for path in sorted(PROTOCOL_NOTES_DIR.glob("*.md")):
        ids, texts, metas = _markdown_file_chunks(path, path.stem, "protocol_notes")
        all_ids += ids
        all_texts += texts
        all_metadatas += metas
        print(f"Protocol notes ({path.name}): {len(ids)} chunks")

    ids, texts, metas = _markdown_file_chunks(MODEL_NOTES_PATH, "ml-model-notes", "model_notes")
    all_ids += ids
    all_texts += texts
    all_metadatas += metas
    print(f"ML-MODEL-NOTES.md: {len(ids)} chunks")

    # Reconcile, not just upsert: if a document now produces FEWER chunks
    # than a previous run (e.g. cleaning up noise shrank a description
    # under the size ceiling so it no longer needs sub-splitting), the
    # old extra chunk ids would otherwise never get removed -- upsert()
    # only adds/updates, it never deletes. Diffing against what's
    # currently stored and deleting anything not in this run's fresh set
    # is what makes ingestion idempotent in the face of shrinking
    # content, not just growing/unchanged content.
    existing_ids = set(collection.get()["ids"])
    fresh_ids = set(all_ids)
    stale_ids = existing_ids - fresh_ids
    if stale_ids:
        collection.delete(ids=list(stale_ids))
        print(f"Removed {len(stale_ids)} stale chunk(s) no longer produced by this run: {sorted(stale_ids)}")

    collection.upsert(ids=all_ids, documents=all_texts, metadatas=all_metadatas)

    after = collection.count()
    print(f"\nTotal chunks upserted this run: {len(all_ids)}")
    print(f"Collection count before: {before}, after: {after}")


if __name__ == "__main__":
    main()
