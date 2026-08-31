FROM python:3.12-slim

# tshark is a hard runtime dependency of pyshark (backend/app/routers/pcap.py)
# -- pcap parsing shells out to the real tshark binary, it is not pure Python.
# DEBIAN_FRONTEND + debconf-set-selections skip the interactive
# "allow non-root capture" prompt wireshark-common's postinst asks by default.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Build context is the repo ROOT (see build instructions below), not
# backend/ alone -- scripts/ingest_rag_corpus.py resolves its docs/ path
# two directories above itself (backend/scripts/../.. = repo root), so the
# image needs docs/ present as a sibling of backend/'s contents, exactly
# like the real repo layout, or that path resolves to nothing.
COPY backend/ .
COPY docs/ /docs/

# Bakes the Chroma RAG corpus (and its cached ONNX embedding model) into the
# image at build time, since Render's free tier has no persistent disk --
# without this, every container restart would boot with an empty RAG corpus.
# Deterministic and free: reads only committed docs/ + a public MITRE bundle,
# no Supabase/LLM calls.
RUN python scripts/ingest_rag_corpus.py

ENV PORT=8000
EXPOSE 8000

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT}"]
