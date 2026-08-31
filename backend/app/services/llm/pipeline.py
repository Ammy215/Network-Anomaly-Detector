"""The Phase 7 investigation pipeline: classify -> retrieve -> explain ->
self_check, wired as a LangGraph `StateGraph`.

LangGraph concepts, briefly: `State` is a typed dict threaded through the
whole run -- each node reads whatever fields it needs off it and returns
a partial update that gets merged in. A node is just a plain function
`(state) -> dict`. An edge says what runs next. This graph's edges are
all unconditional (classify -> retrieve -> explain -> self_check -> END)
-- there's no branching logic here today. LangGraph's payoff for a
straight line like this isn't branching, it's a standard, inspectable
shape (typed state, a single `.invoke()` entrypoint) instead of four
hand-nested function calls, and room to add real branching later (e.g.
skipping retrieval on a very low-confidence classification) without
restructuring anything.
"""

import difflib
import logging
import re
from typing import TypedDict

from langgraph.graph import END, START, StateGraph

from app.services.llm.groq_client import structured_completion
from app.services.llm.prompts import (
    CLASSIFY_SYSTEM_PROMPT,
    EXPLAIN_SYSTEM_PROMPT,
    SELF_CHECK_SYSTEM_PROMPT,
    format_flow_data,
    format_retrieved_chunks,
)
from app.services.llm.schemas import (
    AnomalyType,
    ClassificationResult,
    InvestigationOutput,
    SelfCheckResult,
)
from app.services.rag.retriever import retrieve

logger = logging.getLogger("netsentinel.llm")

CLASSIFY_MODEL = "openai/gpt-oss-120b"
EXPLAIN_MODEL = "openai/gpt-oss-120b"
SELF_CHECK_MODEL = "openai/gpt-oss-20b"  # smaller/cheaper, separate quota bucket

# Retrieval query per anomaly type. Genuinely useful for port_scan, where
# the Phase 6 corpus has real MITRE coverage (T1595/T1046) phrased in
# matching mechanism language (see docs/RAG-EVAL-NOTES.md). The corpus was
# deliberately scoped to Reconnaissance + Discovery only -- it has no
# beaconing/DNS-tunneling/exfiltration MITRE techniques ingested at all,
# so those queries are expected to surface only weak matches, which the
# similarity floor below then drops before they ever reach `explain`.
QUERY_TEMPLATES: dict[AnomalyType, str] = {
    AnomalyType.port_scan: (
        "port scanning many connections to different ports network service "
        "discovery active reconnaissance"
    ),
    AnomalyType.beaconing: (
        "periodic beaconing command and control network communication callback"
    ),
    AnomalyType.dns_tunneling: (
        "DNS tunneling covert channel data exfiltration through DNS queries"
    ),
    AnomalyType.data_exfil: "large outbound data transfer data exfiltration",
    AnomalyType.unknown: "unusual anomalous network flow behavior",
}

# Chunks below this similarity never reach `explain` -- this is the
# concrete mechanism that makes an honest "no good mapping" result
# possible, not just a prompt instruction hoping the model behaves.
SIMILARITY_FLOOR = 0.35


class State(TypedDict, total=False):
    flow: dict
    classification: dict
    retrieved_chunks: list[dict]
    investigation: dict
    self_check: dict


def classify_node(state: State) -> dict:
    flow = state["flow"]
    result = structured_completion(
        model=CLASSIFY_MODEL,
        system_prompt=CLASSIFY_SYSTEM_PROMPT,
        user_prompt=format_flow_data(flow),
        schema=ClassificationResult,
    )
    return {"classification": result.model_dump()}


def retrieve_node(state: State) -> dict:
    anomaly_type = AnomalyType(state["classification"]["anomaly_type"])
    query = QUERY_TEMPLATES[anomaly_type]
    chunks = retrieve(query, top_k=5)
    relevant = [c for c in chunks if c["similarity"] >= SIMILARITY_FLOOR]
    return {"retrieved_chunks": relevant}


def explain_node(state: State) -> dict:
    flow = state["flow"]
    classification = state["classification"]
    chunks = state["retrieved_chunks"]

    user_prompt = (
        f"{format_flow_data(flow)}\n\n"
        f"PRELIMINARY CLASSIFICATION: {classification['anomaly_type']} "
        f"(confidence {classification['confidence']}) -- {classification['reasoning']}\n\n"
        f"{format_retrieved_chunks(chunks)}"
    )
    result = structured_completion(
        model=EXPLAIN_MODEL,
        system_prompt=EXPLAIN_SYSTEM_PROMPT,
        user_prompt=user_prompt,
        schema=InvestigationOutput,
    )
    return {"investigation": result.model_dump()}


_DASH_VARIANTS_RE = re.compile("[‐‑‒–—―]")


def _normalize(text: str) -> str:
    """Lowercase + collapse whitespace, plus two normalizations found by
    real false-positive citations in production, not added speculatively:
    - Strip markdown emphasis markers (**bold**, __bold__). The retrieved
      chunk is raw markdown; a model quoting its prose naturally drops the
      formatting syntax, which is not a misquote.
    - Fold every dash-like Unicode punctuation variant (non-breaking
      hyphen, en/em dash, etc.) to a plain ASCII '-'. A model quoting
      "three-feature" as "three‑feature" (non-breaking hyphen) is
      stylistic substitution, not a different word.
    """
    text = text.replace("**", "").replace("__", "")
    text = _DASH_VARIANTS_RE.sub("-", text)
    return " ".join(text.lower().split())


_ELLIPSIS_RE = re.compile(r"\s*(?:\.{3}|…)\s*")


def _segment_supported(norm_excerpt: str, norm_chunk: str) -> bool:
    """A literal substring match always passes; anything else falls back
    to how much of the excerpt is covered by the single longest matching
    run of text, which tolerates minor paraphrasing but still fails a
    wholly fabricated excerpt (near-zero overlap).
    """
    if not norm_excerpt:
        return False
    if norm_excerpt in norm_chunk:
        return True
    matcher = difflib.SequenceMatcher(None, norm_excerpt, norm_chunk)
    match = matcher.find_longest_match(0, len(norm_excerpt), 0, len(norm_chunk))
    return (match.size / len(norm_excerpt)) >= 0.6


def _citation_supported(excerpt: str, chunk_text: str) -> bool:
    """Exact-or-close-paraphrase check: does `excerpt` actually appear in
    `chunk_text`? Models routinely elide a middle sentence of a long quote
    with a mid-excerpt "..." -- each side of that ellipsis is then a real,
    separately verbatim run, not one contiguous quote, so it's checked
    segment by segment rather than as a single span.
    """
    norm_chunk = _normalize(chunk_text)
    segments = [s for s in _ELLIPSIS_RE.split(excerpt) if _normalize(s)]
    if not segments:
        return False
    return all(_segment_supported(_normalize(s), norm_chunk) for s in segments)


def deterministic_self_check(investigation: dict, chunks: list[dict]) -> dict:
    """Code-only verification, no LLM call: does every citation's source id
    actually exist among the retrieved chunks, and does its excerpt text
    actually appear in that chunk? Does every named MITRE technique
    actually correspond to a retrieved chunk's source? Both are exactly
    checkable in code, so there's no reason to spend a model call on
    them -- this is what reliably catches a fabricated citation.
    """
    chunks_by_id = {c["id"]: c for c in chunks}
    chunk_sources = {c["source"] for c in chunks}

    invalid_citations = []
    for citation in investigation.get("citations", []):
        chunk = chunks_by_id.get(citation["source"])
        if chunk is None or not _citation_supported(citation["excerpt"], chunk["text"]):
            invalid_citations.append(citation["source"])

    unsupported_claims = [
        f"MITRE technique {technique_id} was named but no retrieved chunk covers it"
        for technique_id in investigation.get("mitre_techniques", [])
        if technique_id not in chunk_sources
    ]

    return {
        "citations_valid": not invalid_citations,
        "invalid_citations": invalid_citations,
        "unsupported_claims": unsupported_claims,
    }


def self_check_node(state: State) -> dict:
    investigation = state["investigation"]
    chunks = state["retrieved_chunks"]

    deterministic = deterministic_self_check(investigation, chunks)

    claims_text = "\n".join(
        f'- citation: source="{c["source"]}", excerpt="{c["excerpt"]}"'
        for c in investigation.get("citations", [])
    ) or "(no citations given)"
    techniques_text = ", ".join(investigation.get("mitre_techniques", [])) or "(none named)"

    user_prompt = (
        f"{format_retrieved_chunks(chunks)}\n\n"
        f"CLAIMS TO VERIFY:\n{claims_text}\n\n"
        f"MITRE TECHNIQUES NAMED: {techniques_text}"
    )
    llm_result = structured_completion(
        model=SELF_CHECK_MODEL,
        system_prompt=SELF_CHECK_SYSTEM_PROMPT,
        user_prompt=user_prompt,
        schema=SelfCheckResult,
    )

    combined = SelfCheckResult(
        citations_valid=deterministic["citations_valid"] and llm_result.citations_valid,
        invalid_citations=sorted(set(deterministic["invalid_citations"]) | set(llm_result.invalid_citations)),
        unsupported_claims=sorted(set(deterministic["unsupported_claims"]) | set(llm_result.unsupported_claims)),
        notes=llm_result.notes,
    )
    return {"self_check": combined.model_dump()}


def build_graph():
    graph = StateGraph(State)
    graph.add_node("classify", classify_node)
    graph.add_node("retrieve", retrieve_node)
    graph.add_node("explain", explain_node)
    graph.add_node("self_check", self_check_node)
    graph.add_edge(START, "classify")
    graph.add_edge("classify", "retrieve")
    graph.add_edge("retrieve", "explain")
    graph.add_edge("explain", "self_check")
    graph.add_edge("self_check", END)
    return graph.compile()


def run_investigation(flow: dict) -> dict:
    """Public entrypoint: one flow's data in, the full pipeline result out."""
    graph = build_graph()
    result = graph.invoke({"flow": flow})
    return {
        "classification": result["classification"],
        "retrieved_chunks": result["retrieved_chunks"],
        "investigation": result["investigation"],
        "self_check": result["self_check"],
    }
