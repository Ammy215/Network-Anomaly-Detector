"""Phase 6 retrieval-quality eval set.

The 15 queries and their expected (source, section) below were written
by inspecting the ingested corpus's chunk inventory -- NOT by running
retrieval first and picking whatever it happened to return. This
mirrors ML-MODEL-NOTES.md's "chosen before seeing results" discipline:
the ground truth is fixed before the test runs, so a bad result can't be
quietly redefined as correct.

`expected_source` is the MITRE technique ID or the protocol_notes/
model_notes source doc id. `expected_section` is the section/title a
correct chunk must carry (several sections get sub-split into multiple
chunks that share the same title -- any of them counts as a hit for
that section).

Run:  python scripts/eval_rag_retrieval.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.rag.retriever import retrieve  # noqa: E402

EVAL_QUERIES = [
    {
        "query": "many connections to different ports in a short time",
        "expected_source": "port-scan-behavioral-signature",
        "expected_section": None,  # any chunk from this doc counts
    },
    {
        # T1595 (the parent Active Scanning technique) was missing from
        # this eval set entirely until an ad-hoc question exposed the
        # gap -- see docs/RAG-EVAL-NOTES.md. Its own MITRE text is written
        # in reconnaissance/intent language, not port-mechanism language,
        # so it needs a query phrased to match that, not "port scanning."
        "query": "active reconnaissance scanning of victim infrastructure before an attack",
        "expected_source": "T1595",
        "expected_section": None,
    },
    {
        "query": "what does it mean when a TCP connection ends with a reset instead of a normal close",
        "expected_source": "tcp-handshake-and-close-semantics",
        "expected_section": "The four `close_type` values",
    },
    {
        "query": "how does the TCP three-way handshake work",
        "expected_source": "tcp-handshake-and-close-semantics",
        "expected_section": "The three-way handshake",
    },
    {
        "query": "what does a missing handshake state mean for a UDP flow",
        "expected_source": "tcp-handshake-and-close-semantics",
        "expected_section": "What `handshake_completed` means in this system",
    },
    {
        "query": "scanning a range of IP addresses to find live hosts on a network",
        "expected_source": "T1595.001",
        "expected_section": None,
    },
    {
        "query": "automated scanning of a target for known software vulnerabilities",
        "expected_source": "T1595.002",
        "expected_section": None,
    },
    {
        "query": "using a wordlist to brute-force guess valid directory or file names on a server",
        "expected_source": "T1595.003",
        "expected_section": None,
    },
    {
        "query": "enumerating which network services are running on a remote host",
        "expected_source": "T1046",
        "expected_section": None,
    },
    {
        "query": "listing other computers reachable on the local network",
        "expected_source": "T1018",
        "expected_section": None,
    },
    {
        "query": "passively capturing network traffic to gather credentials or information",
        "expected_source": "T1040",
        "expected_section": None,
    },
    {
        "query": "finding accessible shared folders on other machines",
        "expected_source": "T1135",
        "expected_section": None,
    },
    {
        "query": "how much worse does the anomaly detector perform on network captures it wasn't trained on",
        "expected_source": "ml-model-notes",
        "expected_section": "3. The baseline does not generalise to unseen captures",
    },
    {
        "query": "does the detector's high precision hold up in a realistic environment where attacks are rare",
        "expected_source": "ml-model-notes",
        "expected_section": "2. Precision collapses at a realistic base rate",
    },
    {
        "query": "is the current detection threshold the mathematically best choice or just a starting point",
        "expected_source": "ml-model-notes",
        "expected_section": "8. The 5% threshold is a committed choice, not an optimum",
    },
    {
        "query": "has the missed-detection tracking feature actually been proven against a real false negative yet",
        "expected_source": "ml-model-notes",
        "expected_section": "Known test gap: `missed_by_model` is unexercised against real data",
    },
]


def matches(result: dict, expected_source: str, expected_section: str | None) -> bool:
    if result["source"] != expected_source:
        return False
    if expected_section is None:
        return True
    return result["title"] == expected_section


def main() -> None:
    hit_at = {1: 0, 3: 0, 5: 0}
    rows = []

    for case in EVAL_QUERIES:
        results = retrieve(case["query"], top_k=5)
        rank = None
        for i, r in enumerate(results, start=1):
            if matches(r, case["expected_source"], case["expected_section"]):
                rank = i
                break

        for k in hit_at:
            if rank is not None and rank <= k:
                hit_at[k] += 1

        rows.append({
            "query": case["query"],
            "expected_source": case["expected_source"],
            "expected_section": case["expected_section"],
            "rank": rank,
            "top_result": f"{results[0]['source']} / {results[0]['title']}" if results else None,
            "top_similarity": results[0]["similarity"] if results else None,
        })

    n = len(EVAL_QUERIES)
    print(f"Queries: {n}")
    for k in (1, 3, 5):
        print(f"hit@{k}: {hit_at[k]}/{n} ({hit_at[k]/n:.0%})")
    print()
    for row in rows:
        status = f"HIT (rank {row['rank']})" if row["rank"] else "MISS"
        print(f"[{status}] {row['query']}")
        print(f"    expected: {row['expected_source']} / {row['expected_section']}")
        print(f"    top result: {row['top_result']} (similarity {row['top_similarity']})")
        print()


if __name__ == "__main__":
    main()
