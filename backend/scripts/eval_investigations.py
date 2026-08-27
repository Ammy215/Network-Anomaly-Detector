"""Phase 7 investigation eval set.

Real flow_ids from this project's own captures, picked by inspecting the
database first -- same ground-truth-before-results discipline as
`eval_rag_retrieval.py`. Each entry states what a CORRECT investigation
should roughly contain, decided before running the pipeline, not after.

This script prints the full pipeline output for each flow for manual
reading (per the Phase 7 test gate: "I pick 3 real flagged flows and read
the generated investigation myself"), plus automatic STRUCTURAL checks
that don't require human judgement:
  - the investigation and self-check outputs are schema-valid
  - every citation's source id is one of this flow's actual retrieved
    chunk ids
  - mitre_techniques is empty whenever retrieved_chunks was empty

It does NOT auto-grade whether the narrative is a *good* investigation --
that judgement is inherently the human test gate this script serves, not
something this script can honestly claim to automate.

Requires a real LLM_API_KEY in backend/.env (this spends Groq free-tier
quota: 5 flows x 3 calls = 15 requests).

Run:  python scripts/eval_investigations.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# The model's output frequently contains unicode punctuation (em-dashes,
# non-breaking hyphens) that Windows' default console codepage (cp1252)
# can't encode -- reconfigure to UTF-8 so this script works the same
# whether run interactively or redirected to a file.
sys.stdout.reconfigure(encoding="utf-8")

from app.services import supabase_client as sc  # noqa: E402
from app.services.llm.pipeline import run_investigation  # noqa: E402
from app.services.llm.schemas import InvestigationOutput, SelfCheckResult  # noqa: E402

EVAL_FLOWS = [
    {
        "flow_id": "6fddbdb2-dcbe-49f0-8bc4-aceefe2d6a79",
        "note": "capture_scan_nmap_lan.pcapng, dst_port 1900, no handshake, RST close.",
        "expect": "classify: port_scan. Corpus has real T1595/T1046 coverage for this "
        "shape -- mitre_techniques should be non-empty, citations should point at "
        "a real chunk about active scanning or service discovery.",
    },
    {
        "flow_id": "428cdde8-4911-4d68-adf4-d40cf14e2b56",
        "note": "capture_scan_nmap_lan.pcapng, dst_port 80, no handshake, RST close.",
        "expect": "Same shape as above -- a second, independent read of the same "
        "expected behaviour.",
    },
    {
        "flow_id": "76fa9bb7-6c36-4a66-9546-404a7e9ce0cd",
        "note": "Already analyst-verdicted true_positive in this project's own data.",
        "expect": "classify: port_scan (same RST/no-handshake shape as the flows "
        "above). Independent confirmation that the pipeline agrees with your own "
        "prior human judgement on this flow.",
    },
    {
        "flow_id": "3988afec-b59b-41dc-a2ed-87ba904731fb",
        "note": "capture1_browsing.pcapng -- flagged, but handshake_completed=True "
        "(a COMPLETED TCP handshake) to a single HTTPS destination, closed with "
        "RST. This is NOT the scan signature (no fan-out, handshake succeeded).",
        "expect": "This is the deliberately-hard case: per-flow data alone can't "
        "see that this is an isolated flow, not part of a scan pattern. Watch "
        "whether classify correctly lands on unknown/low-confidence rather than "
        "over-pattern-matching on 'RST' alone to port_scan.",
    },
    {
        "flow_id": "fccfd0e7-7d47-4261-92be-7454f24a3c01",
        "note": "capture4_idle.pcapng -- inbound from 20.42.65.94, single flow, no "
        "handshake, RST. Statistically similar to one scan probe, but this "
        "capture has no scanning activity in it at all (idle-traffic capture).",
        "expect": "Whatever classify decides, mitre_techniques/citations must "
        "still only be populated if a real chunk supports it -- this flow tests "
        "grounding discipline under a genuinely ambiguous single-flow signal, "
        "not classification 'correctness' (there may not be a single right "
        "answer from one flow's data alone -- see the note this script prints "
        "about that limitation).",
    },
]


def check_structural(flow_id: str, result: dict) -> list[str]:
    problems = []
    try:
        investigation = InvestigationOutput.model_validate(result["investigation"])
    except Exception as exc:
        return [f"investigation failed schema validation: {exc}"]
    try:
        SelfCheckResult.model_validate(result["self_check"])
    except Exception as exc:
        problems.append(f"self_check failed schema validation: {exc}")

    chunk_ids = {c["id"] for c in result["retrieved_chunks"]}
    for citation in investigation.citations:
        if citation.source not in chunk_ids:
            problems.append(f"citation source '{citation.source}' is not one of this flow's retrieved chunk ids")

    if not result["retrieved_chunks"] and investigation.mitre_techniques:
        problems.append("mitre_techniques is non-empty despite zero retrieved chunks")

    return problems


def main() -> None:
    for case in EVAL_FLOWS:
        flow = sc.get_flow_for_investigation(case["flow_id"])
        print("=" * 100)
        print(f"flow_id: {case['flow_id']}")
        print(f"note: {case['note']}")
        print(f"expected: {case['expect']}")
        print("-" * 100)

        if not flow:
            print("FLOW NOT FOUND -- skipping")
            continue
        if not flow.get("is_anomalous"):
            print("FLOW NOT FLAGGED under the active model -- skipping (investigation is flagged-only)")
            continue

        result = run_investigation(flow)

        print(f"classification: {result['classification']}")
        print(f"retrieved_chunks: {[c['id'] for c in result['retrieved_chunks']]}")
        print(f"investigation: {result['investigation']}")
        print(f"self_check: {result['self_check']}")

        problems = check_structural(case["flow_id"], result)
        if problems:
            print("STRUCTURAL PROBLEMS FOUND:")
            for p in problems:
                print(f"  - {p}")
        else:
            print("structural checks: OK")
        print()


if __name__ == "__main__":
    main()
