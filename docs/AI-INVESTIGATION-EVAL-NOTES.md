# NetSentinel — AI Investigation Pipeline Evaluation

> **Status:** Phase 7 (LLM investigation pipeline: classify -> retrieve ->
> explain -> self_check). Same honesty standard as `docs/ML-MODEL-NOTES.md`
> and `docs/RAG-EVAL-NOTES.md`: real results below, including a real
> disagreement between two runs on the same flow and a real citation the
> self-check flagged — not smoothed over.

## What was measured, and why this way

`backend/scripts/eval_investigations.py` runs the full pipeline against 5
real flow_ids from this project's own captures, picked by inspecting the
database first (their expected behavior noted in the script before
running it) — the same ground-truth-before-results discipline used
throughout this project. This script cannot and does not auto-grade
whether a narrative is a *good* investigation; that judgement is the
human test gate (Ammar reading 3 of these directly). What it does check
automatically: every output is schema-valid, every citation's source id
is actually one of that flow's retrieved chunks, and `mitre_techniques`
is never populated from zero retrieved context.

Provider: Groq (`openai/gpt-oss-120b` for classify/explain,
`openai/gpt-oss-20b` for self_check), chosen over Google AI Studio/Gemini
specifically because Groq's free tier has an account-wide no-training
policy and Gemini's free tier does not — see the Phase 7 plan for the
full comparison. Verified live: Gemini was never wired up or tested here.

## Results summary

| flow | classify | mitre_techniques | self_check |
|---|---|---|---|
| `6fddbdb2` (nmap, port 1900) | `unknown` (0.9) | `[]` | clean |
| `428cdde8` (nmap, port 80) | `port_scan` (0.85) | `[T1595, T1046]` | clean |
| `76fa9bb7` (analyst-verdicted true_positive) | `port_scan` (0.85) | `[T1595, T1046]` | **flagged 1 citation** |
| `3988afec` (completed-handshake, non-scan-shaped) | `unknown` (0.85) | `[]` | clean |
| `fccfd0e7` (idle-capture, ambiguous single flow) | `unknown` (0.75) | `[]` | clean |

Full raw output (every field, every run) is reproducible via `python
scripts/eval_investigations.py` — not pasted in full here to keep this
document readable, but nothing below is a summary that hides a miss.

## A real, non-engineered self-check catch

Flow `76fa9bb7` (a flow you've already independently verdicted
`true_positive`) is the one case here where `self_check` actually flagged
something — not the deliberately-broken test case from
`test_llm_pipeline.py`, a real one that came out of a normal run.

The `explain` step's citation for `protocol_notes:port-scan-behavioral-signature:1` read:

> "What a port scan literally does... This is mapped in MITRE ATT&CK as
> Active Scanning (T1595) ... and the host-side response to it as Network
> Service Discovery (T1046)."

Every fragment in that excerpt is real text from the chunk — but it's
three non-contiguous fragments spliced together with the model's own
"..." connectors, not an actual contiguous quote. Checked directly: the
longest single contiguous match between this excerpt and the real chunk
text covers only 36% of the excerpt (`_citation_supported`'s threshold is
60%), so `deterministic_self_check` correctly flagged it as
`invalid_citations`.

Is this a "fabrication"? No — nothing false was claimed, and the
technique attribution is accurate. But allowing splice-with-ellipsis
citations to pass silently would open the door to a much more dangerous
version of the same pattern (splicing fragments in a way that *does*
change the meaning), so flagging it for human review is the correct,
conservative behavior — exactly what a self-check guardrail is for. This
is real evidence for the test gate's "does the self-check ever actually
catch something" beyond the one case engineered in
`test_llm_pipeline.py::test_self_check_node_catches_fabricated_citation_end_to_end`.

## A real limitation found: classification isn't fully stable on ambiguous flows

Flow `6fddbdb2` was classified `unknown` (0.9 confidence) in this eval
run. An earlier standalone call to the same flow (same code, same data,
run manually during verification) classified it `port_scan` (0.94
confidence) instead. Both reasonings are individually defensible reads
of genuinely ambiguous data — this specific flow has a **completed**
TCP handshake before the RST, which is atypical for the classic
no-handshake scan signature this project's other 999 nmap-capture flows
show, so a reasonable classifier could land either way. This is real
run-to-run non-determinism from the LLM's own sampling, not a bug in the
pipeline: `classify_node` makes one call with no fixed seed, so a
borderline case can genuinely go either way between runs.

**Known limitation, stated rather than hidden**: per-flow classification
only ever sees one flow's own statistics — it has no visibility into
whether the same source IP contacted many other destination ports in the
same window (that aggregate signal already exists in this project's
`host_profiles` table, computed in Phase 2, but Phase 7 does not
currently feed it into `classify`). For an isolated flow like this one,
that's a genuine, structural source of ambiguity no amount of prompting
resolves — worth a fast follow (feeding `host_profiles.
unique_dst_ports_contacted` for the flow's source IP into `classify`'s
input) if this turns out to matter in practice, not built pre-emptively
here per this project's measure-before-optimizing discipline.

## The honest "no good mapping" cases

Three of the five flows (`6fddbdb2` in this run, `3988afec`, `fccfd0e7`)
classified `unknown` and correctly produced `mitre_techniques: []` with
no fabricated technique — including `3988afec`, the flow deliberately
chosen because it has a completed handshake and a single destination
(not scan-shaped at all) despite being flagged anomalous, and `fccfd0e7`,
which retrieved a real `T1049` chunk but correctly declined to cite it
because the flow's own data didn't support that specific claim (the
`explain` prompt's "presence in retrieved context is necessary but not
sufficient to cite" rule, added after an earlier internal check found
weak/tangential chunks clearing the similarity floor for
`dns_tunneling`/`data_exfil` categories the corpus has zero real coverage
for).

## A real bug found and fixed during this eval

The first eval run crashed: Groq's `openai/gpt-oss-120b`, even under
strict `json_schema` mode, occasionally emits malformed JSON (observed:
`"confidence": 0. nine,` — a spelled-out digit mid-number breaking the
parser). The original retry logic only retried on HTTP 429 (rate
limiting); this is a different, genuinely transient generation failure.
Fixed in `groq_client.py`: also retry (bounded, same limit as 429) when
the error body's code is `json_validate_failed`. Confirmed: the eval
script failed once against this exact error before the fix, and ran
clean immediately after.

## Known limitations of this evaluation

1. **Small eval set (5 flows).** Real, honestly-measured results for
   these 5 flows from this project's own data — not a claim that
   generalises to arbitrary future flows.
2. **No formal repeat-run stability measurement.** The `6fddbdb2`
   disagreement was noticed because it happened to be re-run manually,
   not because this script runs each flow multiple times to measure
   consistency.
3. **`classify` has no cross-flow context** (see above) — a structural
   limitation, not a prompting one.
4. **Groq's own model may change behavior over time** (it's a hosted,
   evolving model) — these results reflect `openai/gpt-oss-120b` /
   `openai/gpt-oss-20b` as served on 2026-08-27.

## Reproducing this

```
python scripts/eval_investigations.py
```

Requires a real `LLM_API_KEY` (Groq, free, no card) in `backend/.env`.
Spends real free-tier quota: 5 flows x 3 Groq calls = 15 requests.
