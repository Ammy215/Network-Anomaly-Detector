# NetSentinel — RAG Retrieval Evaluation

> **Status:** Phase 6 (RAG knowledge base, retrieval only). Same honesty
> standard as `docs/ML-MODEL-NOTES.md`: the real hit rate is reported
> below, including misses, disproven hypotheses, and bugs found along
> the way — not rounded up.

## What was measured, and why this way

The queries in `backend/scripts/eval_rag_retrieval.py` were written by
inspecting the ingested corpus's chunk inventory — **the expected
answer for each was fixed before retrieval was run against it, not
picked afterward to match whatever came back.** This is the same
ground-truth-before-results discipline `ML-MODEL-NOTES.md` applies
throughout (e.g. the 5% threshold "chosen before seeing results").

**Metric: hit@k**, not full precision/recall. With exactly one gold
chunk (or gold section) per query, recall@k *is* hit@k by definition,
and precision@k would just reduce to 1/k on a hit or 0 on a miss — hit@k
reported directly at k=1, 3, 5 is more informative for a corpus this
size (42 chunks) than the full IR evaluation machinery a much larger,
multi-relevant-document corpus would need.

A query counts as a hit if the expected source (a MITRE technique ID, or
a protocol-notes/model-notes document) appears at or before rank k —
and, where a specific section was named as the expected answer (not just
"anything from this document"), only a chunk from that exact section
counts.

## Results

| metric | value |
|---|---|
| hit@1 | **15/16 (94%)** |
| hit@3 | 15/16 (94%) |
| hit@5 | **16/16 (100%)** |

## Per-query results

| query | expected | result |
|---|---|---|
| many connections to different ports in a short time | port-scan-behavioral-signature | HIT, rank 1 (0.44) |
| active reconnaissance scanning of victim infrastructure before an attack | T1595 Active Scanning | HIT, rank 1 (0.69) |
| TCP connection ends with a reset instead of a normal close | tcp-handshake-and-close-semantics / close_type values | HIT, rank 1 (0.65) |
| how does the TCP three-way handshake work | tcp-handshake-and-close-semantics / three-way handshake | HIT, rank 1 (0.66) |
| missing handshake state for a UDP flow | tcp-handshake-and-close-semantics / handshake_completed states | HIT, rank 1 (0.76) |
| scanning a range of IP addresses to find live hosts | T1595.001 Scanning IP Blocks | HIT, rank 1 (0.48) |
| automated scanning for known software vulnerabilities | T1595.002 Vulnerability Scanning | HIT, rank 1 (0.67) |
| wordlist brute-force of directory/file names | T1595.003 Wordlist Scanning | HIT, rank 1 (0.58) |
| enumerating network services on a remote host | T1046 Network Service Discovery | HIT, rank 1 (0.56) |
| listing other computers reachable on the local network | T1018 Remote System Discovery | HIT, **rank 4** (0.43) |
| passively capturing traffic to gather credentials/info | T1040 Network Sniffing | HIT, rank 1 (0.64) |
| finding accessible shared folders on other machines | T1135 Network Share Discovery | HIT, rank 1 (0.67) |
| detector performance on captures it wasn't trained on | ML-MODEL-NOTES §3 (generalisation) | HIT, rank 1 (0.50) |
| does high precision hold up at a realistic base rate | ML-MODEL-NOTES §2 (precision collapse) | HIT, rank 1 (0.52) |
| is the detection threshold the optimal choice | ML-MODEL-NOTES §8 (threshold not an optimum) | HIT, rank 1 (0.49) |
| has the missed-detection feature been proven against a real case | ML-MODEL-NOTES known test gap | HIT, rank 1 (0.45) |

`T1018` never ranked 1st for its query, but did move from outside the
top 5 to rank 4 once the corpus-cleaning fix below landed (see that
section for why).

## Investigation: "connecting to many ports quickly" retrieved no MITRE chunks in the top 3

This was flagged after the initial eval run passed — a fair challenge,
since the original 15-query set never actually tested whether T1595 (the
parent Active Scanning technique) was retrievable *at all*. Two real
things were found chasing it down, and one hypothesis that turned out
to be wrong. All three are recorded here rather than quietly fixed and
forgotten.

**First, a real ingestion bug, unrelated to relevance ranking.** MITRE's
technique descriptions contain inline cross-reference links like
`[Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593)`
pointing at *other* techniques. The original cleaning step stripped
citation markers and HTML tags but not these — so a technique's
embedded text included other, unrelated techniques' names as if they
were its own content. Fixed in `mitre_source.py::_clean_description`.

**Second, this fix exposed a real idempotency bug in the ingestion
script.** Cleaner text meant two MITRE descriptions no longer needed
sub-splitting, so they went from 2 chunks to 1 — but the ingestion
script only ever called `upsert()`, which adds and updates, never
deletes. The now-unused chunk ids (`mitre:T1016:1`, `mitre:T1040:2`)
were left behind as silent orphans in the collection. Fixed by having
`ingest_rag_corpus.py` diff the fresh chunk-id set against what's
currently stored and delete anything no longer produced, *before*
upserting. Verified: a stale-producing run now reports exactly which
ids it removed, and two immediately-consecutive clean runs hold steady
at 42 → 42 with zero removals.

**Third — and this is the actual answer to the original question — my
own hypothesis that the link-stripping fix would resolve T1595's low
score for "connecting to many ports quickly" was tested and was
***wrong***.** Measured effect: similarity moved from 0.0298 to 0.0400
— real, but nowhere near enough to explain the original observation.
The real explanation, found by reading what MITRE's own T1595
description actually says: it's written in **reconnaissance-intent
language** ("adversaries execute active reconnaissance scans... probes
victim infrastructure via network traffic") — it never mentions ports
at all. **T1046 (Network Service Discovery)** is the technique whose
own text explicitly says "port, vulnerability, and/or wordlist scans,"
which is why it — not T1595 — kept surfacing for port-specific
phrasing. This was confirmed directly: a query written to match T1595's
actual language ("active reconnaissance scanning of victim
infrastructure before an attack") retrieves it at **rank 1, similarity
0.69**, reproducibly. T1595 was never unreachable — the original eval
set simply never asked it a question its own text could answer, and
that gap is now closed (added as the second row in the results table
above).

**The honest takeaway**: this was retrieval behaving correctly, not a
defect — a mechanism-phrased query (ports, connections) should and did
favor the mechanism-phrased sources (T1046, the protocol-notes docs)
over an intent-phrased source (T1595). The real bugs found along the
way (link noise, stale-chunk orphaning) were genuine and are fixed; the
ranking behavior that triggered the investigation was not a bug.

## The T1018 result, looked at directly

For "listing other computers reachable on the local network," T1018
(Remote System Discovery) now ranks 4th (previously outside the top 5,
before the link-cleaning fix incidentally improved it) at similarity
0.43. The top results for this query are still all genuinely
Discovery-tactic techniques — the embedding model correctly finds the
right neighbourhood, it just doesn't put this one specific technique
first among several closely related "find things on the network"
techniques. This reads as the same class of limitation as the T1595
investigation above: a small (384-dimension) local embedding model's
fine-grained discrimination between semantically overlapping technique
descriptions is imperfect, and a generically-phrased query ("other
computers" rather than "hosts" or "systems," T1018's own vocabulary)
makes it worse. Left as originally phrased rather than tuned to score
better, per the discipline stated above.

## Known limitations of this evaluation

1. **Small eval set (16 queries) against a small corpus (42 chunks).**
   94% hit@1 / 100% hit@5 here are real, honestly-measured numbers for
   this specific corpus and these specific queries — not a claim that
   generalises to arbitrary future queries or a much larger corpus.
2. **One gold answer per query.** Several queries could plausibly match
   more than one chunk; the eval set only checks against the single
   answer decided on before running it, not whether other retrieved
   chunks were also reasonable.
3. **No negative queries.** Every query here has a genuinely relevant
   chunk somewhere in the corpus. The set doesn't test what retrieval
   returns for a query with no good match at all — worth adding once
   Phase 7 puts an LLM behind retrieval.
4. **The embedding model is `all-MiniLM-L6-v2`** (Chroma's bundled
   default, 384 dimensions, no API key) — chosen for zero cost and zero
   external dependency over a heavier local model
   (`sentence-transformers`/`BAAI/bge-small-en-v1.5`) or a hosted API.
   Both the T1595 investigation and the T1018 result are plausible early
   signals that a stronger embedding model could measurably improve
   fine-grained discrimination between closely related techniques —
   worth revisiting if Phase 7 surfaces more cases like this in
   practice, rather than switching pre-emptively on two data points.

## Reproducing this

```
python scripts/ingest_rag_corpus.py   # idempotent; reconciles stale chunks
python scripts/eval_rag_retrieval.py
```

Requires the embedding model already downloaded (automatic on first
use, ~80MB, one-time).
