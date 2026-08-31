# NetSentinel — Performance Measurement & Fixes (Phase 13)

> **Status:** Phase 13 (performance pass). A permanent record, not a
> changelog. Every number below is a real measurement against the running
> app with real data (3,100+ flows), not an estimate — including two
> measurement-methodology mistakes I made and corrected mid-phase, left in
> rather than quietly fixed, because the honesty standard this project
> holds (`ML-MODEL-NOTES.md`, `SECURITY-TESTING-NOTES.md`) applies to how
> a number was produced, not just what it says.

## Method

Per `docs/PROJECT.md` §23: measure before optimizing, fix only what
measurement shows is a real problem, never trade accuracy for speed
without flagging it and getting a decision. All numbers use the real
Supabase-backed backend, a real Chromium session, and real captured
network traffic — no synthetic flows were inserted into the product.

**Two measurement-methodology corrections, made before any numbers were
trusted:**
1. My first API-latency pass used a **fresh `httpx` connection per
   call to `localhost`**. Windows resolves `localhost` by trying IPv6
   before falling back to IPv4, adding ~1.5-2s of pure connection-setup
   artifact per call — not real server latency. Fixed by using
   `127.0.0.1` with one persistent connection, matching how a real
   browser actually behaves.
2. My first frontend-timing pass used Playwright's `networkidle` as the
   "page is done loading" signal. It never reliably fires in this app:
   the sidebar polls `/api/capture/status` every 5 seconds
   (`Sidebar.jsx:14`), so the network is never truly idle. Fixed by
   waiting for real rendered content (skeleton placeholders clearing, or
   specific text) instead.

Both are described in full where they apply below so the corrected
numbers can be trusted at face value.

## Baseline measurements (before any fix)

### 1. PCAP pipeline (real 5MB / 4,881-packet capture of real browsing traffic)

| stage | time | % of total |
|---|---|---|
| **tshark/PyShark parsing** | **58.1s** | **87%** |
| flow assembly overhead (on top of parsing) | noise-level (~0s) | — |
| feature extraction (90 flows) | 0.000s | 0% |
| insert_flows (DB) | 1.6s | 2.5% |
| insert_flow_features (DB) | 0.27s | 0.4% |
| host_profiles rebuild (full-DB, 3,231 flows) | 2.3s | 3.5% |
| scoring | 4.2s | 6.5% |
| **TOTAL** | **64.4s** | |

Throughput: **~84 packets/second**. Confirmed on a second, larger real
capture (17MB / 15,750 packets, built by combining real captured packets
— documented honestly, not a single continuous capture): **162.1s,
~97 packets/second** — consistent rate, roughly linear scaling, no
severe degradation but no improvement either. This is a genuine
fixed-rate bottleneck in the tshark-subprocess-per-packet approach, not
a one-time startup cost.

**Extrapolated** (not measured directly — stated as an extrapolation):
a full 50MB file at this traffic density carries roughly 48,000 packets
→ **~8-9 minutes of pure parsing alone**, before any DB write or
scoring. `POST /api/pcap/upload` is fully synchronous, so this blocks
one HTTP request for the entire duration.

### 2. API latency (corrected method: persistent connection, 127.0.0.1)

| endpoint | latency | note |
|---|---|---|
| baseline auth overhead (`/api/integrations/status`) | 160-215ms | JWT verify + uncached `user_profiles` lookup — present on every authenticated request |
| `GET /api/models` | 373-453ms | |
| `GET /api/flows/{id}/score` | 347-461ms | |
| `GET /api/verdicts/summary` | 920ms-1.2s | 4 sequential round-trips |
| `GET /api/flows/source-files` | 920ms-1.0s | paginated, 4 round-trips over all flows |
| `GET /api/flows` (default, 500-cap) | 1.8-3.6s | |
| `GET /api/flows?source_file=...` (68-row result) | **2.8-3.1s** | **slower than the unfiltered default** — see Fix 1 |
| `POST /investigate` fetch=true (cold, real Groq) | 16.7s | inherent — 3 LLM models, sequential pipeline; not addressed this phase |
| `POST /investigate` fetch=false (warm/cached) | 794-841ms | cache exists, but flow was re-fetched in full before the cache check — see Fix 2 |
| `POST /enrichment` fetch=true (cold, real 4 providers) | 5.6s | inherent — waiting on 4 external APIs; not addressed this phase |
| `POST /enrichment` fetch=false (warm/cached) | ~1,024ms | same re-fetch-before-cache pattern, structurally different — see Fix 2's enrichment note |
| `POST /rag/search` (no LLM, pure vector) | 605-907ms | measured fine, left untouched |

### 3. Frontend load times (real browser, real session, 3,100+ flows)

| page | cold | warm |
|---|---|---|
| initial app load (shared parallel fetch) | ~16.4s | — |
| Overview (reuses shared state) | (included above) | 383ms |
| Flows (fetches independently, every visit) | 3.8s | 3.1s |
| Investigations (reuses shared state) | 126ms | 131ms |
| Live Capture | 504ms | 444ms |
| Model dashboard (reuses shared state) | 128ms | 131ms |

**Root cause, cross-validated against API latency #2**: `App.jsx`'s
top-level effect fetches every flow across **all 15 source files in
parallel** (`Promise.all`), each hitting the same inefficient filtered
`/api/flows` endpoint (2.8-3.1s each). That's the entire explanation for
the cold start.

### 4. Row-expand mount cost (Phase 8 known item)

No prior measurement of "~400-500ms" exists anywhere in the repo —
searched docs, commit history, code comments. This is a fresh baseline.
**803-1077ms** across 3 real rows: the real `GET /api/flows/{id}/score`
fetch (~350-460ms) plus component/animation mount overhead
(~450-620ms).

### 5. Ingress cap (F10 recheck)

Unchanged from Phase 12: no request-size middleware existed anywhere.
The 50MB cap only limited *parsed* bytes, post-spool.

### 6. Large-file handling

Tested up to 17MB/15,750 real packets — no crash, no OOM (PyShark
streams rather than loading the whole file into memory). The danger is
wall-clock time, not memory: see the extrapolation in §1.

---

## Fixes applied (priority order given by the author)

### Fix 1 — `list_flows()`'s score-fetch, scoped instead of whole-table

**Root cause.** Any filtered or sorted flows query
(`needs_wide_search`) called `_scores_for_model()`, which paginated
through **every** score row in the table (4 round-trips over ~3,100+
rows via `.range()`), regardless of how few flows the filter actually
matched. The code comment explained *why* it avoided a direct `.in_()`
call — PostgREST fails above ~600 ids in one request ("JSON could not
be generated") — but the chosen workaround (fetch everything,
unconditionally) didn't scale down for a small result either.

**The trade-off, and why a straight chunked `.in_()` wasn't the whole
answer.** My first fix replaced the whole-table pagination with a
chunked `.in_()` scoped to the actual result set
(`_scores_for_flow_ids`, batch size 400 — safely under the documented
~600 cliff). Measured immediately after:

| query | before | first fix attempt | 
|---|---|---|
| `source_file` filter (68 rows) | 2.8-3.1s | **828ms-1.4s** (real win) |
| `sort=score_desc`, no filter (≈ whole table) | *(not separately measured before — see below)* | **4.97-5.6s** (worse) |

The score-sort case got *worse*: with no `source_file` filter, the
matching set is essentially the whole table (~3,200 rows), and chunking
those ids into batches of 400 needs **9** round-trips of `.in_()` calls
— each one also paying the cost of enumerating hundreds of ids in the
request itself. The original whole-table `.range()` pagination needed
only 4 round-trips *with no ids to enumerate at all*. Scoping by id only
pays off when the result set is meaningfully smaller than the table;
when it isn't, plain pagination is cheaper.

**Final fix: a hybrid**, dispatched on whether a `source_file` filter
actually narrows the result:
- `source_file` set → scoped, chunked `.in_()` (`_scores_for_flow_ids`,
  batch 400) — a real subset, worth scoping to.
- Bare `sort=score_desc`/`score_asc` with no filter → the original
  whole-table `.range()` pagination, kept intact and renamed
  (`_scores_for_all`) rather than removed, since it's still the right
  tool for that case.

**Real before/after, final version:**

| query | before | after (final, hybrid) |
|---|---|---|
| `source_file` filter (68 rows) | 2.8-3.1s (median ~2981ms) | **828ms-3.3s, median 1133ms** |
| `sort=score_desc`, no filter (500-flow view, ~3,200-row scope) | *(see note)* | **3.6-4.2s, median 3935ms** — unchanged, by design |

The score-sort row is *not* a regression and *not* an improvement — the
hybrid routes it back to code that is identical to what ran before any
of this phase's changes, so its performance is the original, unchanged
baseline, correctly preserved. I don't have a clean pre-Phase-13 number
for that *exact* query shape (my original baseline measured the
`source_file` filter and the plain default, not a bare score-sort), so
I'm stating this as "restored to original," not claiming a number I
didn't measure before touching the code.

**Verification**: 10 unit tests (`tests/test_performance_phase13.py`)
pin the chunking behavior, the empty-input case, the batch-size ceiling,
and — critically — that the whole-table path never calls `.in_()` at
all. Full suite: 71 passed.

### Fix 2 — investigate/enrichment: cache check before the flow re-fetch

**Investigate — fixed in full.** The cache lookup
(`get_cached_investigation`) is keyed on `flow_id` alone and needs no
other data, so it now runs **first**, before the role check, the rate
limit, and the flow re-fetch. This is safe, not just faster:
`investigations.flow_id` has `ON DELETE CASCADE` from `flows`, so a
cached row can only exist for a flow that was flagged (this endpoint's
own gate) at cache-write time and still exists now — nothing about
*who* can see *what* changes.

Real before/after (warm cache hit, `fetch=false`):

| | before | after |
|---|---|---|
| round-trips on a cache hit | 4 (flow+features join, active model, score, then cache) | **1** (cache only) |
| measured latency | 794-841ms | **335-909ms** (median 578ms) |

The wide variance in both is real Supabase-side network jitter for a
single call (consistent with the raw-latency baseline elsewhere in this
doc); the structural win — 4 round-trips collapsed to 1 — is the actual
fix, and it shows up as the new minimum being roughly where the old
warm-case *floor* for a single round-trip already sat.

**A correctness bug found and fixed as a direct consequence**: before
this change, `fetch=true` on an *already-cached* flow still ran the
role check and **charged the rate limit** — a viewer got a wrongful 403,
and an analyst burned a token from their hourly budget, for a request
that was never going to make an LLM call. Verified directly: a viewer
calling `fetch=true` on a cached flow now correctly returns `HTTP 200,
cached=true` instead of `HTTP 403`.

**Enrichment — not reordered, and here's why.** The identical change
isn't safely available. Enrichment's cache key is the **IP**, not the
flow_id, and the IP is only known after reading the flow's `src_ip`/
`dst_ip` — there's no way to check the cache before some flow lookup.
Worse, the `is_anomalous` gate that runs before the cache check isn't
just an efficiency artifact here: enrichment's cache is shared **across
flows** by IP, so if a different (still-flagged) flow triggered the
enrichment for an IP, skipping the gate would let a **currently
non-flagged** flow read that cached result too — a real access-control
change, not a pure speed win. That's exactly the "don't trade accuracy
for speed without flagging it" case, so I left it as-is rather than
deciding it myself. `get_flow_with_score()` (the function enrichment
calls) is already the minimal query for what it needs (id/src_ip/dst_ip
+ is_anomalous, no unnecessary joins) — there's no free efficiency gain
available here without either a schema change or a real decision about
loosening that gate, and I'm not making that decision unilaterally.

**Reviewed with the author (2026-08-31): confirmed as a known future
improvement, not something to build in this phase.** The real fix isn't
"skip the gate" — it's giving enrichment's cache a key design that
already accounts for read-access to the underlying flow, not just the
IP, so a cache hit and an authorization check aren't structurally at
odds. That's a genuine design change (likely: keying or gating
per-flow rather than purely per-IP, or recording which flagged flow(s)
legitimately earned an IP its cached entry), out of scope for a
performance pass. Left for a future phase.

### Fix 3 — request-size middleware (F10 follow-up, local mitigation only)

A new `@app.middleware("http")` in `main.py` rejects any request with a
declared `Content-Length` over 100MB (`max_request_body_bytes`, double
the existing 50MB PCAP-specific cap) with an immediate 413 — **before**
Starlette reads or spools any of the body. This is deliberately a
*different* safety net from `max_upload_size_bytes`: that one bounds
what gets *parsed* inside the PCAP handler, after the whole request is
already spooled to disk; this one bounds what gets *accepted at all*,
for every route.

**Explicitly not a complete fix, stated plainly**: a client using
chunked transfer-encoding declares no `Content-Length`, so this check
simply doesn't apply to it. Real streaming/chunked-upload enforcement
needs a background-job upload architecture — see "Explicitly out of
scope" below.

Verified: a request declaring a Content-Length over the limit is
rejected with 413 before any body is read; a normal request is
unaffected; a malformed (non-numeric) header doesn't crash the
middleware. 3 tests, full suite still 71 passed.

---

## Re-measured as requested: did the side effects show up?

**App.jsx cold start — yes, substantially, and directly attributable.**
The root cause (15 parallel calls to the filtered `/api/flows`
endpoint) is exactly what Fix 1 changed.

| | before | after |
|---|---|---|
| cold app-level load | ~16.4s | **~5.9s** (~64% reduction) |

**Flows-page's own visit cost and row-expand cost — moved, but NOT
attributable to Fix 1.** Checking precisely rather than assuming:
`FlowsPage.jsx` in its default state (`sourceFileFilter=''`,
`scoreSort='started_desc'`) sends **no query parameters at all** — it
hits the plain, unfiltered `GET /api/flows` branch, which Fix 1 never
touched. Row-expand depends on `GET /api/flows/{id}/score`
(`models.py`), a completely different function, also untouched.

| | before | after |
|---|---|---|
| Flows page visit (cold / warm) | 3.8s / 3.1s | 2.7s / 2.0s |
| row-expand (3 real rows) | 803-1077ms | 556-848ms |

Both numbers did move, and I'm reporting them exactly as measured — but
attributing them to Fix 1 would be wrong given the code path is
unchanged. The most honest explanation is ordinary Supabase-side network
latency variance between two separate real measurement runs at
different times, the same variance visible throughout this whole
document (e.g., a single warm cache-hit ranging 335-909ms above). I'm
flagging this explicitly because the instruction was "don't assume
improvement," and assuming these two shared Fix 1's root cause would
have been exactly that.

---

## Explicitly out of scope for this phase

**Chunked/background PCAP processing.** This is the real fix for the
tshark-parsing bottleneck (§1), and it's a genuine feature — a job
queue, progress polling or SSE, a way to walk away from an upload and
come back — not a performance tweak, and it belongs in a
deployment-focused phase. Flagging it here with the concrete numbers
that make the case: **current architecture, ~84-97 packets/second,
would take ~8-9 minutes to parse a full 50MB file synchronously**,
likely exceeding typical browser and reverse-proxy default timeout
thresholds (commonly 30-120s) well before parsing finishes. This is not
a "someday" concern — it's the single largest number in this whole
document.

**The 50MB cap itself** stays as-is and undecided. Fix 3 adds a
separate, larger (100MB) global safety net against absurd requests, but
does not touch or re-justify the existing PCAP-specific cap — that
requires the chunked-upload work above to actually be safe to raise.

**Full ingress-limiting** (true enforcement against chunked
transfer-encoding, a reverse-proxy `client_max_body_size`) remains the
Phase 12 F10 risk-accept, unchanged. Fix 3 is a real, cheap improvement
on top of that risk-accept, not a replacement for it.

---

## Measured and found fine — left untouched

- **Feature extraction** (0.000s for 90 flows) and **insert_flow_features**
  (0.27s) — no cost worth chasing.
- **RAG search** (`/api/rag/search`, 605-907ms, no LLM call) — reasonable
  for a vector-similarity query plus the fixed per-request auth cost.
- **Investigations, Model dashboard, Overview once loaded** (110-383ms
  warm) — fast, because they reuse `App.jsx`'s shared state rather than
  fetching independently.
- **Live Capture page** (444-504ms) — reasonable for its own small set of
  calls.
- **`GET /api/models` and `GET /api/flows/{id}/score`** (350-460ms) —
  proportionate to the fixed per-request auth overhead plus one real
  query; not touched.
- **Large-file memory behavior** — PyShark streams packets rather than
  loading the whole file at once; no OOM risk was found even at 17MB.
  The danger measured in this phase is wall-clock time, not memory.

## No accuracy or correctness was traded for speed

Every fix in this phase is a pure latency change with identical output:
`list_flows()`'s hybrid returns the same rows and scores as before,
`investigate`'s reordering returns the same cached payload (and fixes a
real bug in who could see it), and the request-size middleware only
rejects requests no legitimate use case would ever send. The one place
a real behavior change was *available* — relaxing enrichment's
flagged-only gate to let a cache check run earlier — was identified,
explained, and deliberately **not** made without asking, per this
project's standing rule.

## Known gaps in this measurement pass

- Investigate/enrichment's **cold** (uncached) latency (16.7s / 5.6s) is
  inherent to calling real external LLM/threat-intel services
  sequentially — not addressed this phase, and not obviously fixable
  without parallelizing calls that may have real reasons to be
  sequential (self-check depends on the explain step's output). Worth a
  dedicated look in a future phase, not measured further here.
- The large-file test reached 17MB/15,750 packets, not the full 50MB —
  the ~8-9 minute figure for a full-size file is an extrapolation from a
  consistent measured rate, not a literal end-to-end run (deliberately,
  to avoid spending 10+ minutes confirming a conclusion two consistent
  data points already support).
- Supabase round-trip latency itself (~150-460ms per call, even warm)
  is the floor under almost every number in this document. It wasn't
  investigated as an optimization target this phase — that's a hosting/
  project-tier question, not an application-code one.
