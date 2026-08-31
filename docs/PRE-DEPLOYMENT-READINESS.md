# NetSentinel — Pre-Deployment Readiness Report

> **Status:** local pre-deployment pass, run before Phase 14 (deployment).
> Same honesty standard as `ML-MODEL-NOTES.md`, `SECURITY-TESTING-NOTES.md`
> and `PERFORMANCE-NOTES.md`: every result below is a real request with a
> real response, a real number, or a raw log line. Nothing is rounded up.
> Where a check was weaker than it looks, or where my own test was wrong
> before the product was, it says so.

**Verdict: GO for Phase 14**, with three caveats recorded at the end that
are deployment-conditions, not blockers. Five defects were found; four
were fixed and re-verified during this pass, one is documentation drift
left open deliberately.

---

## Method and scope

Everything ran against `localhost` — backend on `:8000`, frontend on
`:5173`, the real Supabase project, the real Groq API, the real
threat-intel providers, and a real authorized Nmap scan of the author's
own router. Three real accounts (admin / analyst / viewer) plus one
throwaway account created and deleted for the signup check.

Cross-checks were made against the prior phases' own recorded numbers, on
the principle that **contradicting an earlier documented result is itself
a finding**. Two such contradictions were found (D1, D3).

**Gate-0 tripwires, all matched before any test ran:**

| tripwire | expected | actual |
|---|---|---|
| active model id | `381419f9-9e71-452f-8e16-46d353dd6491` | matched |
| threshold | `-0.138634784603203` | matched |
| RAG corpus size | 42 chunks (RAG-EVAL-NOTES) | 42 |
| integrations | both disabled | both disabled |
| capture running | no | no |
| audit-log high-water | — | id 134 |

---

## Defects found

Three were found by reading code *before* testing began; two more during
the pass itself. Four are fixed; D3 is left open by decision.

### D1 — Rate limiting was materially narrower than Phase 12 documented · **FIXED**

`SECURITY-TESTING-NOTES.md:160-162` claims *"a shared `global` bucket so
an attacker can't spread thinly across endpoints... capture 20/h."* Grep
found exactly **three** enforcement sites in the whole backend
(`pcap.py:59`, `investigate.py:76`, `enrichment.py:41`). So:

- the `capture` bucket was declared in `LIMITS` and **never wired** —
  start/stop were completely unthrottled;
- the `global` bucket only ever incremented inside `enforce()`, giving
  **zero** protection to `/api/flows`, `/api/admin/*`, `/api/rag/search`,
  `/api/capture/*`, `/api/models`, `/api/verdicts/*`;
- the `rate_limit()` dependency factory written for exactly this purpose
  was **dead code**, and its import of `auth` was what forced the global
  bucket into the wrong place;
- Phase 12's tests call `enforce()` directly, so the wiring gap was
  invisible to the suite.

**Fix.** Removed the dead factory (which broke the circular import),
charged `global` centrally in `auth.user_from_raw_token()` — the one
place every authenticated request provably passes, header and SSE alike —
and wired `capture` into start/stop.

**Verified on the running app:**
```
capture bucket   : 23 attempts -> {400: 20, 429: 3}, first 429 at #21
                   "Rate limit exceeded (20 per 3600s). Retry in 3593s."
global bucket    : 330 requests as VIEWER to /api/integrations/status
                   -> {200: 300, 429: 30}   (before: 330x200, zero 429)
```
Cost of the added check: none measurable — the authenticated-request floor
is **206ms median**, against Phase 13's 160-215ms baseline.

### D2 — Verdict TOCTOU race re-opened the F1 forged-attribution bug · **FIXED**

`upsert_flow_verdict()` read the row, then upserted, deciding whether to
include `created_by` from that read. Two concurrent first-time verdicts
could both read empty, both write `created_by`, and the loser's upsert
became an UPDATE that overwrote the winner's authorship while keeping the
winner's `created_at` — precisely the F1 bug, reachable through the
concurrency window. Worse, the Phase 12 audit compensation only writes
`previous_*` when `previous` is truthy, so the overwriting request logged
**nothing** about the overwrite, defeating the documented
"reconstruct from `audit_log`" recovery for exactly the case it exists for.

**Fix.** Insert-then-update, making the primary key itself the
serialization point instead of a prior read: exactly one concurrent INSERT
wins, every loser gets a duplicate-key error and falls to an UPDATE that
never touches `created_by`. No transaction needed, which matters because
PostgREST exposes none. `updated_by` is now written (the migration for it
is applied).

**Verified — 8 concurrent trials against real Supabase, 8/8 correct:**
```
every trial: created_by != updated_by, both preserved
audit entries: 2 per flow, 16 total
  INSERT winner -> no previous_* fields (correct: nothing preceded it)
  loser         -> previous_author=<winner>, overwrote_other_analyst=True
overwrite logged in 8/8 trials   (before the fix: 0/8 — loser saw previous=None)
```
*Honest note:* my first pass/fail criterion here was wrong. I asserted
`created_by == the first client-side sender`, but with a 0.3-0.8ms gap
between sends and hundreds of ms of network latency, client send order
does not determine DB arrival order. The rows were internally consistent
all along; the assertion was measuring something meaningless.

### D4 — A JWKS fetch failure was reported as "Invalid or expired session" · **FIXED**

Hit during the pass:
```
status=401  30072ms  {"detail":"Invalid or expired session."}
```
30.07s is exactly `PyJWKClient`'s default fetch timeout, and the backend
log shows **no `user_profiles` lookup** for that request — it failed
inside `_decode_token`. `PyJWKClient` cached keys for only 5 minutes, so
it re-fetched over the network regularly; a failed fetch surfaces as
`PyJWKClientError` (a `PyJWTError` subclass), which the blanket
`except jwt.PyJWTError` turned into a 401.

The user's session is valid. They are told to log in again, and logging in
again cannot help, because the fault is server→Supabase connectivity. On
hosted infrastructure with any egress flakiness this becomes random
spurious logouts, indistinguishable in logs from genuine auth failures.

**Fix.** `PyJWKClientConnectionError` (a dedicated subclass in PyJWT
2.13.0) → **503 "Authentication service temporarily unavailable"**.
Everything else — unknown `kid`, expired, bad signature, wrong audience —
stays 401. Cache lifespan raised 300s → 3600s (rotation is a rare
deliberate admin action; a restart still forces a refresh), fetch timeout
lowered 30s → 10s against a measured JWKS latency of 843-1563ms.

*Frequency, stated honestly:* the network was healthy when I measured it
(JWKS 6/6 OK, Supabase REST 12/12 OK, median 204ms). This is a
transient-triggered path, not a constant failure — but it runs on a timer
in normal operation, so it will be hit.

### D5 — Every SSE connection wrote a live bearer token into the log · **FIXED**

Phase 12 recorded token-in-query-string as "an accepted trade-off" but
never tested *where the token lands*. Measured:
```
INFO: 127.0.0.1:48877 - "GET /api/capture/stream?token=eyJhbGciOiJFUzI1NiIsImtpZCI6IjY1MTdlOTYz...
```
Uvicorn's access logger writes the full request line, query string
included. Every live-capture stream wrote a ~1h-valid credential to the
log in plaintext. This is worse deployed than locally: hosted platforms
aggregate stdout into retained, searchable log services, frequently
readable by more people than the database is.

**Fix.** A logging filter on `uvicorn.access` and the root logger redacts
`token=<value>`. The URL contract is unchanged; only the log sink is.

**Verified on the running server:**
```
SSE status=200 (endpoint still works)
TOKEN FRAGMENT PRESENT IN LOG: False   (before fix: True)
log line now: "GET /api/capture/stream?token=[REDACTED] HTTP/1.1" 200 OK
```
Confirmed alongside: a **viewer can open the live stream** (200). That is
the Phase 10 design (any authenticated role may view), now asserted rather
than assumed.

### D3 — Documentation/code drift, five instances · **OPEN, by decision**

Not fixed, because a mid-pass edit would mean the artifact under test was
no longer the one measured. All five are stale text, no behaviour:

1. `SECURITY-TESTING-NOTES.md:460-463` says F9's viewer default and F1's
   `updated_by` column are *"applied to files, not yet to the live
   database."* **Both are applied** — verified: `role` default is
   `'viewer'::text`, `updated_by` exists.
2. `AuthScreen.jsx:42` tells users *"new accounts start as analyst."*
   **Provably false** — this pass created an account that landed as
   `viewer` and was refused upload with 403.
3. `supabase_schema.sql:286` comment says *"(default role: analyst)"*
   above the trigger whose default is now `viewer`.
4. `upsert_flow_verdict()`'s docstring contradicted itself about
   `updated_by` (resolved incidentally by D2's rewrite).
5. `SECURITY-TESTING-NOTES.md:160-162`'s rate-limit claim was wrong until
   D1 was fixed; it now describes the code, but was inaccurate as written.

Item 2 is the one that matters — it misstates a privilege level to a user.

---

## Part A — regression across every phase's own gate

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | PCAP: valid / malformed / oversized / wrong-type | **PASS** | valid → 200, 16 flows, 10.4s · `.txt` → 400 *"File must be a .pcap or .pcapng file."* · header+garbage → 400 *"Could not parse this file as a packet capture."* · 51MB → 413 *"File exceeds the 50MB size cap."* |
| 2 | Feature extraction + scoring, no drift | **PASS** | `capture_scan_nmap_lan.pcapng`: **1039 flows** (documented 1039), **1000 flagged = 96.2%** (documented 1000 / 96.2%), **996** RST+no-handshake flows scoring **99.07-99.07** — inside ML-MODEL-NOTES' documented 99.07-100 band. Zero drift. |
| 3 | Verdict persists; explanation renders | **PASS** | verdict written, re-fetched `value='true_positive'` with note/author/timestamp intact; `/score` returns **8 contributing features** with contribution, flow value and baseline (Phase-4 gate: every anomaly lists its features) |
| 4 | Enrichment: public vs private | **PASS** | private→private: `{"applicable": false, "reason": "Both source and destination are private/internal IPs..."}` · public IP: `applicable=true`, all 4 providers `available=true` |
| 5 | RAG search + AI investigation | **PASS** | corpus **42 chunks**; investigation on a real scan flow → `port_scan` (0.7), **MITRE `['T1595','T1046']`**, 2 real citations, 5 chunks retrieved, **9.8s wall-clock** (cold run, not cache); self-check active — see below |
| 6 | All pages, real data, no console errors | **PASS** | 5 pages clicked: `console errors: []`, `page errors: []`, `failed/4xx/5xx: []` |
| 7 | Roles / signup lands as viewer | **PASS** | new account via the same `on_auth_user_created` trigger → `role=viewer`; `/api/auth/me` → viewer; `POST /api/pcap/upload` → **403** *"This action requires one of: analyst, admin."* |
| 8 | Live capture end to end | **PASS** | start 200 → 25 flows → stop 200 (34.3s) → `running=False`; **25/25 scored by the active model** (same pipeline as upload) |
| 9 | Runs clean with both integrations disabled | **PASS** | `{"mini_siem":{"enabled":false},"threathunter":{"enabled":false}}`; UI shows "Not configured" for both; no integration errors in 892 log lines |
| 10 | Re-verify ≥3 Phase 12 findings | **PASS** | **F2** canary not in client-facing error (`"lookup failed (HTTPStatusError)"`) · **F6** audit-log `limit=-1` → 422, rag `top_k=-5` → 422, 2001-char note → 422 · **F7** self-demotion → 400 |
| 11 | Phase 13 performance fixes hold | **PASS** | see table below |

**Item 5's self-check, in full.** `self_check` returned:
```json
{"citations_valid": false,
 "invalid_citations": ["protocol_notes:port-scan-behavioral-signature:1"],
 "unsupported_claims": []}
```
This is the *same chunk* AI-INVESTIGATION-EVAL-NOTES documented being
flagged, for the same reason (excerpt support below the 60% contiguous
match threshold). The deterministic self-check is active and behaving
conservatively — a corroboration of the prior phase's result, not a
contradiction.

**Item 11 — performance, N grew 3231 → 3327:**

| endpoint | this pass (median, n=5) | Phase 13 baseline | verdict |
|---|---|---|---|
| auth floor (`/api/integrations/status`) | **206ms** | 160-215ms | in range — the new global-limiter check costs nothing measurable |
| `/api/flows` default (500-cap) | **1754ms** (1669-2155) | 1189-1606ms | ~9% above prior range — see caveat 3 |
| `/api/flows?source_file=` (68 rows) | **1030ms** | median 1133ms | better |
| `/api/verdicts/summary` | **1017ms** | 920-1200ms | in range |
| `/api/rag/search` | **711ms** | 605-907ms | in range |
| investigate warm (cache hit) | **370ms** | median 578ms | better — Phase 13's cache-first fix holds |

---

## Part B — adversarial and edge-case input

| # | Check | Result | Evidence |
|---|---|---|---|
| 12 | PCAP variations | **PASS** | empty (0 B) → 400 *"Uploaded file is empty."* · 0-flow (24-byte header) → 200, `flow_count: 0` · ARP-only → 200, 0 flows · protocol-heavy (icmp/ipv6/dns) → 200, 8 flows · corrupt → 400 · 51MB → 413 *"exceeds the 50MB size cap"* · 101MB → 413 *"Request body too large"* |
| 13 | Concurrent access, no corruption | **PASS** (after D2) | 8/8 trials: one row, authorship preserved, overwrite logged in both audit entries |
| 14 | Every role's full journey | **PASS** | **viewer**: all 10 write/privileged surfaces → 403 (verdict, upload, capture start, capture stop, admin role, admin users, audit-log, rag/search, investigate fetch=true, enrichment fetch=true) · **analyst**: upload → verdict → investigate → enrich all succeed · **admin**: audit log shows accurate attribution for all 27 entries generated by this pass |
| 15 | New hostile inputs | **PASS / documented** | see below |

**Two layers proven distinct:** the 51MB and 101MB rejections return
*different messages* (`"exceeds the 50MB size cap"` vs `"Request body too
large"`), and the 101MB was **faster** (1.0s vs 2.5s) despite being larger
— consistent with the middleware rejecting before reading the body.
Independently confirmed: the 101MB rejection consumed **no** rate-limit
token (uploads #9/#10 still passed, #11 hit 429), proving the middleware
runs ahead of the limiter.

**Item 15 — new hostile inputs beyond Phase 12's set:**

- **H1 — unthrottled O(N) endpoint from the lowest-privilege role.** Was
  real; **fixed as D1**. A viewer looping `/api/flows?sort=score_desc`
  (the path that paginates every flow *and* every score row) hit no
  limiter at all. Now capped.
- **H3 — limiter charged before the resource is known.** Confirmed:
  `enforce()` runs before the flow lookup, so
  `POST /api/flows/<nonexistent>/investigate {"fetch":true}` as an analyst
  returns 404 **after** charging the bucket — budget spent with zero Groq
  cost. Buckets are per-user, so this is **self-denial only**, not a
  cross-user DoS. Documented, not fixed. *Related inconsistency left
  open:* enrichment still charges its bucket on a cache hit, which is the
  exact behaviour `investigate.py` documents as a bug it fixed.
- **H4 — attacker-controlled filename → `source_file`, unbounded.** Did
  **not** reproduce: a 10,000-char filename is rejected (400, though by a
  generic *"error parsing the body"* rather than a clear validation
  message), and the longest `source_file` actually stored is 43 chars.
  20,000-char and null-byte `?source_file=` queries both returned 200 with
  no 500 and no leaked driver text.
- **H5 — partial-failure integrity.** `replace_host_profiles()` is
  DELETE-then-INSERT with no transaction and the upload handler has no
  rollback, so a mid-upload failure could leave flows with no scores.
  Checked observationally rather than by inducing it: **3327 total flows,
  3327 scored by the active model, 0 unscored.** No evidence this path has
  ever fired in real data.
- **H6 — SSE token in logs.** Was real; **fixed as D5**.

---

## Part C — the §21 interview demo, run for real

Executed start to finish locally. Every beat produced real evidence.

1. **Normal traffic** — 3 real HTTPS sites, then a 2s gap.
2. **Authorized Nmap scan** of the author's own router (PROJECT.md §4):
   `nmap -sT --top-ports 100 -Pn 192.168.0.1` →
   *"Not shown: 96 closed tcp ports (conn-refused)"*, 4 open (22, 53, 80, 1900).
3. **Capture** — 2280 packets, 1589 KB.
4. **Upload** via §21's path — 200, **161 flows**, 29.9s.
5. **Detection** — of 107 flows to the scanned host, **100 flagged**; all
   closed-port flows scored **exactly 99.07**; **96 `handshake=False` + 4
   `handshake=True`**, mapping exactly onto nmap's own "96 closed + 4
   open". The 7 unflagged are UDP DNS (41.73), correctly not scan-shaped.
6. **AI investigation** — `port_scan` (0.7), **MITRE `['T1595','T1046']`**
   — matching AI-INVESTIGATION-EVAL-NOTES' documented expectation for a
   scan-shaped flow — 2 real citations, self-check active, 9.8s cold.
   Hedged wording: *"characteristics indicative of a port scanning
   attempt."*
7. **Wireshark validation** — independent `tshark` read of the same
   5-tuple: SYN out `15:33:13.533498`, `RST+ACK` back `15:33:13.534535`,
   no SYN-ACK — corroborating `close_type=rst` / `handshake_completed=False`
   at packet level. **96 RSTs** from the host and **100 distinct ports**
   SYN'd, matching nmap and the app exactly. Three independent sources
   agree.
8. **Verdict** — `true_positive` recorded, summary updated, full audit
   trail (`pcap_upload` → `investigation_run` → `verdict_change`) with
   correct attribution.

**The one honest gap in the demo script.** §21 says *"source IP extracted
→ threat-intel enrichment"*, but an Nmap LAN scan is private→private, so
`external_ip_for_flow()` returns `None` and **no provider is ever called**
— the flow returns `applicable: false` with its reason string. That is
correct behaviour, not a bug, but §21's script implies an enrichment step
that a LAN-scan demo cannot produce. Demonstrated separately on a real
public-IP flagged flow (all 4 providers `available=true`). Anyone
presenting this demo should script that beat honestly.

---

## Cleanup and final state

Fabricated test data was removed; real captured data and genuine analyst
judgements were kept, per this project's standing rule.

**Deleted:** 8 race-test verdicts, 1 item-3 verdict, 4 test-upload
`source_file`s (24 flows), 1 throwaway signup account. After each
deletion `verdicts/summary` was re-fetched and matched the Gate-0
snapshot **byte-for-byte** — that equality is the cleanup evidence, not an
assertion.

**Intentionally kept** (real data, real analysis):
- `partc_demo.pcap` — 161 flows from the real demo scan
- `live:Wi-Fi:2026-08-31T10:15:22...` — 25 flows from the live-capture check
- 1 genuine `true_positive` verdict on the real scan flow
- 2 investigations (permanently cached by design; deleting them would only
  re-spend quota later)

| | Gate 0 | Gate 7 | delta |
|---|---|---|---|
| total flows | 3141 | 3327 | +186 (both real captures) |
| verdicts | 2 | 3 | +1 (genuine) |
| source_files | 16 | 18 | +2 |
| audit high-water | 134 | 161 | +27, all from this pass |
| capture running | no | **no** | — |
| active model | `381419f9…` / `-0.138634784603203` | **unchanged** | — |
| integrations | both off | **both off** | — |

Test suite: **90 passed, 4 deselected** (71 at pass start + 19 new
regression tests for D1, D2, D4, D5).

---

## Go / no-go

**GO for Phase 14**, conditional on three things being carried into the
deployment work rather than forgotten:

1. **`ENVIRONMENT=production` must be set on the host.** It is
   `development` locally, which serves `/docs`, `/redoc` and
   `/openapi.json` unauthenticated. The F8 gate exists and works — it just
   needs the env var. Verify with a `curl /docs` returning 404 after deploy.
2. **Live capture cannot run on free hosting** (no raw sockets in
   free-tier containers) — PROJECT.md §8 already states this. The hosted
   build is upload/replay only; live capture is demoed locally. This must
   be stated in the README, and the Live Capture page should say so rather
   than failing opaquely.
3. **The in-process rate limiter does not survive multi-worker or
   multi-instance deployment.** It is correct for single-process uvicorn
   and was verified as such; if the host runs more than one worker, the
   caps are per-worker and the real fix is a shared store. Already
   documented in PERFORMANCE-NOTES F3.

**Not blockers, but open and deliberate:** D3's documentation drift —
particularly `AuthScreen.jsx:42` misstating the privilege level a new
account receives — and H3's charge-before-lookup / enrichment
charge-on-cache-hit inconsistency.

## What this pass did NOT cover

- **The just-under-50MB upload boundary was deliberately not run.** At the
  measured 84-97 packets/sec it is ~8-9 minutes of synchronous parsing and
  would create ~45,000 fabricated flows (14× the corpus) needing deletion,
  to re-prove something PERFORMANCE-NOTES already measured at three
  points. The over-limit rejection was tested instead, in 2.5s.
- **Chunked/background PCAP processing remains unbuilt** — a real feature
  for a future phase, not a performance fix. A full 50MB capture would
  block one HTTP request for ~9 minutes, likely exceeding browser and
  reverse-proxy defaults.
- **No frontend test suite exists.** All UI verification here was ad-hoc
  Playwright driving a real browser; there are no committed frontend tests.
- **The signup check used the admin API, not the AuthScreen form.** It
  fires the same `on_auth_user_created` trigger and hits the same column
  default that *is* the F9 fix, and the boundary was proven with a real
  403 — but the UI flow and the confirm-email branch were not exercised.
- **D5's fix covers the log sink, not the URL.** The token still travels
  in the query string; it simply no longer reaches logs. Eliminating the
  class needs a short-lived ticket exchange.
- **LLM non-determinism is not characterised.** AI-INVESTIGATION-EVAL-NOTES
  already documents same-flow classification varying across runs with no
  fixed seed; this pass ran each investigation once.
- **Three of my own assertions were wrong before the product was** — the
  D2 race criterion, an `is_anomalous` read from the upload response
  (which never carries scores, since `score_new_flows()` writes to a
  separate table), and `self_check` key names. Each is corrected in place
  above. The pattern is worth noting: reading a field from the wrong
  response shape produced two false "failures" that took real
  investigation to clear.
