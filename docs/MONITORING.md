# Monitoring — what is watched, and what it has shown

Scoped for a portfolio deployment on free tiers: enough to know when the app
is down, why it is slow, and what the numbers actually are — not an
enterprise observability stack. Every figure below was measured against the
live deployment unless it is explicitly marked as an estimate.

## What is watched

| Signal | Who calls it | How often | What it proves |
|---|---|---|---|
| `GET /api/health` | Render's internal health checker (direct, bypasses Cloudflare) | every ~5s | The process is up. Touches nothing — must stay free to call. |
| `GET /api/health/ready` | UptimeRobot (external, through Cloudflare) | every 60 min | The app can do its job: database reachable, a model is active, and its artifact exists on disk. `200 {"status":"ok"}` or `503 {"status":"degraded"}`. |
| `TIMING` log lines | the backend itself, every request | continuous | Server-side time per endpoint, as deployed (see below). |

**Why two health endpoints.** A process can be "up" while the app is broken:
a paused Supabase project, a revoked key, or a deploy missing the model
artifact all leave `/api/health` answering happily. `/ready` catches those.
Render's checker deliberately stays on `/api/health` — if it pointed at
`/ready`, a Supabase outage would make Render restart a perfectly healthy
process.

**What `/ready` does not say.** It never reports *which* check failed —
that goes to the server log (`netsentinel.health`). It is unauthenticated,
and shouldn't describe the backend's internals to whoever asks. Its result
is cached for 30s so it can't be used to generate database load.

## Cold starts (measured)

Render's free tier spins an idle instance down after 15 minutes. The next
request waits for the container to boot:

| Measurement | Result |
|---|---|
| Cold `/api/health` (two separate occasions) | **42.7s**, **42.9s** to first byte, then HTTP 200 |
| Warm `/api/health` / `/api/health/ready` | ~0.3–0.8s from India (mostly network) |

A non-browser client gets a real, delayed `200` — not a Render loading page —
so the uptime monitor records cold starts as slow successes, **provided its
timeout is longer than ~43s.** A shorter timeout turns every hourly check
into a false "down" alert.

`/api/health` touches nothing, so those ~43s are container start plus Python
imports (scikit-learn, Chroma, the ONNX embedding model). That's the likely
lever if cold start ever needs shortening — not yet measured in detail.

**Why hourly, not every 5 minutes.** A 5-minute pinger would keep the
instance awake permanently: ~720–744 of the workspace's 750 free
instance-hours a month, and exhausting them suspends *every* free service
in the workspace. Hourly checks cost roughly a quarter-hour of uptime each
(≈ 180–200h/month), and — as a side effect — keep the Supabase free project
above its 7-day inactivity pause. The trade-off is accepted: a real visitor
after an idle spell still waits ~43s.

## Real client IPs in the audit log

Every audit row used to record a Render load-balancer address (`10.x`)
instead of the user's. The fix was chosen from a one-shot capture of real
production headers (a temporary log line, deployed and removed in the next
commit), including deliberately forged headers:

- Traffic arrives as **browser → Cloudflare → Render load balancer (10.x) → uvicorn.**
- `X-Forwarded-For` arrived as `<anything the client sent>, <client>, <cloudflare edge>, <render lb>`.
  A forged leftmost entry survived intact.
  - `FORWARDED_ALLOW_IPS='*'` would therefore record attacker-chosen IPs.
  - `FORWARDED_ALLOW_IPS=10.0.0.0/8` would stop on the Cloudflare edge and record Cloudflare's IP.
- `CF-Connecting-IP` carried the real address on every request. **Cloudflare rejected a client-supplied copy outright** (`403`, `error code: 1000`) before it reached Render.
- Forged `True-Client-IP` was overwritten and forged `X-Real-IP` was stripped — neither is relied on.

So `client_ip()` (`backend/app/services/auth.py`) uses `CF-Connecting-IP`,
**only** when the socket peer is Render-internal (`10.0.0.0/8`), and only if
it parses as an IP; anything else falls back to the peer. Adversarial cases
are in `backend/tests/test_client_ip.py`. Audit rows written before the fix
keep their `10.x` addresses — the real ones can't be recovered.

**Residual assumption:** this trusts that everything reaching the container
from `10.x` came through Cloudflare. The only other `10.x` caller observed
is Render's own health checker, which sends no proxy headers.

## Known latency cost: Render (Ohio) ↔ Supabase (Tokyo)

The backend runs in Render's **Ohio (US East)** region; the database is in
Supabase's **Tokyo** region. Every Supabase query from the backend crosses
the Pacific.

- **Estimate, not yet measured:** roughly 150–200ms per database round trip.
  Co-located, the same round trip would be single-digit milliseconds.
- **Endpoints pay this per query, not per request.** Anything that makes
  several sequential Supabase calls (paginated flow listing, score lookups,
  auth's profile lookup) pays it several times over.
- **Why the deployed app feels slower than `PERFORMANCE-NOTES.md` suggests:**
  those numbers were measured on localhost — but localhost was a laptop in
  India, itself talking to Tokyo. So local numbers already contained a
  long-distance database hop; deployment makes that hop longer rather than
  adding one. The honest comparison is "India→Tokyo vs Ohio→Tokyo", not
  "zero vs 150ms".
- **Not fixed, deliberately.** Moving either service is a real migration
  (a new Supabase project and data move, or a new Render service), out of
  scope for this phase. If it were done, the choice would be to move the
  backend to a region near Tokyo — Render's nearest is Singapore — not the
  database.

## Reading the timing logs

Each request (except Render's `/api/health` checks) writes one line:

```
INFO:netsentinel.timing:TIMING GET /api/flows 200 1234.5ms
```

- The path is the **route template** (`/api/flows/{flow_id}/score`), never the
  raw URL: no path IDs, and no query string — which is where the live-capture
  SSE endpoint's bearer token lives. Unmatched paths log as `unmatched`
  rather than echoing what a scanner asked for. Pinned by
  `backend/tests/test_request_timing.py`.
- It measures server time until the response **starts**. For JSON endpoints
  that is the whole cost; for the SSE stream it is only time-to-first-byte.
- It is server-side only: add the client↔Cloudflare↔Render network time on
  top for what a user actually waits.

To see per-endpoint cost: Render dashboard → Logs → search `TIMING`.
