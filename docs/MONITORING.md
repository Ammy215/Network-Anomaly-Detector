# Monitoring — what is watched, and what it has shown

Scoped for a portfolio deployment on free tiers: enough to know when the app
is down, why it is slow, and what the numbers actually are — not an
enterprise observability stack. Every figure below was measured against the
live deployment unless it is explicitly marked as an estimate.

## What is watched

| Signal | Who calls it | How often | What it proves |
|---|---|---|---|
| `GET /api/health` | Render's internal health checker (direct, bypasses Cloudflare) | every ~5s | The process is up. Touches nothing — must stay free to call. |
| `GET /api/health/ready` | GitHub Actions (`.github/workflows/backend-wake.yml`) | every 6 hours | The app can do its job: database reachable, a model is active, and its artifact exists on disk. `200 {"status":"ok"}` or `503 {"status":"degraded"}`. Also wakes the instance. |
| `GET /rest/v1/model_versions` | GitHub Actions (`.github/workflows/supabase-keepalive.yml`) | daily | Supabase sees real database activity, so the free project is never paused. Queries Supabase directly, never through Render. |
| `TIMING` log lines | the backend itself, every request | continuous | Server-side time per endpoint, as deployed (see below). |

**Why two health endpoints.** A process can be "up" while the app is broken:
a paused Supabase project, a revoked key, or a deploy missing the model
artifact all leave `/api/health` answering happily. `/ready` catches those.
Render's checker deliberately stays on `/api/health` — if it pointed at
`/ready`, a Supabase outage would make Render restart a perfectly healthy
process.

**Why not UptimeRobot (it was tried, and cannot work here).** The monitor was
removed on 19 Sep 2026 after it reported NetSentinel "down" for 7 days while
the site served real visitors normally. The cause is not a timeout or a
method: **Render refuses to wake a hibernated free instance for a known
uptime-monitor User-Agent.** Measured one second apart, same method, same
endpoint, only the User-Agent differing:

```
UptimeRobot UA  07:35:24Z -> 503 in 0.71s   x-render-routing: hibernate-wake-error
curl UA         07:35:25Z -> 200 in 33.89s  (woke normally)
UptimeRobot UA  07:35:59Z -> 200 in 0.72s   (served fine, once already awake)
```

The block applies only to the *wake* path — once the instance is up, the same
agent is served normally. That leaves no usable setting, because Render spins
an idle instance down after 15 minutes:

- **Ping faster than 15 min** → the instance never sleeps, so no wake is ever
  needed and the monitor works — at **~720 instance-hours/month**, which is
  96% of the workspace's 750-hour allowance for one service.
- **Ping slower than 15 min** → every check lands on a hibernated instance the
  monitor is not permitted to wake → a permanent false "down", and no
  monitoring signal at all.

There is no middle setting, so UptimeRobot was replaced rather than retuned.
The sibling honeypot project keeps its own service warm at a 5-minute
interval and its monitor works for exactly this reason — it never hibernates,
so the wake path is never exercised.

**What replaced it:** `.github/workflows/backend-wake.yml`, every 6 hours,
a plain `curl` (which Render does wake for) against `/api/health/ready`, with
a 90s timeout and 3 attempts 30s apart. It deliberately sets **no**
User-Agent — adding a monitoring one would recreate the bug above, which is
noted in the workflow itself. Each wake keeps the instance up ~15 minutes, so
it costs about **1 h/day (~30 h/month)**.

`/ready` still accepts `HEAD` as well as `GET` (`b848ccc`). That was added for
UptimeRobot's free plan, which only sends `HEAD`; it is no longer load-bearing
but is harmless and keeps the endpoint usable by any checker.

**Verified against a hibernated instance**, which is the only path that
matters: the workflow's own script woke the service and returned
`200 {"status":"ok"}` in **43.8s on the first attempt**. The failure path was
checked separately against an unreachable host — three attempts, then `exit 1`,
surfacing Render's `x-render-routing` header so "the app is broken" and
"Render would not start the container" stay distinguishable in the run log.

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
| Cold `/api/health/ready` (19 Sep, four separate wakes) | **33.7s**, **33.9s**, **42.8s**, **43.8s** |
| Warm `/api/health` / `/api/health/ready` | ~0.3–0.8s from India (mostly network) |

A non-browser client gets a real, delayed `200` — not a Render loading page —
so a checker records cold starts as slow successes, **provided its timeout is
longer than the wake.** The measured spread is **33.7–43.8s** across six
wakes, and the slowest was the most recent — which is why `backend-wake.yml`
allows **90s** rather than trimming to the observed maximum. A 60s timeout
would have passed every one of these, but with under 17s of headroom on the
worst; the earlier UptimeRobot monitor's default 30s would have failed all of
them outright.

`/api/health` touches nothing, so those ~43s are container start plus Python
imports (scikit-learn, Chroma, the ONNX embedding model). That's the likely
lever if cold start ever needs shortening — not yet measured in detail.

**Why every 6 hours, not every 5 minutes.** A 5-minute pinger would keep the
instance awake permanently: ~720–744 of the workspace's 750 free
instance-hours a month, and exhausting them suspends *every* free service in
the workspace — not just this one. Six-hourly checks cost roughly a
quarter-hour of uptime each, ≈ **30 h/month**. The trade-off is accepted: a
real visitor after an idle spell still waits ~43s.

**Keeping Supabase alive is a separate job now, deliberately.** It used to be
a side effect of this ping, which turned out to be a single point of failure:
when Render stopped waking the instance on 12 Sep 2026, the health check never
reached the backend, so no database query ran, and Supabase paused the project
seven days later for inactivity. `supabase-keepalive.yml` queries Supabase
directly, so a Render outage can no longer starve the database.

## Incident: 7 days of false "down" alerts (12–19 Sep 2026)

UptimeRobot reported the backend down continuously for 6d 21h, confirmed from
four of its regions. **The site was serving real visitors fine throughout** —
the monitor was reporting its own inability to wake a hibernated instance, not
an outage. Worth recording because every individual signal looked like a real
failure:

- Render's **Events** log showed nothing at all across the whole window: no
  suspension, no failed deploy, no restart. The last deploy before it ran
  clean for ~22 hours first.
- `/api/health` kept returning `200` to Render's own internal checker, because
  that only runs while the instance is up.
- A browser `GET` woke the service and returned `200` in 42.8s on demand.

**The real damage was second-order.** The backend's health check was also what
kept Supabase active. With every check failing at Render's router, no database
query ran for 8 days and **Supabase paused the project** for inactivity — a
genuine outage caused by a monitoring failure, not by either service being
unhealthy. Hence `supabase-keepalive.yml` querying Supabase directly.

**Diagnostic lesson, stated plainly:** three successive theories fitted the
evidence and were wrong — a quota suspension (Render logs those, and usage was
*estimated* at ~400h of 750 at the time — extrapolated from a month-to-date
average, which the next section shows is not a steady rate), a bad deploy (it had run fine for a day), and a
broken health endpoint (it answered correctly when awake). What settled it was
a controlled A/B: same method, same endpoint, one second apart, only the
User-Agent changed. **When several plausible causes survive the evidence, the
next step is an experiment that isolates one variable — not another theory.**

## Workspace instance-hours (measured, 19 Sep 2026)

Render gives the whole workspace **750 free instance-hours a month**, shared by
every free web service in it. A spun-down service consumes none; when the pool
runs out, Render suspends *all* the workspace's free services — including this
one — until the 1st. The dashboard shows only the workspace total (Billing →
Monthly Included Usage), never a per-service breakdown.

**Measured burn rate: ~15–20 h/day, not 48 h/day.**

| Reading | When (UTC, 19 Sep) | Free instance hours |
|---|---|---|
| 1 | ~06:38 — taken between 06:25 and 06:52; the exact time was not recorded | 635.07 |
| 2 | ~12:28 | 640.05 |

The delta is 4.98 h over ~5.85 h ≈ **20 h/day**. About 1.5 h of that was this
service being woken five times by the diagnostic testing itself, so the rate
attributable to the other services is closer to **15 h/day**.

**The 48 h/day figure was wrong, and why.** It assumed the honeypot and
metadata-analyzer services were running 24/7, inferred from both answering in
under a second at 07:20. A sub-second reply only proves a service was awake *at
that instant*. By 12:30 both were asleep: the honeypot took **32.8 s** to wake,
and the metadata analyzer did not answer within **90 s**. Read one snapshot as a
steady state and the projection is off by 2–3×.

| Assumption | Rate | Reaches 750 h (110 h left) |
|---|---|---|
| Two services always-on (the wrong model) | 48 h/day | ~21 Sep |
| Measured, including test wakes | ~20 h/day | ~24 Sep |
| Measured, excluding test wakes | ~15 h/day | ~26 Sep |
| Services wake only for their own monitors | ~2 h/day | not before the 1 Oct reset |

What decides which row is real is what wakes the *other* services besides their
monitors. One candidate, from reading that project's code and not confirmed:
its frontend sends a heartbeat every 2 minutes, which would hold the backend
awake for as long as anyone leaves that app open in a browser tab.

**Method note for the next reading:** record the exact time with every reading.
The largest error above is not knowing when reading 1 was taken; two
timestamped readings give a rate directly with no estimating.

**Also on 19 Sep:** the NetSentinel UptimeRobot monitor was deleted. The first
manual run of `backend-wake.yml` (12:25) succeeded, its wake step taking 44 s —
a real cold start from a GitHub runner. The 12:23 *scheduled* run did not fire;
GitHub documents that scheduled runs can be delayed or dropped. The metadata
analyzer not answering within 90 s is undiagnosed and belongs to that project.

**23 Sep — keep-alive tightened to daily.** Over 19–23 Sep, `backend-wake.yml`
fired all 14 of its scheduled runs (6-hourly, gaps ≤ ~9 h — jitter, never a
miss). `supabase-keepalive.yml` on `*/2` fired **once** (21 Sep); the 23 Sep
run never appeared — not late, not queued. Supabase was still live (last
activity 21 Sep), but at a 2-day interval one dropped run uses a third of the
7-day pause window. Daily leaves room for five consecutive drops.

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

**Verified in production:** a real sign-in on the live site after the fix
recorded the client's actual public IP (confirmed against the IP
Cloudflare's own `/cdn-cgi/trace` reported for the same machine); every
earlier row shows a `10.x` address.

## Login events: one row per real sign-in

Login counts in `audit_log` were inflated — 230 rows across 4 accounts,
most within two minutes of the previous one, some under 1ms apart.

**Cause (read from the library source, then reproduced).** The frontend
posted `/api/auth/login-event` on every `SIGNED_IN` from supabase-js — but
in auth-js 2.112.4 `SIGNED_IN` is not only a sign-in. `_recoverAndRefresh()`
emits it whenever a stored session is recovered, which runs on every
hidden→visible tab switch, and each event is re-broadcast to every other open
tab over a `BroadcastChannel`. A deliberate two-tab test on the live site
wrote **9 login rows for zero sign-ins** (pairs 3.6ms and 11ms apart — the
cross-tab fan-out). The exact per-action multiplier wasn't pinned down; the
fix doesn't depend on it.

**Fix.** Every Supabase access token carries a `session_id` claim: created by
a real sign-in (password or email link), unchanged across refreshes and tabs.
The backend stores it on the login row, and a partial unique index
(`audit_log_login_session_uniq`) admits at most one login per session — the
database decides, because duplicates arrive concurrently and a
check-then-insert in application code would race. A client-side-only fix
(log only after `signInWithPassword`) was rejected on evidence: all 4
accounts were confirmed through an email link, so every new user's first
login would have gone unrecorded. Side benefit: a client can no longer
inflate the audit log by calling the endpoint in a loop.

**Verified in production:**
- Tab switching across two tabs on an existing session → exactly 1 row.
- Sign out, sign in with password → Supabase logs show `POST
  /auth/v1/token?grant_type=password → 200`, `auth.sessions` gains a new
  session, and `audit_log` gains exactly one row carrying that session's ID.

**Historical counts are inflated.** Rows before this fix have no
`session_id` and can't be de-duplicated after the fact. Count logins per
distinct user per day for that period, not rows.

## Known gap: failed sign-ins are invisible to `audit_log`

Password sign-in goes straight from the browser to Supabase Auth; our
backend only hears about a login after it succeeded. A failed attempt
therefore never reaches `audit_log` — one appeared during verification
(`POST .../token?grant_type=password → 400`) and exists only in Supabase's
own logs.

Accepted, not tooled: to see failed attempts, query the Supabase project's
edge logs for `grant_type=password` with a `400` status. Recording them
ourselves would mean proxying credentials through the backend, which the
architecture deliberately avoids.

## Known latency cost: Render (Ohio) ↔ Supabase (Tokyo)

The backend runs in Render's **Ohio (US East)** region; the database is in
Supabase's **Tokyo** region. Every Supabase query from the backend crosses
the Pacific.

- **Measured: ≈170–215ms per Supabase call** (server-side `TIMING` lines;
  co-located, the same call would be single-digit milliseconds):

  | Sample | Server time | What it isolates |
  |---|---|---|
  | `/api/health/ready`, cache miss (steady state) | 214.2ms | one Supabase query |
  | `/api/health/ready`, cache hit | 0.8ms | the endpoint with no query — so the query ≈ 213ms |
  | `/api/health/ready`, first miss | 448.4ms | one query + opening a fresh connection |
  | `/api/capture/status` (n=16) | median ≈170ms, 153–213ms, occasional 440–540ms | auth's one profile lookup |
  | `/api/auth/me` | 179.0ms | same |

  Single samples of `/ready`; `/capture/status` is the steadier corroboration.
- **Endpoints pay this per query, not per request.** Anything that makes
  several sequential Supabase calls (paginated flow listing, score lookups,
  auth's profile lookup) pays it several times over.
- **Why the deployed app feels slower than `PERFORMANCE-NOTES.md` suggests:**
  those numbers were measured on localhost — but localhost was a laptop in
  India, itself talking to Tokyo. So local numbers already contained a
  long-distance database hop; deployment makes that hop longer rather than
  adding one. The honest comparison is "India→Tokyo vs Ohio→Tokyo", not
  "zero vs 150ms".
- **Measured per-endpoint cost, as deployed** (one browsing session):
  `/api/models` 310–402ms · `/api/integrations/status` 196ms ·
  `/api/verdicts/summary` 1191ms · `/api/flows/source-files` 1245–1492ms ·
  `/api/auth/login-event` 659ms.
- **The bigger cost is the flows fan-out, not geography alone.** The app
  shell loads flows with one `/api/flows?source_file=…` request *per capture
  file*, all in parallel (`fetchAllFlows` in `frontend/src/App.jsx`). With
  20 capture files that is 20 concurrent requests. Their start times
  (completion minus duration) all fall within ~1s, but they **finish one
  after another**: 2.1s, 2.7s, 2.8s … 7.4s, 10.1s. So the page's flow data
  is complete only after **~10s of server time** — even though no single
  request is slow on its own. Why they serialize is not yet established;
  candidates are the free instance's CPU share, the shared Supabase client's
  connection handling, or Supabase itself. Not comparable one-to-one with
  `PERFORMANCE-NOTES.md`'s 2.8–3.1s `/api/flows` (that was one request, at a
  smaller data size, not 20 concurrent ones). Recorded there as a known
  production issue, with the candidate fix direction.
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

## Real usage: who is using it, and for what

No analytics dependency — `audit_log` already records every sign-in and
every state-changing action with a user and a timestamp. Run in the
Supabase SQL editor (the `service_role`-backed editor, not the app):

```sql
-- Per UTC day, last 30 days.
select created_at::date as day_utc,
       count(distinct user_id)                                   as active_users,
       count(distinct user_id)    filter (where action = 'login') as users_signed_in,
       count(distinct session_id) filter (where action = 'login') as real_sign_ins,
       count(*)                   filter (where action <> 'login') as actions
from audit_log
where created_at > now() - interval '30 days'
group by 1 order by 1 desc;

-- What people actually do.
select action, count(*) as times, count(distinct user_id) as users,
       max(created_at) as last_seen
from audit_log
where action <> 'login' and created_at > now() - interval '30 days'
group by action order by times desc;
```

How to read it:
- **`real_sign_ins` counts only sign-ins after the login fix** (rows with a
  `session_id`). Before it, login rows were inflated — use
  `users_signed_in` (distinct users) for that period, never a row count.
- **Active users** includes anyone who signed in *or* acted that day.
- Dates are UTC days; IST runs 5h30m ahead.
- It sees what the backend sees: failed sign-ins and pure page views are
  not in `audit_log` (see the known gap above).

**Baseline (11 Sep 2026):** tested against the live data. Today shows 1
active user with 2 real sign-ins (exactly the two verification sign-ins);
30–31 Aug show 3–4 active users and 25–46 actions a day — `verdict_change`
(39 all-time) is the most-used feature, then `pcap_upload` (8).

## Data-consistency checklist (manual)

Not automated, deliberately: the database is written by two code paths
(PCAP upload and live capture) plus two offline scripts, and a scheduled
checker would be more machinery than this project needs. A documented,
repeatable check is enough. **Run it after:** every deploy, every model
activation (`activate_model.py`), and any bulk upload — otherwise monthly.

**1. Database invariants** — one query, every value has an expected answer:

```sql
with active as (select id from model_versions where is_active)
select
  (select count(*) from model_versions where is_active)                        as c1_active_models,             -- expect 1
  (select count(*) from flows f left join flow_features ff on ff.flow_id = f.id
    where ff.flow_id is null)                                                    as c2_flows_without_features,    -- expect 0
  (select count(*) from flows f where not exists (
     select 1 from flow_scores s, active a
     where s.flow_id = f.id and s.model_version_id = a.id))                     as c3_flows_unscored_by_active,  -- expect 0
  (select count(*) from flows)                                                   as c4_total_flows,               -- compare with UI
  (select count(*) from flow_scores s join active a on s.model_version_id = a.id
    where s.is_anomalous)                                                        as c5_flagged_by_active,         -- compare with UI
  (select count(*) from flow_scores s where not exists (
     select 1 from flows f where f.id = s.flow_id))                              as c6_orphan_scores;             -- expect 0
```

What a wrong answer means:
- **c1 = 0** — no active model; the UI falls back to the newest
  `isolation_forest / behavioural_only` row. c1 > 1 is prevented by a
  partial unique index.
- **c2 > 0** — flows were stored but feature extraction didn't finish.
- **c3 > 0** — scoring on upload is best-effort, so a failure is only a
  log warning. This is the check that catches it; fix by re-running
  `activate_model.py` for the active version.
- **c6 > 0** — shouldn't happen (cascade delete); investigate before
  trusting any score counts.

**2. Database ↔ UI** — on the live site, signed in:
- Overview's total flows and flagged count match **c4** and **c5**.
- The Flows page's "scored by" label names the active model's algorithm
  and variant (`select algorithm, variant from model_versions where is_active`).
- `GET /api/health/ready` returns `{"status":"ok"}`.

**3. After activating a different model only** — the investigation cache
is keyed on `flow_id` alone and stores no model version, so investigations
written under the previous model keep being served. Count them:

```sql
select count(*) filter (where s.is_anomalous is not true) as cached_for_flows_active_model_does_not_flag
from investigations i
cross join (select id from model_versions where is_active) m
left join flow_scores s on s.flow_id = i.flow_id and s.model_version_id = m.id;
```

Non-zero means analysts can open an AI explanation for a flow the shipped
model no longer flags. Latent today, not live — see the baseline.

**Baseline (11 Sep 2026), tested against the live data:** c1 = 1, c2 = 0,
c3 = 0, c4 = 3,531, c5 = 2,282, c6 = 0. Investigation cache: 8 entries, all
written under the current model, all for flows it still flags (0 stale).
