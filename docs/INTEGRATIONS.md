# NetSentinel — Outbound Integrations (Phase 11)

Two optional, loosely-coupled outbound integrations, per `docs/PROJECT.md`
§19: NetSentinel pushes normalized events to a **Mini SIEM** for
correlation, and forwards flagged flows' public-IP IOCs to
**ThreatHunter** for a lookup. Neither is required — NetSentinel runs
identically whether one, both, or neither is configured.

**Honest scope note**: neither schema below is copied from an existing,
agreed contract. `docs/PROJECT.md` §19 states intent (loose coupling,
normalized events, IOC forwarding) but no field names or transport.
ThreatHunter has exactly one documented endpoint
(`POST /api/ioc/investigate`) with no documented request/response body.
These schemas are NetSentinel's own reasonable design, built to be
self-explanatory enough that a receiving implementation could be written
from this document alone — not a spec both sides already agreed to.

## Configuration

Two environment variables, both optional, both empty by default:

| Variable | Enables | Default |
|---|---|---|
| `MINI_SIEM_WEBHOOK_URL` | Mini SIEM event delivery | unset (disabled) |
| `THREATHUNTER_ENDPOINT_URL` | ThreatHunter IOC forwarding | unset (disabled) |

Each is independent — setting one has no effect on the other. Leaving
both unset (the default, and the actual current state of this project)
is fully supported: the events are still built and logged, delivery is
simply skipped.

## Delivery model (applies to both)

- **Transport**: a single synchronous `POST` with a JSON body, 3-second
  timeout, no retry. This matches every other outbound call already in
  this codebase (`backend/app/services/enrichment/providers.py`'s
  threat-intel lookups) rather than introducing new infrastructure.
- **Best-effort**: a delivery failure (timeout, connection refused,
  non-2xx response) is logged and swallowed — it never fails the upload,
  the verdict save, or the live capture that triggered it.
- **Fire-and-forget**: the response body (if any) is not currently stored
  or surfaced anywhere in NetSentinel's UI. Storing/displaying a returned
  ThreatHunter result is a natural future addition, out of scope here.

## 1. Mini SIEM — normalized security events

**Trigger conditions** (either fires the same event envelope):
- `event_type: "flow_flagged"` — the active model flags a flow (upload or
  live capture, doesn't matter which — both funnel through the same
  scoring code).
- `event_type: "verdict_recorded"` — an analyst/admin saves a verdict on
  any flow (flagged or not — a verdict on an unflagged flow, marked true
  positive, is how a missed detection gets captured).

**Request**: `POST <MINI_SIEM_WEBHOOK_URL>`, `Content-Type: application/json`

```json
{
  "event_id": "b4b2b3b0-1234-4a1b-9abc-1234567890ab",
  "event_type": "flow_flagged",
  "source_system": "netsentinel",
  "generated_at": "2026-08-30T13:49:07.183456+00:00",
  "severity": "high",
  "flow": {
    "id": "58917b63-1609-41f3-900b-4fb3fe495a15",
    "source_file": "live:Wi-Fi:2026-08-30T13:21:44.560626+00:00",
    "src_ip": "192.168.0.108",
    "src_port": 39039,
    "dst_ip": "160.79.104.10",
    "dst_port": 443,
    "protocol": "TCP",
    "started_at": "2026-08-30T13:21:44.679443+00:00",
    "ended_at": "2026-08-30T13:21:53.776947+00:00"
  },
  "detection": {
    "anomaly_score": 91.8083462132921,
    "is_anomalous": true,
    "model_algorithm": "isolation_forest",
    "model_variant": "behavioural_only",
    "model_version_id": "381419f9-9e71-452f-8e16-46d353dd6491",
    "top_features": [
      {"feature": "is_bidirectional", "contribution": 0.1996, "direction": "toward_anomalous"}
    ]
  },
  "verdict": null
}
```

For `verdict_recorded`, `verdict` is populated instead of `null`:

```json
"verdict": {
  "value": "true_positive",
  "note": "Confirmed beaconing pattern, escalated.",
  "created_by": "analyst@example.com",
  "updated_at": "2026-08-30T13:52:10.001Z"
}
```

**Field notes**:
- `severity` — one of `critical` / `high` / `elevated` / `medium` / `low`
  / `unscored`. Mirrors `frontend/src/severity.js`'s bands exactly
  (`critical` = flagged and score ≥ 95; `high` = flagged, any score;
  `elevated` ≥ 85; `medium` ≥ 50; `low` below that; `unscored` if the
  flow has never been scored at all). Kept in sync by hand — if the UI's
  cutoffs ever change, update both.
- `detection` is `null` only for a `verdict_recorded` event on a flow no
  model ever scored (verdicts are deliberately independent of scoring —
  see `backend/app/routers/verdicts.py`'s own docstring).
- `top_features` is the full, signed per-feature attribution already
  computed for the flow — the same data the Flows table's detail panel
  shows, not a separate summary.

## 2. ThreatHunter — IOC forwarding

**Trigger condition**: a flow the active model flags, **and** it has a
public (non-RFC1918/non-private) IP on either side — reusing Phase 5's
own `external_ip_for_flow()` check verbatim, the same logic the
enrichment feature already uses. A flagged flow between two internal
hosts produces no IOC and triggers nothing.

**Request**: `POST <THREATHUNTER_ENDPOINT_URL>`, `Content-Type: application/json`

Targets ThreatHunter's one documented endpoint shape,
`/api/ioc/investigate`:

```json
{
  "ioc_type": "ip",
  "ioc_value": "160.79.104.10",
  "source_system": "netsentinel",
  "context": {
    "flow_id": "58917b63-1609-41f3-900b-4fb3fe495a15",
    "anomaly_score": 91.8083462132921,
    "protocol": "TCP",
    "dst_port": 443,
    "detected_at": "2026-08-30T13:21:53.777Z"
  }
}
```

`ioc_type` is always `"ip"` today — NetSentinel's flow data has no
domain/hash indicators to extract (no DNS resolution or file transfer
content is captured), so `"domain"`/`"hash"` are documented here as
future values, not currently emitted.

## Where this lives in the code

- `backend/app/services/integrations/mini_siem.py` — event construction
  + delivery.
- `backend/app/services/integrations/threathunter.py` — IOC request
  construction + delivery.
- `backend/app/services/scoring.py`'s `score_new_flows()` — the one
  shared trigger point both the PCAP-upload and live-capture paths funnel
  through for the `flow_flagged`/ThreatHunter triggers.
- `backend/app/routers/verdicts.py`'s `set_flow_verdict()` — the
  `verdict_recorded` trigger (Mini SIEM only; ThreatHunter has no
  verdict-based trigger).
- `GET /api/integrations/status` — returns `{"mini_siem": {"enabled":
  bool}, "threathunter": {"enabled": bool}}` for the frontend's status
  indicator. Booleans only; the configured URLs themselves are never
  exposed to the browser.
