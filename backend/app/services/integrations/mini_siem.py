"""Optional outbound integration: normalized security events pushed to a
Mini SIEM webhook. See docs/INTEGRATIONS.md for the full schema.

Same resilience shape as app/services/enrichment/providers.py: a guard
clause short-circuits when unconfigured (MINI_SIEM_WEBHOOK_URL unset),
delivery is a single best-effort attempt wrapped in one try/except that
never raises into the caller, and the event is always built and logged
at INFO regardless of whether delivery is attempted -- so "disabled"
still leaves a verifiable trace, just no network call.
"""

import logging
import uuid
from datetime import datetime, timezone

import httpx

from app.config import settings

logger = logging.getLogger("netsentinel.integrations.mini_siem")

TIMEOUT_SECONDS = 3.0

# Mirrors frontend/src/severity.js's severityBand() cutoffs exactly, so a
# flow's severity reads the same whether you're looking at the UI or an
# emitted event. Ported by hand (different language, same thresholds) --
# if those cutoffs ever change, change both.
CRITICAL_CUTOFF = 95
ELEVATED_CUTOFF = 85
MEDIUM_CUTOFF = 50


def _severity(flow: dict) -> str:
    score = flow.get("anomaly_score")
    is_anomalous = bool(flow.get("is_anomalous"))
    if is_anomalous:
        return "critical" if (score is not None and score >= CRITICAL_CUTOFF) else "high"
    if score is None:
        return "unscored"
    if score >= ELEVATED_CUTOFF:
        return "elevated"
    if score >= MEDIUM_CUTOFF:
        return "medium"
    return "low"


def _flow_summary(flow: dict) -> dict:
    return {
        "id": flow.get("id"),
        "source_file": flow.get("source_file"),
        "src_ip": flow.get("src_ip"),
        "src_port": flow.get("src_port"),
        "dst_ip": flow.get("dst_ip"),
        "dst_port": flow.get("dst_port"),
        "protocol": flow.get("protocol"),
        "started_at": flow.get("started_at"),
        "ended_at": flow.get("ended_at"),
    }


def _detection_summary(flow: dict, model_version: dict | None) -> dict | None:
    # A real score always has a non-null anomaly_score -- absence means
    # this flow was never scored at all (e.g. a verdict recorded before
    # any model touched it), which get_flow_for_investigation() already
    # represents this same way (None, not a missing key).
    if flow.get("anomaly_score") is None:
        return None
    return {
        "anomaly_score": flow["anomaly_score"],
        "is_anomalous": bool(flow.get("is_anomalous")),
        "model_algorithm": (model_version or {}).get("algorithm"),
        "model_variant": (model_version or {}).get("variant"),
        "model_version_id": (model_version or {}).get("id"),
        "top_features": flow.get("top_features") or [],
    }


def _build_event(event_type: str, flow: dict, model_version: dict | None, verdict: dict | None) -> dict:
    return {
        "event_id": str(uuid.uuid4()),
        "event_type": event_type,
        "source_system": "netsentinel",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "severity": _severity(flow),
        "flow": _flow_summary(flow),
        "detection": _detection_summary(flow, model_version),
        "verdict": verdict,
    }


def _send(event: dict) -> None:
    logger.info("Mini SIEM event built: %s for flow %s", event["event_type"], event["flow"]["id"])
    if not settings.mini_siem_webhook_url:
        logger.debug("Mini SIEM integration disabled (MINI_SIEM_WEBHOOK_URL not set) -- delivery skipped.")
        return
    try:
        logger.info("Sending %s event to Mini SIEM webhook", event["event_type"])
        response = httpx.post(settings.mini_siem_webhook_url, json=event, timeout=TIMEOUT_SECONDS)
        response.raise_for_status()
    except Exception as exc:
        logger.warning("Mini SIEM webhook delivery failed: %s", exc)


def notify_flow_flagged(flow: dict, model_version: dict | None) -> None:
    """`flow` must already have anomaly_score/is_anomalous/top_features
    merged onto it (the shape scoring.py's flagged rows and
    get_flow_for_investigation() both already produce).
    """
    _send(_build_event("flow_flagged", flow, model_version, verdict=None))


def notify_verdict_recorded(flow: dict, model_version: dict | None, verdict_row: dict) -> None:
    verdict = {
        "value": verdict_row.get("verdict"),
        "note": verdict_row.get("note"),
        "created_by": verdict_row.get("created_by"),
        "updated_at": verdict_row.get("updated_at"),
    }
    _send(_build_event("verdict_recorded", flow, model_version, verdict=verdict))
