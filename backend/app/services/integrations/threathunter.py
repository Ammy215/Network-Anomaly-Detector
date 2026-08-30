"""Optional outbound integration: forwards a flagged flow's public-IP IOC
to ThreatHunter for a lookup. See docs/INTEGRATIONS.md for the full
schema and the honest caveat that ThreatHunter's actual request body
isn't documented anywhere -- this is NetSentinel's best-effort guess at
one, built against its one documented endpoint, POST /api/ioc/investigate.

Same resilience shape as mini_siem.py / enrichment/providers.py: guard
clause when unconfigured, single best-effort attempt, never raises into
the caller, always logs the constructed request even when delivery is
skipped.
"""

import logging
from datetime import datetime, timezone

import httpx

from app.config import settings
from app.services.enrichment.ip_classification import external_ip_for_flow

logger = logging.getLogger("netsentinel.integrations.threathunter")

TIMEOUT_SECONDS = 3.0


def _build_request(flow: dict, ip: str) -> dict:
    return {
        "ioc_type": "ip",
        "ioc_value": ip,
        "source_system": "netsentinel",
        "context": {
            "flow_id": flow.get("id"),
            "anomaly_score": flow.get("anomaly_score"),
            "protocol": flow.get("protocol"),
            "dst_port": flow.get("dst_port"),
            "detected_at": datetime.now(timezone.utc).isoformat(),
        },
    }


def _send(request_body: dict, ip: str) -> None:
    logger.info("ThreatHunter IOC request built for %s (flow %s)", ip, request_body["context"]["flow_id"])
    if not settings.threathunter_endpoint_url:
        logger.debug("ThreatHunter integration disabled (THREATHUNTER_ENDPOINT_URL not set) -- delivery skipped.")
        return
    try:
        logger.info("Sending IOC lookup request to ThreatHunter for %s", ip)
        response = httpx.post(settings.threathunter_endpoint_url, json=request_body, timeout=TIMEOUT_SECONDS)
        response.raise_for_status()
        logger.info("ThreatHunter responded for %s: HTTP %s", ip, response.status_code)
    except Exception as exc:
        logger.warning("ThreatHunter IOC forwarding failed for %s: %s", ip, exc)


def notify_flow_flagged(flow: dict) -> None:
    """`flow` must have real src_ip/dst_ip -- reuses Phase 5's own
    external_ip_for_flow() so "has a public IP" means exactly what the
    enrichment endpoint already means by it, not a second definition.
    A flow with no external IP on either side is a silent no-op, not
    something worth logging -- that's the common case for this project's
    LAN-monitoring model, not an error.
    """
    ip = external_ip_for_flow(flow)
    if not ip:
        return
    _send(_build_request(flow, ip), ip)
