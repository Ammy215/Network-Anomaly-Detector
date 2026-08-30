"""One function per threat-intel provider. Every function returns the
same shape regardless of outcome:

    {"available": bool, "data": dict | None, "error": str | None}

so a provider being down, rate-limited, or misconfigured can never raise
into the caller -- enrichment is additive context, not load-bearing.
This mirrors app/services/scoring.py::score_new_flows, which applies the
same "a failure here must not break the primary flow" rule to scoring.

Only IPs that already passed ip_classification.is_external() should ever
reach these functions -- that gate lives in the caller (enrichment
service / router), not here, so these stay simple, testable, IP-in-
result-out functions.
"""

import logging

import httpx

from app.config import settings

logger = logging.getLogger("netsentinel.enrichment")

TIMEOUT_SECONDS = 6.0

NOT_CONFIGURED = {"available": False, "data": None, "error": "not configured"}


def _request_failed(provider: str, ip: str, exc: Exception) -> dict:
    logger.warning("%s lookup failed for %s: %s", provider, ip, exc)
    return {"available": False, "data": None, "error": str(exc)}


def _rate_limited(provider: str, ip: str) -> dict:
    logger.warning("%s rate-limited (429) for %s", provider, ip)
    return {"available": False, "data": None, "error": "rate limited"}


def check_abuseipdb(ip: str) -> dict:
    if not settings.abuseipdb_api_key:
        return NOT_CONFIGURED
    try:
        logger.info("calling AbuseIPDB for %s", ip)
        response = httpx.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
            timeout=TIMEOUT_SECONDS,
        )
        if response.status_code == 429:
            return _rate_limited("AbuseIPDB", ip)
        response.raise_for_status()
        data = response.json().get("data", {})
        return {
            "available": True,
            "data": {
                "abuse_confidence_score": data.get("abuseConfidenceScore"),
                "total_reports": data.get("totalReports"),
                "country_code": data.get("countryCode"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "last_reported_at": data.get("lastReportedAt"),
            },
            "error": None,
        }
    except Exception as exc:
        return _request_failed("AbuseIPDB", ip, exc)


def check_otx(ip: str) -> dict:
    if not settings.otx_api_key:
        return NOT_CONFIGURED
    try:
        logger.info("calling OTX for %s", ip)
        response = httpx.get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
            headers={"X-OTX-API-KEY": settings.otx_api_key},
            timeout=TIMEOUT_SECONDS,
        )
        if response.status_code == 429:
            return _rate_limited("OTX", ip)
        response.raise_for_status()
        body = response.json()
        return {
            "available": True,
            "data": {
                "pulse_count": (body.get("pulse_info") or {}).get("count"),
                "reputation": body.get("reputation"),
            },
            "error": None,
        }
    except Exception as exc:
        return _request_failed("OTX", ip, exc)


def check_ipinfo(ip: str) -> dict:
    if not settings.ipinfo_api_key:
        return NOT_CONFIGURED
    try:
        logger.info("calling IPInfo for %s", ip)
        response = httpx.get(
            f"https://ipinfo.io/{ip}/json",
            params={"token": settings.ipinfo_api_key},
            timeout=TIMEOUT_SECONDS,
        )
        if response.status_code == 429:
            return _rate_limited("IPInfo", ip)
        response.raise_for_status()
        body = response.json()
        return {
            "available": True,
            "data": {
                "city": body.get("city"),
                "region": body.get("region"),
                "country": body.get("country"),
                "org": body.get("org"),
                "loc": body.get("loc"),
            },
            "error": None,
        }
    except Exception as exc:
        return _request_failed("IPInfo", ip, exc)


def check_virustotal(ip: str) -> dict:
    """VirusTotal's IP-reputation endpoint -- not its more familiar
    hash/URL/domain scanning, since flows here only ever carry IPs (no
    DNS resolution is captured, so there is no domain to look up).
    """
    if not settings.virustotal_api_key:
        return NOT_CONFIGURED
    try:
        logger.info("calling VirusTotal for %s", ip)
        response = httpx.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": settings.virustotal_api_key},
            timeout=TIMEOUT_SECONDS,
        )
        if response.status_code == 429:
            return _rate_limited("VirusTotal", ip)
        response.raise_for_status()
        attributes = response.json().get("data", {}).get("attributes", {})
        return {
            "available": True,
            "data": {
                "last_analysis_stats": attributes.get("last_analysis_stats"),
                "reputation": attributes.get("reputation"),
                "country": attributes.get("country"),
            },
            "error": None,
        }
    except Exception as exc:
        return _request_failed("VirusTotal", ip, exc)


# NVD (CVE context) is deliberately not wired up here. A CVE lookup needs
# a specific product/version (a CPE string or keyword); this project's
# flow data has only a destination port number, with no service banner
# or fingerprint behind it. Building a port -> CVE table (e.g. "port 445
# -> these SMB CVEs") would be a speculative, largely-wrong mapping for a
# fan-out nmap scan hitting random high ports with nothing actually
# listening -- exactly the invented, unfounded claim docs/PROJECT.md's
# hedged-language rule (section 4) rules out. Revisit if flow data ever gains a
# real service fingerprint to key a CVE lookup off of.

PROVIDERS = {
    "abuseipdb": check_abuseipdb,
    "otx": check_otx,
    "ipinfo": check_ipinfo,
    "virustotal": check_virustotal,
}
