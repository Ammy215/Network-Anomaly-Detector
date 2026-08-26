"""Cache-or-fetch orchestration for IP enrichment.

Cached by IP, not by flow -- an IP's reputation doesn't depend on which
flow surfaced it, so two flagged flows hitting the same public IP share
one cache entry. A stale/missing cache entry is only ever refreshed when
`force_fetch=True` (the analyst clicked "Enrich"), never automatically --
the free `force_fetch=False` path only ever reads the cache.
"""

import logging
from datetime import datetime, timedelta, timezone

from app.services import supabase_client
from app.services.enrichment.providers import PROVIDERS

logger = logging.getLogger("netsentinel.enrichment")

# Reputation data doesn't move fast. Named and centralized here so it's
# easy to revisit -- flagged as a starting default, not a settled number.
ENRICHMENT_CACHE_TTL_HOURS = 168  # 7 days


def _is_fresh(fetched_at: str) -> bool:
    fetched = datetime.fromisoformat(fetched_at)
    if fetched.tzinfo is None:
        fetched = fetched.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) - fetched < timedelta(hours=ENRICHMENT_CACHE_TTL_HOURS)


def get_or_fetch_enrichment(ip: str, force_fetch: bool) -> dict:
    """Returns `{"ip", "cached", "fetched_at", "providers": {...}}`.

    `force_fetch=False`: read-only. Returns a cached row if one exists
    (regardless of freshness, with `cached: true`), or a "not yet
    fetched" placeholder if none exists -- never calls any provider.

    `force_fetch=True`: fetches fresh from every provider only if the
    cached row is missing or past its TTL; otherwise still just serves
    the cache. This is the only path that can spend API quota, and only
    when the cache genuinely needs it.
    """
    cached = supabase_client.get_cached_enrichment(ip)

    if cached and (not force_fetch or _is_fresh(cached["fetched_at"])):
        logger.info("enrichment cache hit for %s (fetched_at=%s)", ip, cached["fetched_at"])
        return {
            "ip": ip,
            "cached": True,
            "fetched_at": cached["fetched_at"],
            "providers": {name: cached.get(name) for name in PROVIDERS},
        }

    if not force_fetch:
        return {"ip": ip, "cached": False, "fetched_at": None, "providers": None}

    logger.info("fetching fresh enrichment for %s", ip)
    results = {name: fn(ip) for name, fn in PROVIDERS.items()}
    row = supabase_client.upsert_enrichment(ip, results)
    return {
        "ip": ip,
        "cached": False,
        "fetched_at": row["fetched_at"],
        "providers": results,
    }
