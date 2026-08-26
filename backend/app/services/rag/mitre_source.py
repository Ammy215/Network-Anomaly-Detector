"""Fetches and filters MITRE ATT&CK's official Enterprise STIX 2.1
bundle down to the techniques a network-flow-metadata-only detector
could ever actually corroborate.

Scope (see docs/PHASE-2-PLAN.md Phase 6 plan for the full justification):
- Reconnaissance (TA0043): Active Scanning and its 3 sub-techniques --
  the direct match to what this project detects.
- Discovery (TA0007): the network-observable subset only -- Network
  Service Discovery, Remote System Discovery, Network Sniffing, Network
  Share Discovery, System Network Connections/Configuration Discovery.

Everything else in these two tactics (OSINT-style recon, registry/
process/cloud/container discovery) leaves no signature a flow monitor
could ever see, so including it would be ungrounded padding rather than
useful corpus.
"""

import logging
import re
from pathlib import Path

import httpx

logger = logging.getLogger("netsentinel.rag")

MITRE_BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)
CACHE_PATH = Path(__file__).resolve().parents[3] / "data" / "mitre" / "enterprise-attack.json"

# Verified present, current, and not revoked/deprecated in the bundle as
# of this phase's implementation (backend/data/mitre/enterprise-attack.json).
TARGET_TECHNIQUE_IDS = {
    "T1595", "T1595.001", "T1595.002", "T1595.003",  # Active Scanning + sub-techniques
    "T1046",  # Network Service Discovery
    "T1018",  # Remote System Discovery
    "T1040",  # Network Sniffing
    "T1135",  # Network Share Discovery
    "T1049",  # System Network Connections Discovery
    "T1016",  # System Network Configuration Discovery
}

_CITATION_RE = re.compile(r"\(Citation:[^)]*\)")
_HTML_TAG_RE = re.compile(r"<[^>]+>")
_MD_LINK_RE = re.compile(r"\[([^\]]*)\]\(https?://[^)]+\)")
_WHITESPACE_RE = re.compile(r"[ \t]+")
_BLANK_LINES_RE = re.compile(r"\n{3,}")


def _clean_description(text: str) -> str:
    """Strips MITRE's inline citation markers, HTML-ish tags, and
    cross-reference links to OTHER techniques -- noise for embedding,
    not content. MITRE descriptions are full of inline links like
    "[Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593)"
    pointing at unrelated techniques; left in, those other techniques'
    names get embedded as if they were part of THIS technique's content.

    Measured effect on T1595 (Active Scanning), the case that prompted
    this: small, not the fix it looked like it would be (0.0298 ->
    0.0400 similarity for a port-scan-mechanism-phrased query). T1595's
    low score for that kind of query turned out to be real and correct
    -- its actual MITRE text describes reconnaissance *intent*, not port-
    level mechanism, and it retrieves well (rank 1, ~0.65 similarity) for
    queries phrased that way instead. See docs/RAG-EVAL-NOTES.md for the
    full investigation. This cleaning step is still worth keeping for
    general corpus hygiene, just not for the reason first assumed.
    Citations are preserved separately as metadata (external_references),
    not lost.
    """
    text = _MD_LINK_RE.sub("", text)
    text = _CITATION_RE.sub("", text)
    text = _HTML_TAG_RE.sub("", text)
    text = _WHITESPACE_RE.sub(" ", text)
    text = _BLANK_LINES_RE.sub("\n\n", text)
    return text.strip()


def fetch_bundle(force_download: bool = False) -> dict:
    """Downloads MITRE's STIX bundle once and caches it locally (it's
    ~48MB, no reason to re-fetch on every ingestion run). Set
    force_download=True to refresh from source.
    """
    import json

    if CACHE_PATH.exists() and not force_download:
        logger.info("using cached MITRE bundle at %s", CACHE_PATH)
        with open(CACHE_PATH, encoding="utf-8") as f:
            return json.load(f)

    logger.info("downloading MITRE ATT&CK Enterprise bundle from %s", MITRE_BUNDLE_URL)
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with httpx.stream("GET", MITRE_BUNDLE_URL, timeout=90.0, follow_redirects=True) as response:
        response.raise_for_status()
        with open(CACHE_PATH, "wb") as f:
            for data in response.iter_bytes():
                f.write(data)

    with open(CACHE_PATH, encoding="utf-8") as f:
        return json.load(f)


def _external_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _attack_url(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url")
    return None


def load_target_techniques(force_download: bool = False) -> list[dict]:
    """The filtered, cleaned technique list this project actually uses.

    Returns one dict per technique: {technique_id, name, description,
    tactic, url, is_subtechnique}.
    """
    bundle = fetch_bundle(force_download=force_download)
    techniques = []

    for obj in bundle["objects"]:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        technique_id = _external_id(obj)
        if technique_id not in TARGET_TECHNIQUE_IDS:
            continue

        tactics = [phase["phase_name"] for phase in obj.get("kill_chain_phases", [])]
        techniques.append({
            "technique_id": technique_id,
            "name": obj["name"],
            "description": _clean_description(obj.get("description", "")),
            "tactic": tactics[0] if tactics else None,
            "url": _attack_url(obj),
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
        })

    found_ids = {t["technique_id"] for t in techniques}
    missing = TARGET_TECHNIQUE_IDS - found_ids
    if missing:
        logger.warning("expected MITRE techniques not found in bundle: %s", sorted(missing))

    techniques.sort(key=lambda t: t["technique_id"])
    return techniques
