"""Internal (never enriched) vs. external (enrichable) IP determination.

A single stdlib check -- `ipaddress.ip_address(x).is_global` -- covers
RFC1918 private ranges, loopback, link-local, and other non-routable
blocks in one call. No manual range list to maintain, no dependency.
"""

import ipaddress


def is_external(ip: str) -> bool:
    """True only for an address actually allocated for public routing."""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        # Not a parseable IP at all -- treat as not-enrichable rather
        # than raising into a caller that's just trying to render a UI.
        return False


def external_ip_for_flow(flow: dict) -> str | None:
    """Which side of a flow (if either) is worth enriching.

    dst_ip is checked first -- a flow's destination is what the model
    actually flags as unusual, and in this project's LAN-monitoring model
    the source is virtually always the analyst's own internal host. Falls
    back to src_ip for the (rarer) case where the destination is internal
    but the source is not. Returns None when neither side is external --
    e.g. this project's own test data, an internal host scanning another
    internal host, has no external indicator to enrich at all.
    """
    dst_ip = flow.get("dst_ip")
    if dst_ip and is_external(dst_ip):
        return dst_ip
    src_ip = flow.get("src_ip")
    if src_ip and is_external(src_ip):
        return src_ip
    return None
