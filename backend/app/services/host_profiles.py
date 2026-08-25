from datetime import datetime


def _parse_timestamp(value):
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(value)


def compute_host_profiles(flows: list[dict]) -> list[dict]:
    """Rolls up per-IP aggregate stats across all flows -- the seed of the
    baseline later ML phases compare traffic against. Pure function: full
    recompute from the given flow list each time, not an incremental
    update. At this data scale (hundreds to low thousands of flows) that's
    simpler and correct where incremental updates are a common source of
    drift bugs; revisit only if it's ever measured to be slow.

    unique_dst_ports_contacted counts distinct destination ports only for
    flows where this IP is the *initiator* (src_ip) -- the direct
    port-scan signal (a host suddenly touching many distinct destination
    ports), not ports others happened to connect to it on.
    """
    profiles: dict[str, dict] = {}

    def touch(ip: str, flow: dict):
        p = profiles.setdefault(ip, {
            "ip": ip,
            "flow_count": 0,
            "total_bytes": 0,
            "dst_ports": set(),
            "first_seen": flow["started_at"],
            "last_seen": flow["ended_at"],
        })
        p["flow_count"] += 1
        p["total_bytes"] += flow["byte_count"]
        started_at = _parse_timestamp(flow["started_at"])
        ended_at = _parse_timestamp(flow["ended_at"])
        if started_at < _parse_timestamp(p["first_seen"]):
            p["first_seen"] = flow["started_at"]
        if ended_at > _parse_timestamp(p["last_seen"]):
            p["last_seen"] = flow["ended_at"]
        return p

    for flow in flows:
        touch(flow["src_ip"], flow)
        touch(flow["dst_ip"], flow)

        if flow.get("dst_port") is not None:
            profiles[flow["src_ip"]]["dst_ports"].add(flow["dst_port"])

    result = []
    for p in profiles.values():
        result.append({
            "ip": p["ip"],
            "flow_count": p["flow_count"],
            "total_bytes": p["total_bytes"],
            "unique_dst_ports_contacted": len(p["dst_ports"]),
            "first_seen": p["first_seen"],
            "last_seen": p["last_seen"],
        })
    return result
