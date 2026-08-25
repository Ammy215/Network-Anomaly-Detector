from datetime import datetime

# Rate features (packets/bytes per second) floor duration at this value.
# Several real flows span microseconds (see the FIN/RST teardown sequences
# from Phase 1) -- dividing by a near-zero duration produces meaningless
# huge or infinite numbers. This floor matches real timestamp resolution,
# so an ultra-short flow gets a large-but-bounded rate instead of inf/NaN.
# duration_seconds itself is still reported as the true (possibly 0.0)
# value; only the rate calculations use the floor.
_MIN_DURATION_SECONDS = 1e-6

_TCP_CLOSE_REASONS = {"fin_fin", "rst", "timeout", "eof"}


def _parse_timestamp(value):
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(value)


def compute_features(flow: dict) -> dict:
    """Derives the feature vector for one flow. Pure function: same input
    always produces the same output, no I/O, no randomness -- this is what
    makes feature extraction unit-testable and re-runs deterministic.

    `flow` is expected to have the raw fields flow assembly now captures:
    packet_count, byte_count, started_at, ended_at, packets_bwd,
    protocol, saw_syn, saw_syn_ack, close_reason.
    """
    started_at = _parse_timestamp(flow["started_at"])
    ended_at = _parse_timestamp(flow["ended_at"])
    duration_seconds = (ended_at - started_at).total_seconds()

    rate_duration = max(duration_seconds, _MIN_DURATION_SECONDS)
    packets_per_second = flow["packet_count"] / rate_duration
    bytes_per_second = flow["byte_count"] / rate_duration
    avg_packet_size = flow["byte_count"] / flow["packet_count"]

    is_bidirectional = flow.get("packets_bwd", 0) > 0

    is_tcp = flow["protocol"] == "TCP"
    handshake_completed = bool(flow.get("saw_syn") and flow.get("saw_syn_ack")) if is_tcp else None
    close_type = flow.get("close_reason")

    return {
        "duration_seconds": duration_seconds,
        "packets_per_second": packets_per_second,
        "bytes_per_second": bytes_per_second,
        "avg_packet_size": avg_packet_size,
        "is_bidirectional": is_bidirectional,
        "handshake_completed": handshake_completed,
        "close_type": close_type,
    }
