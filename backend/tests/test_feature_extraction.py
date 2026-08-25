from datetime import datetime, timedelta, timezone

from app.services.feature_extraction import compute_features

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def test_normal_bidirectional_tcp_flow():
    flow = {
        "protocol": "TCP",
        "packet_count": 10,
        "byte_count": 1000,
        "packets_bwd": 5,
        "saw_syn": True,
        "saw_syn_ack": True,
        "close_reason": "fin_fin",
        "started_at": T0,
        "ended_at": T0 + timedelta(seconds=2),
    }
    features = compute_features(flow)

    assert features["duration_seconds"] == 2.0
    assert features["packets_per_second"] == 5.0
    assert features["bytes_per_second"] == 500.0
    assert features["avg_packet_size"] == 100.0
    assert features["is_bidirectional"] is True
    assert features["handshake_completed"] is True
    assert features["close_type"] == "fin_fin"


def test_zero_duration_flow_floors_rate_instead_of_dividing_by_zero():
    flow = {
        "protocol": "TCP",
        "packet_count": 3,
        "byte_count": 180,
        "packets_bwd": 0,
        "saw_syn": True,
        "saw_syn_ack": False,
        "close_reason": "rst",
        "started_at": T0,
        "ended_at": T0,  # same instant -- real case, seen in Phase 1's FIN/RST teardown sequences
    }
    features = compute_features(flow)

    assert features["duration_seconds"] == 0.0
    # rate is floored (1e-6s), not inf/NaN -- large but finite and deterministic
    assert features["packets_per_second"] == 3 / 1e-6
    assert features["bytes_per_second"] == 180 / 1e-6
    assert features["avg_packet_size"] == 60.0
    assert features["is_bidirectional"] is False
    assert features["handshake_completed"] is False  # SYN seen, but no SYN-ACK
    assert features["close_type"] == "rst"


def test_udp_flow_has_null_handshake_fields_not_false():
    flow = {
        "protocol": "UDP",
        "packet_count": 2,
        "byte_count": 200,
        "packets_bwd": 1,
        "saw_syn": False,
        "saw_syn_ack": False,
        "close_reason": "timeout",
        "started_at": T0,
        "ended_at": T0 + timedelta(seconds=1),
    }
    features = compute_features(flow)

    assert features["is_bidirectional"] is True
    # NULL because the concept doesn't apply to UDP, not False -- UDP has no handshake at all
    assert features["handshake_completed"] is None
    assert features["close_type"] == "timeout"


def test_one_directional_unanswered_tcp_syn():
    flow = {
        "protocol": "TCP",
        "packet_count": 1,
        "byte_count": 60,
        "packets_bwd": 0,
        "saw_syn": True,
        "saw_syn_ack": False,
        "close_reason": "eof",
        "started_at": T0,
        "ended_at": T0,
    }
    features = compute_features(flow)

    assert features["is_bidirectional"] is False
    assert features["handshake_completed"] is False
    assert features["close_type"] == "eof"


def test_iso_string_timestamps_are_accepted_not_only_datetime_objects():
    # Supabase returns timestamps as ISO strings on read -- feature
    # extraction has to handle both that and raw datetime objects (used
    # when computing features right after assembly, before a DB round-trip).
    flow = {
        "protocol": "TCP",
        "packet_count": 4,
        "byte_count": 400,
        "packets_bwd": 2,
        "saw_syn": True,
        "saw_syn_ack": True,
        "close_reason": "fin_fin",
        "started_at": "2026-01-01T00:00:00+00:00",
        "ended_at": "2026-01-01T00:00:02+00:00",
    }
    features = compute_features(flow)
    assert features["duration_seconds"] == 2.0
    assert features["packets_per_second"] == 2.0
