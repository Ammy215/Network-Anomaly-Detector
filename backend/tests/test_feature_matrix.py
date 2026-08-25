import numpy as np

from app.services.ml.feature_matrix import (
    BEHAVIORAL_FEATURE_NAMES,
    FEATURE_NAMES,
    build_feature_matrix,
    subset_columns,
)


def flow(**overrides):
    base = {
        "duration_seconds": 1.0,
        "packets_per_second": 10.0,
        "bytes_per_second": 1000.0,
        "avg_packet_size": 100.0,
        "packet_count": 10,
        "is_bidirectional": True,
        "handshake_completed": True,
        "close_type": "fin_fin",
        "protocol": "TCP",
    }
    base.update(overrides)
    return base


def test_feature_order_is_stable():
    # Train and inference both index by this order; if it silently changed,
    # a model would score the wrong column and fail quietly.
    assert FEATURE_NAMES == [
        "duration_seconds",
        "packets_per_second",
        "bytes_per_second",
        "avg_packet_size",
        "packet_count",
        "is_bidirectional",
        "handshake_true",
        "handshake_false",
        "handshake_not_applicable",
        "close_fin_fin",
        "close_rst",
        "close_timeout",
        "close_eof",
    ]


def test_numeric_features_are_log1p_transformed():
    matrix = build_feature_matrix([flow(duration_seconds=99.0)])
    assert matrix[0][FEATURE_NAMES.index("duration_seconds")] == np.log1p(99.0)


def test_handshake_is_three_state_not_boolean():
    tcp_completed = build_feature_matrix([flow(handshake_completed=True)])[0]
    tcp_failed = build_feature_matrix([flow(handshake_completed=False)])[0]
    # NULL means "not applicable" (non-TCP), NOT "failed" -- collapsing the
    # two would assert every UDP flow failed a handshake it never attempts.
    udp_na = build_feature_matrix([flow(handshake_completed=None, protocol="UDP")])[0]

    i_true = FEATURE_NAMES.index("handshake_true")
    i_false = FEATURE_NAMES.index("handshake_false")
    i_na = FEATURE_NAMES.index("handshake_not_applicable")

    assert (tcp_completed[i_true], tcp_completed[i_false], tcp_completed[i_na]) == (1, 0, 0)
    assert (tcp_failed[i_true], tcp_failed[i_false], tcp_failed[i_na]) == (0, 1, 0)
    assert (udp_na[i_true], udp_na[i_false], udp_na[i_na]) == (0, 0, 1)


def test_close_type_one_hot_is_mutually_exclusive():
    row = build_feature_matrix([flow(close_type="rst")])[0]
    close_columns = [row[FEATURE_NAMES.index(f"close_{c}")]
                     for c in ("fin_fin", "rst", "timeout", "eof")]
    assert sum(close_columns) == 1
    assert row[FEATURE_NAMES.index("close_rst")] == 1


def test_missing_numeric_values_do_not_crash():
    row = build_feature_matrix([flow(duration_seconds=None)])[0]
    assert row[FEATURE_NAMES.index("duration_seconds")] == 0.0


def test_behavioural_subset_excludes_all_timing_and_size_features():
    # This is the ablation that tests whether detection is about connection
    # behaviour rather than capture-path timing artifacts.
    assert "duration_seconds" not in BEHAVIORAL_FEATURE_NAMES
    assert "packets_per_second" not in BEHAVIORAL_FEATURE_NAMES
    assert "avg_packet_size" not in BEHAVIORAL_FEATURE_NAMES
    assert "close_rst" in BEHAVIORAL_FEATURE_NAMES
    assert "handshake_false" in BEHAVIORAL_FEATURE_NAMES


def test_subset_columns_preserves_values():
    flows = [flow(close_type="rst"), flow(close_type="eof")]
    full = build_feature_matrix(flows)
    subset = subset_columns(full, BEHAVIORAL_FEATURE_NAMES)
    assert subset.shape == (2, len(BEHAVIORAL_FEATURE_NAMES))
    col = BEHAVIORAL_FEATURE_NAMES.index("close_rst")
    assert subset[0][col] == 1
    assert subset[1][col] == 0
