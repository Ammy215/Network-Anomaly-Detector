"""Turns stored flow rows into the numeric matrix the models consume.

This module is the SINGLE SOURCE OF TRUTH for feature order and encoding.
Training and inference both build their matrices here, so the two can
never silently drift apart -- a feature-order mismatch between fit and
predict is a classic, silent, and very hard-to-spot ML bug.
"""

import numpy as np

# Numeric features get log1p before scaling. Phase 2's rate features use a
# 1e-6 duration floor, which produces values up to 1e6 packets/sec for
# microsecond flows. Left untransformed those outliers would dominate
# One-Class SVM's RBF kernel almost entirely -- the model would effectively
# see one axis. log1p compresses them to a comparable range while staying
# monotonic (a bigger rate is still a bigger value) and defined at 0.
NUMERIC_FEATURES = [
    "duration_seconds",
    "packets_per_second",
    "bytes_per_second",
    "avg_packet_size",
    "packet_count",
]

# byte_count is deliberately absent: it is exactly
# avg_packet_size * packet_count, so it carries no information those two
# don't already, while adding a correlated dimension that makes distance
# based models (OCSVM) worse, not better.

CLOSE_TYPES = ["fin_fin", "rst", "timeout", "eof"]

# Handshake is three-state, not boolean. Phase 2 deliberately stores NULL
# for non-TCP flows because "did the TCP handshake complete" is not a
# question you can ask of UDP -- collapsing NULL to False would assert
# that every UDP flow FAILED a handshake, which is false and would teach
# the model a wrong distinction. 370 of 809 baseline flows are non-TCP,
# so this is not an edge case here.
HANDSHAKE_STATES = ["true", "false", "not_applicable"]

FEATURE_NAMES = (
    NUMERIC_FEATURES
    + ["is_bidirectional"]
    + [f"handshake_{state}" for state in HANDSHAKE_STATES]
    + [f"close_{close_type}" for close_type in CLOSE_TYPES]
)

# Indices of the columns that are log1p-transformed numerics, for callers
# (e.g. occlusion explanations) that need to undo or reason about scaling.
NUMERIC_SLICE = slice(0, len(NUMERIC_FEATURES))

# Behaviour-only subset, used by the confound-controlled ablation: no
# timing, no packet sizes, only what the connection actually DID. If
# detection survives on these alone, it is about connection behaviour
# rather than capture-path artifacts.
BEHAVIORAL_FEATURE_NAMES = [
    name for name in FEATURE_NAMES if name not in NUMERIC_FEATURES
]


def _handshake_state(flow: dict) -> str:
    value = flow.get("handshake_completed")
    if value is None:
        return "not_applicable"
    return "true" if value else "false"


def build_feature_matrix(flows: list[dict]) -> np.ndarray:
    """flows -> (n_samples, n_features) float array, in FEATURE_NAMES order.

    Pure function: no fitting, no state, no I/O. Whatever scaling happens,
    happens to the OUTPUT of this, never inside it -- which is what keeps
    the single scaler-fit site in train_models.py meaningful.
    """
    rows = []
    for flow in flows:
        numeric = [float(flow.get(name) or 0.0) for name in NUMERIC_FEATURES]
        # log1p is safe here: all five numerics are non-negative by
        # construction (durations, counts, sizes, and rates).
        numeric = list(np.log1p(numeric))

        handshake_state = _handshake_state(flow)
        close_type = flow.get("close_type")

        row = (
            numeric
            + [1.0 if flow.get("is_bidirectional") else 0.0]
            + [1.0 if handshake_state == state else 0.0 for state in HANDSHAKE_STATES]
            + [1.0 if close_type == candidate else 0.0 for candidate in CLOSE_TYPES]
        )
        rows.append(row)

    return np.asarray(rows, dtype=float)


def subset_columns(matrix: np.ndarray, feature_names: list[str]) -> np.ndarray:
    """Selects a named subset of columns, preserving FEATURE_NAMES order."""
    indices = [FEATURE_NAMES.index(name) for name in feature_names]
    return matrix[:, indices]
