import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import train_models  # noqa: E402

from app.services.ml.feature_matrix import FEATURE_NAMES, build_feature_matrix  # noqa: E402
from app.services.ml.scoring import (  # noqa: E402
    explain,
    is_anomalous,
    raw_scores,
    to_anomaly_score,
)
from tests.test_leakage import NORMAL, SCAN  # noqa: E402


def bundle():
    return train_models.fit_bundle("isolation_forest", NORMAL[:160], FEATURE_NAMES)


def test_anomaly_score_is_bounded_0_to_100():
    b = bundle()
    raw = raw_scores(b, build_feature_matrix(NORMAL + SCAN))
    scores = to_anomaly_score(b, raw)
    assert scores.min() >= 0.0
    assert scores.max() <= 100.0


def test_more_anomalous_flows_score_higher_than_normal_ones():
    b = bundle()
    normal_scores = to_anomaly_score(b, raw_scores(b, build_feature_matrix(NORMAL[160:])))
    scan_scores = to_anomaly_score(b, raw_scores(b, build_feature_matrix(SCAN)))
    print(f"\n  mean normal score={normal_scores.mean():.1f}  "
          f"mean scan score={scan_scores.mean():.1f}")
    assert scan_scores.mean() > normal_scores.mean()


def test_score_mapping_is_monotonic_in_raw_score():
    """A lower decision_function must never produce a lower anomaly score."""
    b = bundle()
    raw = np.linspace(b.training_scores_sorted.min() - 0.1,
                      b.training_scores_sorted.max() + 0.1, 50)
    scores = to_anomaly_score(b, raw)
    assert np.all(np.diff(scores) <= 1e-9)


def test_threshold_flags_roughly_the_configured_fraction_of_training_data():
    """By construction the 5th-percentile threshold flags ~5% of training
    flows. Verifying it keeps the threshold definition honest.
    """
    b = bundle()
    flagged = is_anomalous(b, raw_scores(b, build_feature_matrix(NORMAL[:160])))
    rate = float(np.mean(flagged))
    print(f"\n  training flag rate={rate:.3f} (threshold percentile="
          f"{train_models.THRESHOLD_PERCENTILE}%)")
    assert 0.02 <= rate <= 0.09


def test_explanations_name_real_features_and_are_ranked():
    b = bundle()
    contributions = explain(b, build_feature_matrix(SCAN[:5]), top_n=3)
    assert len(contributions) == 5
    for row in contributions:
        assert len(row) <= 3
        for entry in row:
            assert entry["feature"] in FEATURE_NAMES
        # Ranked by contribution, descending.
        values = [e["contribution"] for e in row]
        assert values == sorted(values, reverse=True)


def test_explanation_is_never_a_bare_verdict():
    """Every flagged flow must carry contributing features -- the project
    rule is no bare 'anomalous' with no reason attached.
    """
    b = bundle()
    matrix = build_feature_matrix(SCAN[:20])
    flagged = is_anomalous(b, raw_scores(b, matrix))
    contributions = explain(b, matrix)
    for i, is_flagged in enumerate(flagged):
        if is_flagged:
            assert len(contributions[i]) > 0, "flagged flow with no explanation"
