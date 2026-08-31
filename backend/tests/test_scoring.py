import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import train_models  # noqa: E402

from app.services.ml.feature_matrix import (  # noqa: E402
    BEHAVIORAL_FEATURE_NAMES,
    FEATURE_NAMES,
    build_feature_matrix,
    subset_columns,
)
from app.services.ml.scoring import (  # noqa: E402
    explain,
    is_anomalous,
    load_bundle,
    raw_scores,
    to_anomaly_score,
)
from tests.test_leakage import NORMAL, SCAN, scan_flow  # noqa: E402


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


def behavioral_bundle():
    """The shipped model's actual variant -- 8 behavioural features, no
    timing/size. Distinct from bundle() above, which fits all 13.
    """
    return train_models.fit_bundle("isolation_forest", NORMAL[:160], BEHAVIORAL_FEATURE_NAMES)


def test_full_explanation_covers_every_feature_and_matches_raw_values():
    """top_n=None, positive_only=False must return one entry per feature,
    and each entry's flow_value must match what build_feature_matrix
    actually produced -- the automated version of "verifiably correct
    against raw feature values": a reader can check close_rst=1.0 against
    this flow's own close_type='rst' without re-running any model math.
    """
    b = behavioral_bundle()
    flow = scan_flow(0)  # close_type='rst', handshake_completed=False
    matrix = subset_columns(build_feature_matrix([flow]), BEHAVIORAL_FEATURE_NAMES)

    breakdown = explain(b, matrix, top_n=None, positive_only=False)[0]

    assert {entry["feature"] for entry in breakdown} == set(BEHAVIORAL_FEATURE_NAMES)
    for entry in breakdown:
        i = BEHAVIORAL_FEATURE_NAMES.index(entry["feature"])
        assert entry["flow_value"] == matrix[0, i]
        assert "baseline_value" in entry

    by_name = {e["feature"]: e for e in breakdown}
    assert by_name["close_rst"]["flow_value"] == 1.0
    assert by_name["close_fin_fin"]["flow_value"] == 0.0
    assert by_name["handshake_false"]["flow_value"] == 1.0
    assert by_name["handshake_true"]["flow_value"] == 0.0


def test_load_bundle_normalizes_windows_backslash_path():
    """train_models.py writes artifact_path via str(Path), which is
    backslash-separated when that run happened on Windows -- but a
    production container is always Linux, where backslash is not a path
    separator, so Path() there treats the whole string as one filename
    and silently never finds the real file. A model_versions row written
    from a Windows training run must still resolve when the deployed
    backend reads it on Linux. Uses the real shipped artifact (committed
    for deployment, see .gitignore) rather than a fixture, so this
    exercises the exact string that broke in production.
    """
    windows_style_path = "models\\isolation_forest_behavioural_only_381419f9.joblib"
    bundle = load_bundle(windows_style_path)
    assert bundle is not None
    assert bundle.algorithm == "isolation_forest"


def test_full_explanation_includes_negative_contributions():
    """positive_only=True (the default) hides features pushing a flow
    TOWARDS normal. With positive_only=False, an unremarkable flow should
    show at least one negative contribution -- otherwise the "in what
    direction" requirement has no evidence behind it.
    """
    b = behavioral_bundle()
    matrix = subset_columns(build_feature_matrix(NORMAL[160:161]), BEHAVIORAL_FEATURE_NAMES)
    breakdown = explain(b, matrix, top_n=None, positive_only=False)[0]
    assert any(entry["contribution"] <= 0 for entry in breakdown)
