"""Scoring, 0-100 normalisation, and per-flow feature attribution.

Everything here consumes an already-fitted bundle (model + scaler +
training score distribution). Nothing in this module ever calls .fit() --
that is what prevents normalisation leakage at inference time. See
train_models.py for the single fit site.
"""

import logging
from dataclasses import dataclass
from pathlib import Path

import numpy as np

logger = logging.getLogger("netsentinel.scoring")

from app.services.ml.feature_matrix import (
    FEATURE_NAMES,
    NUMERIC_FEATURES,
    build_feature_matrix,
)


@dataclass
class ModelBundle:
    """Everything needed to score a flow the same way training did."""

    algorithm: str
    model: object
    scaler: object
    feature_names: list[str]
    # Sorted training decision_function scores. Used to map a raw score to
    # a percentile, which is what makes the 0-100 scale interpretable.
    training_scores_sorted: np.ndarray
    # Per-feature median of the SCALED training matrix, used as the
    # "typical value" substituted during occlusion attribution.
    training_medians_scaled: np.ndarray
    threshold: float


def load_bundle(artifact_path: str) -> ModelBundle | None:
    """Loads a persisted bundle. Returns None if the artifact is missing.

    Artifacts are git-ignored binaries, so a fresh clone won't have them
    until train_models.py runs. Callers degrade gracefully rather than
    crashing -- an unscored flow is acceptable, a 500 on upload is not.

    `artifact_path` is read from the model_versions row exactly as
    train_models.py wrote it -- if that run happened on Windows, it's a
    backslash-separated string. Backslash is not a path separator on
    POSIX, so Path() on Linux treats the whole thing as one filename and
    silently never finds the real file (a production Docker container is
    always Linux, no matter what OS trained the model) -- normalizing
    before constructing the Path makes this work on both.
    """
    import joblib

    normalized = artifact_path.replace("\\", "/")
    path = Path(normalized)
    if not path.is_absolute():
        path = Path(__file__).resolve().parents[3] / normalized
    if not path.exists():
        logger.warning("Model artifact not found at %s -- flows will be unscored", path)
        return None
    return joblib.load(path)


def raw_scores(bundle: ModelBundle, matrix: np.ndarray) -> np.ndarray:
    """decision_function: higher = more normal, lower = more anomalous.

    Note .transform(), never .fit_transform() -- the scaler's parameters
    come from training and are frozen. If this ever re-fit, a flow's score
    would depend on which other flows happened to be in the same batch.
    """
    scaled = bundle.scaler.transform(matrix)
    return bundle.model.decision_function(scaled)


def to_anomaly_score(bundle: ModelBundle, raw: np.ndarray) -> np.ndarray:
    """Maps raw scores to 0-100, where 100 = most anomalous.

    Defined as the percentile rank against the TRAINING score
    distribution: a score of 95 means "this flow looks more anomalous than
    95% of known-normal traffic". That phrasing is meaningful to an
    analyst, and unlike min-max scaling it is robust -- one extreme
    outlier cannot rescale everything else.
    """
    training = bundle.training_scores_sorted
    # Position of each raw score within the training distribution.
    # Lower raw score => fewer training points below it => higher anomaly.
    position = np.searchsorted(training, raw, side="left")
    fraction_more_normal = 1.0 - (position / max(len(training), 1))
    return np.clip(fraction_more_normal * 100.0, 0.0, 100.0)


def is_anomalous(bundle: ModelBundle, raw: np.ndarray) -> np.ndarray:
    return raw < bundle.threshold


def _raw_baseline_values(bundle: ModelBundle) -> np.ndarray:
    """The training-typical value per feature, in the same (unscaled) units
    as `matrix` -- i.e. `bundle.training_medians_scaled` run back through
    the scaler's inverse. Same shape as one row of `matrix`.
    """
    return bundle.scaler.inverse_transform(
        bundle.training_medians_scaled.reshape(1, -1)
    )[0]


def _display_value(feature_name: str, raw_value: float) -> float:
    """Undoes feature_matrix.py's log1p for the 5 NUMERIC_FEATURES so a
    duration/rate/size shows in real units, not a log-compressed number.
    One-hot/boolean features pass through unchanged.
    """
    if feature_name in NUMERIC_FEATURES:
        return float(np.expm1(raw_value))
    return float(raw_value)


def explain(
    bundle: ModelBundle,
    matrix: np.ndarray,
    top_n: int | None = 3,
    positive_only: bool = True,
) -> list[list[dict]]:
    """Occlusion attribution: which features actually drove each score.

    For each feature, substitute the training median and re-score. If the
    flow becomes markedly more "normal" without that feature, that feature
    was carrying the anomaly. This is model-agnostic and needs no extra
    dependency, and it explains cleanly: "replace this value with a
    typical one and see how much the anomaly disappears".

    Known limitation, stated rather than hidden: with correlated features
    (duration, packets_per_second and bytes_per_second are mathematically
    linked), occluding one alone understates its importance, because the
    others still carry the same signal. Attribution here is indicative,
    not a rigorous Shapley decomposition.

    Every entry also carries `flow_value` (this flow's actual value, read
    straight off `matrix` before scaling) and `baseline_value` (the
    training-typical value) so a caller can show *why* a feature mattered,
    not just that it did -- and so the claim is checkable against the
    flow's own raw data, not just the model's math.

    `top_n=None` returns every feature. `positive_only=False` also returns
    features that pushed the flow *towards* normal (negative contribution)
    -- useful for showing the full picture, e.g. why a borderline flow
    wasn't flagged. Defaults reproduce the original top-3/positive-only
    behavior exactly.
    """
    scaled = bundle.scaler.transform(matrix)
    baseline_raw = bundle.model.decision_function(scaled)

    n_samples, n_features = scaled.shape
    # Build every occluded variant at once, then score in a single batch --
    # one call instead of n_samples * n_features individual calls.
    variants = np.repeat(scaled, n_features, axis=0)
    for feature_index in range(n_features):
        variants[feature_index::n_features, feature_index] = (
            bundle.training_medians_scaled[feature_index]
        )

    occluded_raw = bundle.model.decision_function(variants).reshape(n_samples, n_features)
    # Positive delta => removing the feature made the flow look MORE
    # normal => that feature was pushing it towards anomalous.
    deltas = occluded_raw - baseline_raw[:, None]

    baseline_values = _raw_baseline_values(bundle)

    results = []
    for sample_index in range(n_samples):
        order = np.argsort(-deltas[sample_index])
        if positive_only:
            order = [i for i in order if deltas[sample_index][i] > 0]
        if top_n is not None:
            order = order[:top_n]
        results.append([
            {
                "feature": bundle.feature_names[i],
                "contribution": round(float(deltas[sample_index][i]), 6),
                "flow_value": round(_display_value(bundle.feature_names[i], matrix[sample_index, i]), 6),
                "baseline_value": round(_display_value(bundle.feature_names[i], baseline_values[i]), 6),
            }
            for i in order
        ])
    return results


def score_flows(bundle: ModelBundle, flows: list[dict]) -> list[dict]:
    """Full scoring pass for a list of flow dicts.

    `top_features` stores the FULL signed per-feature breakdown (every
    feature, both directions) -- the compact "top 3" view shown in a flows
    table is a display-time filter over this, not a separate computation,
    so there is only ever one stored explanation per flow.
    """
    if not flows:
        return []
    matrix = build_feature_matrix(flows)
    if bundle.feature_names != FEATURE_NAMES:
        from app.services.ml.feature_matrix import subset_columns

        matrix = subset_columns(matrix, bundle.feature_names)

    raw = raw_scores(bundle, matrix)
    scores = to_anomaly_score(bundle, raw)
    flags = is_anomalous(bundle, raw)
    contributions = explain(bundle, matrix, top_n=None, positive_only=False)

    return [
        {
            "flow_id": flow["id"],
            "raw_score": float(raw[i]),
            "anomaly_score": float(scores[i]),
            "is_anomalous": bool(flags[i]),
            "top_features": contributions[i],
        }
        for i, flow in enumerate(flows)
    ]
