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
    """
    import joblib

    path = Path(artifact_path)
    if not path.is_absolute():
        path = Path(__file__).resolve().parents[3] / artifact_path
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


def explain(bundle: ModelBundle, matrix: np.ndarray, top_n: int = 3) -> list[list[dict]]:
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

    results = []
    for sample_index in range(n_samples):
        order = np.argsort(-deltas[sample_index])[:top_n]
        results.append([
            {
                "feature": bundle.feature_names[i],
                "contribution": round(float(deltas[sample_index][i]), 6),
            }
            for i in order
            if deltas[sample_index][i] > 0
        ])
    return results


def describe_deviation(flow: dict, baselines: dict) -> list[str]:
    """Human-readable context to sit alongside the numeric attribution.

    `baselines` maps a numeric feature name to its median in the training
    set, so the analyst sees "50.0 vs typical 107.0" rather than a bare
    contribution number with no frame of reference.
    """
    notes = []
    for name in NUMERIC_FEATURES:
        value = flow.get(name)
        median = baselines.get(name)
        if value is None or median is None:
            continue
        notes.append(f"{name}={value:.6g} (baseline median {median:.6g})")
    return notes


def score_flows(bundle: ModelBundle, flows: list[dict], top_n: int = 3) -> list[dict]:
    """Full scoring pass for a list of flow dicts."""
    if not flows:
        return []
    matrix = build_feature_matrix(flows)
    if bundle.feature_names != FEATURE_NAMES:
        from app.services.ml.feature_matrix import subset_columns

        matrix = subset_columns(matrix, bundle.feature_names)

    raw = raw_scores(bundle, matrix)
    scores = to_anomaly_score(bundle, raw)
    flags = is_anomalous(bundle, raw)
    contributions = explain(bundle, matrix, top_n=top_n)

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
