"""Phase 3: train, evaluate, version, and apply the anomaly models.

Run:  python scripts/train_models.py

Deliberately a batch script and NOT an HTTP endpoint -- training is an
offline job that reads the whole table and takes seconds to minutes, which
has no business blocking a web request (PROJECT.md section 23).

The honesty rules this script is built to satisfy:
  * Train ONLY on normal traffic. Scan captures are never fitted on.
  * Fit the scaler ONCE, on the training slice only (see FIT SITE below).
  * Choose the threshold a priori from training scores -- never tuned
    against the scan labels, which would fit the test set.
  * Report the unflattering numbers next to the flattering ones.
"""

import json
import sys
import time
import uuid
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import joblib  # noqa: E402

from app.services import supabase_client  # noqa: E402
from app.services.ml.feature_matrix import (  # noqa: E402
    BEHAVIORAL_FEATURE_NAMES,
    FEATURE_NAMES,
    NUMERIC_FEATURES,
    build_feature_matrix,
    subset_columns,
)
from app.services.ml.scoring import (  # noqa: E402
    ModelBundle,
    explain,
    is_anomalous,
    raw_scores,
    to_anomaly_score,
)

RANDOM_SEED = 42
THRESHOLD_PERCENTILE = 5.0
# The committed operating point stays 5% (chosen a priori, above). The
# wider sweep only *characterises* the trade-off curve -- it is reported,
# never used to reselect the threshold, which would be fitting the test set.
THRESHOLD_SWEEP = [1.0, 5.0, 10.0, 25.0, 50.0]
REALISTIC_BASE_RATE = 0.01
SCAN_PORT_FANOUT_THRESHOLD = 50

ARTIFACT_DIR = Path(__file__).resolve().parents[1] / "models"


# --------------------------------------------------------------------------
# Data loading and labelling
# --------------------------------------------------------------------------

def load_flows_with_features() -> list[dict]:
    """Every flow joined to its Phase 2 feature row, flattened."""
    flows = supabase_client.list_all_flows_with_features()
    complete = [f for f in flows if f.get("duration_seconds") is not None]
    if len(complete) != len(flows):
        print(f"  ! {len(flows) - len(complete)} flows lack feature rows and were skipped")
    return complete


def is_scan_capture(source_file: str) -> bool:
    return "scan" in source_file.lower()


def is_loopback(ip: str) -> bool:
    return str(ip).startswith("127.")


def is_loopback_dominated(flows: list[dict], fraction: float = 0.5) -> bool:
    """A capture whose traffic is mostly loopback cannot be honestly
    compared against LAN-captured baseline traffic.

    Loopback has no network hop (microsecond RTTs) and a different link
    layer (no 14-byte Ethernet header), so such a capture is separable
    from LAN traffic on capture-path artifacts alone -- a model would
    score near-perfect detection while having learned "loopback != WAN"
    rather than "scan != normal". Detected structurally rather than by
    hardcoded filename so this keeps working for future captures.
    """
    if not flows:
        return False
    loopback = sum(
        1 for f in flows if is_loopback(f["src_ip"]) or is_loopback(f["dst_ip"])
    )
    return (loopback / len(flows)) > fraction


def label_scan_flows(scan_flows: list[dict]) -> set[str]:
    """Which flows inside a scan capture are actually the scan.

    A capture taken on a live Wi-Fi adapter during a scan contains the scan
    AND ordinary background traffic (browser, telemetry). Labelling the
    whole capture "anomalous" would mislabel that background and unfairly
    depress precision, so the scan is identified by its actual behaviour:
    one source hitting one destination across many distinct ports.

    This is a stated heuristic, not oracle ground truth.
    """
    fanout: dict[tuple, set] = {}
    for flow in scan_flows:
        if flow.get("dst_port") is None:
            continue
        key = (flow["src_ip"], flow["dst_ip"])
        fanout.setdefault(key, set()).add(flow["dst_port"])

    scanning_pairs = {
        pair for pair, ports in fanout.items()
        if len(ports) > SCAN_PORT_FANOUT_THRESHOLD
    }
    return {
        flow["id"] for flow in scan_flows
        if (flow["src_ip"], flow["dst_ip"]) in scanning_pairs
    }


# --------------------------------------------------------------------------
# Fitting
# --------------------------------------------------------------------------

def fit_bundle(algorithm: str, train_flows: list[dict], feature_names: list[str]) -> ModelBundle:
    """Fits scaler + model on the training flows only.

    >>> THE SINGLE SCALER FIT SITE IN THE ENTIRE CODEBASE <<<
    Every other code path calls scaler.transform(). If a second .fit() ever
    appears anywhere, tests/test_leakage.py will not catch it directly --
    but the batch-invariance test will, because a re-fitting scaler makes a
    flow's score depend on its batch-mates.
    """
    matrix = build_feature_matrix(train_flows)
    if feature_names != FEATURE_NAMES:
        matrix = subset_columns(matrix, feature_names)

    scaler = StandardScaler()
    scaled = scaler.fit_transform(matrix)  # <-- the one and only .fit

    if algorithm == "isolation_forest":
        model = IsolationForest(
            n_estimators=100,
            max_samples="auto",
            contamination="auto",  # we derive the threshold ourselves
            random_state=RANDOM_SEED,
            n_jobs=-1,
        )
    elif algorithm == "one_class_svm":
        model = OneClassSVM(kernel="rbf", gamma="scale", nu=0.05)
    else:
        raise ValueError(f"unknown algorithm: {algorithm}")

    model.fit(scaled)

    training_raw = model.decision_function(scaled)
    threshold = float(np.percentile(training_raw, THRESHOLD_PERCENTILE))

    return ModelBundle(
        algorithm=algorithm,
        model=model,
        scaler=scaler,
        feature_names=feature_names,
        training_scores_sorted=np.sort(training_raw),
        training_medians_scaled=np.median(scaled, axis=0),
        threshold=threshold,
    )


def matrix_for(bundle: ModelBundle, flows: list[dict]) -> np.ndarray:
    matrix = build_feature_matrix(flows)
    if bundle.feature_names != FEATURE_NAMES:
        matrix = subset_columns(matrix, bundle.feature_names)
    return matrix


# --------------------------------------------------------------------------
# Metrics
# --------------------------------------------------------------------------

def flag_rate(bundle: ModelBundle, flows: list[dict]) -> float | None:
    if not flows:
        return None
    raw = raw_scores(bundle, matrix_for(bundle, flows))
    return float(np.mean(is_anomalous(bundle, raw)))


def precision_at_base_rate(recall: float, fpr: float, base_rate: float) -> float | None:
    """What precision would be if anomalies were `base_rate` of traffic.

    Our evaluation set is ~55% scan flows, which inflates precision far
    above anything realistic -- scans are rare in production. This
    re-projection is the honest counterpart to the raw number.

    Returns None (JSON null) rather than 0.0 when the model predicts no
    positives at all: precision is genuinely *undefined* there, and a 0.0
    would read like a measurement rather than an absence of one.
    """
    tp = base_rate * recall
    fp = (1.0 - base_rate) * fpr
    return float(tp / (tp + fp)) if (tp + fp) > 0 else None


def json_safe(obj):
    """NaN and Infinity have no JSON representation, so they are mapped to
    null rather than allowed to blow up serialisation at the DB boundary.
    """
    if isinstance(obj, dict):
        return {k: json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [json_safe(v) for v in obj]
    if isinstance(obj, float) and (np.isnan(obj) or np.isinf(obj)):
        return None
    return obj


def evaluate(bundle: ModelBundle, eval_flows: list[dict], y_true: np.ndarray) -> dict:
    raw = raw_scores(bundle, matrix_for(bundle, eval_flows))
    y_pred = is_anomalous(bundle, raw).astype(int)
    # decision_function is higher-is-more-normal; negate so that
    # higher-is-more-anomalous, which is what the AUC metrics expect.
    y_anomaly_score = -raw

    tp = int(np.sum((y_true == 1) & (y_pred == 1)))
    fp = int(np.sum((y_true == 0) & (y_pred == 1)))
    fn = int(np.sum((y_true == 1) & (y_pred == 0)))
    tn = int(np.sum((y_true == 0) & (y_pred == 0)))

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    metrics = {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "precision_at_1pct_base_rate": (
            round(projected, 4)
            if (projected := precision_at_base_rate(recall, fpr, REALISTIC_BASE_RATE)) is not None
            else None
        ),
    }

    # AUC metrics need both classes present.
    if len(np.unique(y_true)) == 2:
        metrics["roc_auc"] = round(float(roc_auc_score(y_true, y_anomaly_score)), 4)
        metrics["average_precision"] = round(
            float(average_precision_score(y_true, y_anomaly_score)), 4
        )
    return metrics


def threshold_sweep(bundle: ModelBundle, eval_flows: list[dict], y_true: np.ndarray) -> list[dict]:
    """Shows the sensitivity/false-alarm trade-off instead of burying it."""
    training = bundle.training_scores_sorted
    raw = raw_scores(bundle, matrix_for(bundle, eval_flows))
    rows = []
    for percentile in THRESHOLD_SWEEP:
        threshold = float(np.percentile(training, percentile))
        y_pred = (raw < threshold).astype(int)
        tp = int(np.sum((y_true == 1) & (y_pred == 1)))
        fp = int(np.sum((y_true == 0) & (y_pred == 1)))
        fn = int(np.sum((y_true == 1) & (y_pred == 0)))
        tn = int(np.sum((y_true == 0) & (y_pred == 0)))
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        rows.append({
            "training_percentile": percentile,
            "threshold": round(threshold, 6),
            "recall": round(recall, 4),
            "precision": round(precision, 4),
            "false_positive_rate": round(fp / (fp + tn), 4) if (fp + tn) else 0.0,
        })
    return rows


def leave_one_capture_out(algorithm: str, normal_flows: list[dict], feature_names: list[str]) -> list[dict]:
    """Train on 4 captures, measure the false-alarm rate on the unseen 5th.

    This is the most honest generalisation signal available from this
    dataset: it asks "does the model treat an entire capture it has never
    seen as normal?", which a random split cannot answer because random
    splits leave temporally-adjacent flows on both sides.
    """
    captures = sorted({f["source_file"] for f in normal_flows})
    folds = []
    for held_out in captures:
        train = [f for f in normal_flows if f["source_file"] != held_out]
        test = [f for f in normal_flows if f["source_file"] == held_out]
        if not train or not test:
            continue
        bundle = fit_bundle(algorithm, train, feature_names)
        folds.append({
            "held_out_capture": held_out,
            "held_out_flows": len(test),
            "false_positive_rate": round(flag_rate(bundle, test) or 0.0, 4),
        })
    return folds


def measure_latency(bundle: ModelBundle, flows: list[dict]) -> float:
    """ms per 1000 flows scored (required by the Phase 3 test gate)."""
    matrix = matrix_for(bundle, flows)
    start = time.perf_counter()
    raw_scores(bundle, matrix)
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    return round(elapsed_ms / max(len(flows), 1) * 1000.0, 3)


# --------------------------------------------------------------------------
# Persistence
# --------------------------------------------------------------------------

def persist(bundle: ModelBundle, metrics: dict, training_flows: list[dict], label: str) -> str:
    ARTIFACT_DIR.mkdir(exist_ok=True)
    version_id = str(uuid.uuid4())
    artifact_path = ARTIFACT_DIR / f"{bundle.algorithm}_{label}_{version_id[:8]}.joblib"
    joblib.dump(bundle, artifact_path)

    hyperparameters = bundle.model.get_params()
    hyperparameters = {k: (v if isinstance(v, (int, float, str, bool, type(None))) else str(v))
                       for k, v in hyperparameters.items()}

    supabase_client.insert_model_version({
        "id": version_id,
        "algorithm": bundle.algorithm,
        "variant": label,
        "feature_list": bundle.feature_names,
        "training_set_size": len(training_flows),
        "training_source_files": sorted({f["source_file"] for f in training_flows}),
        "hyperparameters": hyperparameters,
        "random_seed": RANDOM_SEED,
        "threshold": bundle.threshold,
        "threshold_strategy": (
            f"{THRESHOLD_PERCENTILE}th percentile of training decision_function scores; "
            "chosen a priori, never tuned against scan labels"
        ),
        "metrics": json_safe(metrics),
        # .as_posix(), not str() -- str(Path) uses the OS-native separator,
        # so a Windows run would write a backslash path into a column that
        # a Linux deployment later reads. Forward slashes work correctly
        # as a path separator on both platforms.
        "artifact_path": artifact_path.relative_to(ARTIFACT_DIR.parent).as_posix(),
    })
    return version_id


def score_and_store(bundle: ModelBundle, version_id: str, flows: list[dict]) -> None:
    matrix = matrix_for(bundle, flows)
    raw = raw_scores(bundle, matrix)
    scores = to_anomaly_score(bundle, raw)
    flags = is_anomalous(bundle, raw)
    contributions = explain(bundle, matrix, top_n=None, positive_only=False)

    rows = [{
        "flow_id": flow["id"],
        "model_version_id": version_id,
        "raw_score": float(raw[i]),
        "anomaly_score": round(float(scores[i]), 2),
        "is_anomalous": bool(flags[i]),
        "top_features": contributions[i],
    } for i, flow in enumerate(flows)]

    supabase_client.insert_flow_scores(rows)


# --------------------------------------------------------------------------

def run_variant(label: str, feature_names: list[str], normal_flows: list[dict],
                scan_flows: list[dict], scan_positive_ids: set[str],
                store_scores: bool, all_flows: list[dict],
                control_flows: list[dict] | None = None) -> dict:
    """One full train/evaluate/version pass for a given feature set."""
    train_flows, val_flows = train_test_split(
        normal_flows,
        test_size=0.2,
        random_state=RANDOM_SEED,
        stratify=[f["source_file"] for f in normal_flows],
    )

    # Evaluation set is HELD-OUT normals + the scan capture. Training flows
    # are excluded: the model was fitted to them, so including them would
    # flatter every metric.
    eval_flows = val_flows + scan_flows
    y_true = np.array([1 if f["id"] in scan_positive_ids else 0 for f in eval_flows])

    results = {}
    for algorithm in ("isolation_forest", "one_class_svm"):
        bundle = fit_bundle(algorithm, train_flows, feature_names)

        metrics = evaluate(bundle, eval_flows, y_true)
        metrics["train_flows"] = len(train_flows)
        metrics["validation_flows"] = len(val_flows)
        metrics["scan_flows_evaluated"] = len(scan_flows)
        metrics["scan_flows_labelled_positive"] = int(y_true.sum())
        # Circular by construction: the threshold IS the 5th percentile of
        # these very scores, so this is ~5% no matter how good the model is.
        metrics["fpr_on_training_normals_CIRCULAR"] = round(flag_rate(bundle, train_flows) or 0.0, 4)
        metrics["fpr_on_heldout_normals"] = round(flag_rate(bundle, val_flows) or 0.0, 4)
        metrics["threshold_sweep"] = threshold_sweep(bundle, eval_flows, y_true)
        metrics["leave_one_capture_out"] = leave_one_capture_out(
            algorithm, normal_flows, feature_names
        )
        metrics["inference_ms_per_1000_flows"] = measure_latency(bundle, eval_flows)

        if control_flows:
            # Reported for transparency, NOT a performance claim. This
            # capture is loopback-dominated, so a high flag rate here is
            # partly capture-path artifact and cannot be read as detection
            # skill. Named to make that impossible to misquote.
            metrics["CONFOUNDED_control_loopback_flag_rate"] = round(
                flag_rate(bundle, control_flows), 4
            )
            metrics["CONFOUNDED_control_flows"] = len(control_flows)

        version_id = persist(bundle, metrics, train_flows, label)
        if store_scores:
            score_and_store(bundle, version_id, all_flows)

        results[algorithm] = {"version_id": version_id, "metrics": metrics}
    return results


def main() -> None:
    print("Loading flows...")
    flows = load_flows_with_features()
    normal_flows = [f for f in flows if not is_scan_capture(f["source_file"])]
    scan_flows = [f for f in flows if is_scan_capture(f["source_file"])]

    # Split scan captures into usable evaluation data vs confounded
    # controls. A loopback-dominated capture is kept and scored, but must
    # never contribute to the headline metrics -- see is_loopback_dominated.
    eval_scan_flows: list[dict] = []
    control_scan_flows: list[dict] = []
    for capture in sorted({f["source_file"] for f in scan_flows}):
        capture_flows = [f for f in scan_flows if f["source_file"] == capture]
        if is_loopback_dominated(capture_flows):
            control_scan_flows.extend(capture_flows)
            print(f"  ! {capture}: {len(capture_flows)} flows are loopback-dominated "
                  f"-> CONTROL ONLY, excluded from metrics")
        else:
            eval_scan_flows.extend(capture_flows)

    print(f"  normal baseline : {len(normal_flows)} flows from "
          f"{len(set(f['source_file'] for f in normal_flows))} captures")
    print(f"  scan (evaluated): {len(eval_scan_flows)} flows from "
          f"{sorted({f['source_file'] for f in eval_scan_flows})}")

    if not normal_flows or not eval_scan_flows:
        raise SystemExit(
            "Need normal captures and at least one non-loopback scan capture. Aborting."
        )

    scan_positive_ids = label_scan_flows(eval_scan_flows)
    background = len(eval_scan_flows) - len(scan_positive_ids)
    print(f"  scan-labelled   : {len(scan_positive_ids)} positive, "
          f"{background} background flows inside the scan capture")

    scan_flows = eval_scan_flows

    print("\n=== PRIMARY: all 13 features ===")
    primary = run_variant("primary", FEATURE_NAMES, normal_flows, scan_flows,
                          scan_positive_ids, store_scores=True, all_flows=flows,
                          control_flows=control_scan_flows)

    print("\n=== ABLATION: behavioural features only (no timing, no sizes) ===")
    behavioural = run_variant("behavioural_only", BEHAVIORAL_FEATURE_NAMES, normal_flows,
                              scan_flows, scan_positive_ids, store_scores=False,
                              all_flows=flows)

    tcp_normal = [f for f in normal_flows if f["protocol"] == "TCP"]
    tcp_scan = [f for f in scan_flows if f["protocol"] == "TCP"]
    print("\n=== ABLATION: TCP-only subset (removes the protocol shortcut) ===")
    tcp_only = run_variant("tcp_only", FEATURE_NAMES, tcp_normal, tcp_scan,
                           scan_positive_ids, store_scores=False, all_flows=flows)

    summary = {"primary": primary, "behavioural_only": behavioural, "tcp_only": tcp_only}
    out = ARTIFACT_DIR / "last_training_report.json"
    ARTIFACT_DIR.mkdir(exist_ok=True)
    out.write_text(json.dumps(summary, indent=2))
    print(f"\nFull report written to {out}")

    print("\n" + "=" * 78)
    print("COMPARISON (primary variant, held-out evaluation set)")
    print("=" * 78)
    header = f"{'metric':<38}{'IsolationForest':>19}{'OneClassSVM':>19}"
    print(header)
    print("-" * 78)
    for key in ("recall", "precision", "f1", "roc_auc", "average_precision",
                "precision_at_1pct_base_rate", "fpr_on_heldout_normals",
                "fpr_on_training_normals_CIRCULAR", "inference_ms_per_1000_flows"):
        i_val = primary["isolation_forest"]["metrics"].get(key, "-")
        s_val = primary["one_class_svm"]["metrics"].get(key, "-")
        print(f"{key:<38}{str(i_val):>19}{str(s_val):>19}")


if __name__ == "__main__":
    main()
