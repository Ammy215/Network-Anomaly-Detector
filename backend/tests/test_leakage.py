"""Demonstrated leakage guards.

Each test proves a property by computing it, not by asserting that the
code "looks right". These are the checks PROJECT.md section 16 requires
against train/test, normalisation, and threshold leakage.
"""

import sys
from pathlib import Path

import numpy as np
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import train_models  # noqa: E402

from app.services.ml.feature_matrix import FEATURE_NAMES, build_feature_matrix  # noqa: E402
from app.services.ml.scoring import raw_scores  # noqa: E402


def normal_flow(i: int) -> dict:
    return {
        "id": f"normal-{i}",
        "source_file": f"capture{i % 4 + 1}_normal.pcapng",
        "protocol": "TCP",
        "src_ip": "192.168.0.107",
        "dst_ip": f"93.184.216.{i % 200}",
        "dst_port": 443,
        "duration_seconds": 0.5 + (i % 10) * 0.1,
        "packets_per_second": 100.0 + i % 50,
        "bytes_per_second": 8000.0 + i * 10,
        "avg_packet_size": 100.0 + i % 40,
        "packet_count": 20 + i % 15,
        "is_bidirectional": True,
        "handshake_completed": True,
        "close_type": "fin_fin",
    }


def scan_flow(i: int) -> dict:
    """Deliberately extreme: microsecond, tiny, RST-without-handshake."""
    return {
        "id": f"scan-{i}",
        "source_file": "capture_scan_lan.pcapng",
        "protocol": "TCP",
        "src_ip": "192.168.0.107",
        "dst_ip": "192.168.0.1",
        "dst_port": i,
        "duration_seconds": 0.00003,
        "packets_per_second": 60000.0,
        "bytes_per_second": 3000000.0,
        "avg_packet_size": 50.0,
        "packet_count": 2,
        "is_bidirectional": True,
        "handshake_completed": False,
        "close_type": "rst",
    }


NORMAL = [normal_flow(i) for i in range(200)]
SCAN = [scan_flow(i) for i in range(300)]


# ---------------------------------------------------------------------------
# 1. Normalisation leakage
# ---------------------------------------------------------------------------

def test_scaler_is_fitted_on_training_slice_only():
    """The scaler must know nothing about the scan flows.

    Demonstrated by recomputing both means and showing the fitted scaler
    matches the training slice exactly and differs materially from a
    scaler that had seen everything.
    """
    train_flows = NORMAL[:160]
    bundle = train_models.fit_bundle("isolation_forest", train_flows, FEATURE_NAMES)

    train_matrix = build_feature_matrix(train_flows)
    full_matrix = build_feature_matrix(NORMAL + SCAN)

    expected_train_mean = train_matrix.mean(axis=0)
    contaminated_mean = full_matrix.mean(axis=0)

    # Fitted on training only -- matches exactly.
    np.testing.assert_allclose(bundle.scaler.mean_, expected_train_mean, rtol=1e-12)

    # And is meaningfully different from what it would have been had the
    # scan flows leaked in. Printed so the difference is visible, not
    # merely asserted.
    duration_idx = FEATURE_NAMES.index("duration_seconds")
    print(
        f"\n  scaler mean[duration] fitted on train  = {bundle.scaler.mean_[duration_idx]:.6f}"
        f"\n  same statistic if scan flows leaked in = {contaminated_mean[duration_idx]:.6f}"
    )
    assert not np.allclose(bundle.scaler.mean_, contaminated_mean, rtol=1e-3)


def test_inference_never_refits_the_scaler():
    """Behavioural proof, stronger than reading the code.

    If any inference path called fit_transform instead of transform, a
    flow's scaled values -- and therefore its score -- would depend on
    which other flows shared its batch. Scoring one flow alone and inside
    a large mixed batch must give bit-identical results.
    """
    bundle = train_models.fit_bundle("isolation_forest", NORMAL[:160], FEATURE_NAMES)
    target = SCAN[0]

    alone = raw_scores(bundle, build_feature_matrix([target]))[0]
    mixed_batch = [target] + NORMAL[:50] + SCAN[1:50]
    in_batch = raw_scores(bundle, build_feature_matrix(mixed_batch))[0]

    print(f"\n  score alone={alone!r}  score in mixed batch={in_batch!r}")
    assert alone == in_batch


# ---------------------------------------------------------------------------
# 2. Train/test leakage
# ---------------------------------------------------------------------------

def test_scan_flows_never_enter_the_training_set():
    all_flows = NORMAL + SCAN
    normal_only = [f for f in all_flows if not train_models.is_scan_capture(f["source_file"])]

    assert len(normal_only) == len(NORMAL)
    assert all("scan" not in f["source_file"].lower() for f in normal_only)
    print(f"\n  training pool = {len(normal_only)} flows, scan flows excluded = {len(SCAN)}")


def test_scan_capture_detection_matches_source_file():
    assert train_models.is_scan_capture("capture_scan_lan.pcapng")
    assert train_models.is_scan_capture("capture_scan_nmap.pcapng")
    assert not train_models.is_scan_capture("capture1_browsing.pcapng")
    assert not train_models.is_scan_capture("test.pcapng")


# ---------------------------------------------------------------------------
# 3. Threshold leakage
# ---------------------------------------------------------------------------

def test_threshold_comes_from_training_scores_not_all_data():
    """Tuning the threshold on labelled scan data would fit the test set
    and make every downstream metric optimistic. Demonstrated by showing
    the threshold differs from the same percentile over everything.
    """
    train_flows = NORMAL[:160]
    bundle = train_models.fit_bundle("isolation_forest", train_flows, FEATURE_NAMES)

    train_threshold = bundle.threshold
    all_raw = raw_scores(bundle, build_feature_matrix(NORMAL + SCAN))
    contaminated_threshold = float(np.percentile(all_raw, train_models.THRESHOLD_PERCENTILE))

    print(
        f"\n  threshold from training scores only = {train_threshold:.6f}"
        f"\n  threshold if computed over all data = {contaminated_threshold:.6f}"
    )
    assert train_threshold != contaminated_threshold

    # And it really is the stated percentile of the training distribution.
    recomputed = float(np.percentile(bundle.training_scores_sorted,
                                     train_models.THRESHOLD_PERCENTILE))
    assert abs(train_threshold - recomputed) < 1e-12


# ---------------------------------------------------------------------------
# 4. Labelling sanity
# ---------------------------------------------------------------------------

def test_scan_labelling_separates_scan_from_background_traffic():
    """A live capture taken during a scan also contains ordinary traffic.
    Labelling by port fan-out must catch the scan and leave background
    flows labelled negative.
    """
    background = [{
        "id": "bg-1",
        "src_ip": "192.168.0.107",
        "dst_ip": "142.250.0.1",
        "dst_port": 443,
    }]
    mixed = SCAN + background
    positives = train_models.label_scan_flows(mixed)

    assert len(positives) == len(SCAN)
    assert "bg-1" not in positives
    print(f"\n  labelled {len(positives)} scan flows, {len(background)} background excluded")
