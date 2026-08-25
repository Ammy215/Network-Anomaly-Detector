"""Score every stored flow with one model version, then make it the
shipped model.

Run:  python scripts/activate_model.py <model_version_id>

Switching the shipped model is a deliberate, recorded act -- never a side
effect of retraining. Scores are keyed by (flow_id, model_version_id), so
activating a different model changes which scores are *displayed* without
destroying any other model's, and the previous model stays fully
queryable via GET /api/models.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services import supabase_client  # noqa: E402
from app.services.ml.scoring import load_bundle, score_flows  # noqa: E402


def main(version_id: str) -> None:
    version = supabase_client.get_model_version(version_id)
    if not version:
        raise SystemExit(f"No model version {version_id}")

    print(f"Model : {version['algorithm']} / {version['variant']}")
    print(f"        {len(version['feature_list'])} features, threshold {version['threshold']:.4f}")

    bundle = load_bundle(version["artifact_path"])
    if bundle is None:
        raise SystemExit(
            f"Artifact missing: {version['artifact_path']}. "
            "Model artifacts are git-ignored -- re-run scripts/train_models.py."
        )

    flows = supabase_client.list_all_flows_with_features()
    scorable = [f for f in flows if f.get("duration_seconds") is not None]
    print(f"Scoring {len(scorable)} flows...")

    scored = score_flows(bundle, scorable)
    written = supabase_client.insert_flow_scores([
        {**row, "model_version_id": version_id} for row in scored
    ])
    flagged = sum(1 for row in scored if row["is_anomalous"])
    print(f"  wrote {written} score rows, {flagged} flagged as anomalous")

    supabase_client.set_active_model_version(version_id)
    active = supabase_client.get_active_model_version()
    print(f"Active: {active['algorithm']} / {active['variant']} ({active['id']})")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: python scripts/activate_model.py <model_version_id>")
    main(sys.argv[1])
