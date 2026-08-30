import logging

from app.services import supabase_client
from app.services.integrations import mini_siem, threathunter
from app.services.ml.scoring import load_bundle, score_flows

logger = logging.getLogger("netsentinel.scoring")


def score_new_flows(inserted: list[dict], feature_rows: list[dict]) -> None:
    """Scores freshly-assembled flows with the current primary model, if
    one exists. Shared by the PCAP upload path and live capture -- neither
    has any scoring logic of its own, they both just call this per batch
    (upload: the whole file's flows at once; live capture: usually a
    single flow at a time, as each one completes).

    Best-effort by design: a scoring failure must not fail the upload or
    interrupt a live capture. The flows and their features are already
    safely stored at this point, and train_models.py can always re-score
    everything later.

    This is also the one place Phase 11's outbound integrations trigger
    from -- both the upload path and live capture funnel through here, so
    firing here (rather than in either caller) means neither needs any
    "is this flow flagged" logic of its own.
    """
    try:
        version = supabase_client.get_active_model_version()
        if not version or not version.get("artifact_path"):
            return

        bundle = load_bundle(version["artifact_path"])
        if bundle is None:
            return

        features_by_id = {row["flow_id"]: row for row in feature_rows}
        enriched = [{**flow, **features_by_id.get(flow["id"], {})} for flow in inserted]

        scored = score_flows(bundle, enriched)
        supabase_client.insert_flow_scores([
            {**row, "model_version_id": version["id"]} for row in scored
        ])

        flows_by_id = {flow["id"]: flow for flow in enriched}
        for score_row in scored:
            if not score_row.get("is_anomalous"):
                continue
            flow = flows_by_id.get(score_row["flow_id"])
            if not flow:
                continue
            flagged_flow = {**flow, **score_row}
            mini_siem.notify_flow_flagged(flagged_flow, version)
            threathunter.notify_flow_flagged(flagged_flow)
    except Exception as exc:
        logger.warning("Could not score flows: %s", exc)
