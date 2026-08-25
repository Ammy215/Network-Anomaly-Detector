import asyncio
import logging
import shutil
from pathlib import Path

import pyshark
from fastapi import APIRouter, HTTPException, UploadFile

from app.config import settings
from app.services import supabase_client
from app.services.feature_extraction import compute_features
from app.services.flow_assembly import assemble_flows
from app.services.host_profiles import compute_host_profiles
from app.services.ml.scoring import load_bundle, score_flows
from app.services.pcap_validation import (
    PcapTooLargeError,
    PcapValidationError,
    has_allowed_extension,
    save_upload_to_tempfile,
    verify_pcap_signature,
)

logger = logging.getLogger("netsentinel.pcap")

router = APIRouter(prefix="/api", tags=["pcap"])

_COMMON_TSHARK_LOCATIONS = (
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
)


def _resolve_tshark_path() -> str | None:
    """PATH often isn't updated yet in an already-running shell right after
    a fresh Wireshark install, so fall back to the standard install
    locations rather than depending on it.
    """
    if settings.tshark_path:
        return settings.tshark_path
    found = shutil.which("tshark")
    if found:
        return found
    for candidate in _COMMON_TSHARK_LOCATIONS:
        if Path(candidate).exists():
            return candidate
    return None


def _score_new_flows(inserted: list[dict], feature_rows: list[dict]) -> None:
    """Scores a fresh upload with the current primary model, if one exists.

    Best-effort by design: a scoring failure must not fail the upload. The
    flows and their features are already safely stored at this point, and
    train_models.py can always re-score everything later.
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
    except Exception as exc:
        logger.warning("Could not score uploaded flows: %s", exc)


@router.post("/pcap/upload")
def upload_pcap(file: UploadFile):
    if not has_allowed_extension(file.filename):
        raise HTTPException(status_code=400, detail="File must be a .pcap or .pcapng file.")

    try:
        tmp_path = save_upload_to_tempfile(file, settings.max_upload_size_bytes)
    except PcapTooLargeError as exc:
        raise HTTPException(status_code=413, detail=str(exc))
    except PcapValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    try:
        verify_pcap_signature(tmp_path)

        tshark_path = _resolve_tshark_path()
        if not tshark_path:
            raise HTTPException(
                status_code=503,
                detail="tshark was not found. Install Wireshark (includes tshark) to enable PCAP parsing.",
            )

        try:
            # PyShark's sync API drives its own asyncio internals and
            # expects an event loop to already exist on the current thread.
            # FastAPI runs sync `def` endpoints in a threadpool worker
            # thread, which has no event loop by default in modern Python
            # (asyncio.get_event_loop() no longer auto-creates one outside
            # the main thread) -- so one has to be created explicitly here.
            try:
                asyncio.get_event_loop()
            except RuntimeError:
                asyncio.set_event_loop(asyncio.new_event_loop())

            capture = pyshark.FileCapture(tmp_path, tshark_path=tshark_path)
            flows = assemble_flows(
                capture,
                source_file=file.filename,
                timeout_seconds=settings.flow_inactivity_timeout_seconds,
            )
            capture.close()
        except Exception as exc:
            logger.warning("tshark failed to parse upload %s: %s", file.filename, exc)
            raise HTTPException(status_code=400, detail="Could not parse this file as a packet capture.")

        inserted = supabase_client.insert_flows(flows)

        feature_rows = [{"flow_id": flow["id"], **compute_features(flow)} for flow in inserted]
        supabase_client.insert_flow_features(feature_rows)

        # Full recompute over every stored flow, not just this upload's --
        # host_profiles is a global rollup, so it uses the paginated fetch
        # (list_all_flows), not the display-capped list_flows.
        all_flows = supabase_client.list_all_flows()
        supabase_client.replace_host_profiles(compute_host_profiles(all_flows))

        _score_new_flows(inserted, feature_rows)

        return {"flow_count": len(inserted), "flows": inserted}

    except PcapValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    finally:
        Path(tmp_path).unlink(missing_ok=True)


@router.get("/flows")
def get_flows():
    """Flows with their anomaly scores.

    `scored_by` names which model produced the scores. Two algorithms
    score the same flow very differently, so a bare score column with no
    attribution is genuinely ambiguous -- the caller must be able to tell
    which model it is looking at.
    """
    version = supabase_client.get_active_model_version()
    return {
        "flows": supabase_client.list_flows(),
        "scored_by": {
            "algorithm": version["algorithm"],
            "variant": version["variant"],
            "model_version_id": version["id"],
            "threshold": version["threshold"],
        } if version else None,
    }
