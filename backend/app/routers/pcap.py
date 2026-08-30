import asyncio
import logging
import shutil
from pathlib import Path

import pyshark
from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile

from app.config import settings
from app.services import rate_limit, supabase_client
from app.services.auth import CurrentUser, get_current_user, log_audit, require_role
from app.services.feature_extraction import compute_features
from app.services.flow_assembly import assemble_flows
from app.services.host_profiles import compute_host_profiles
from app.services.scoring import score_new_flows
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


@router.post("/pcap/upload")
def upload_pcap(
    file: UploadFile,
    request: Request,
    current_user: CurrentUser = Depends(require_role("analyst", "admin")),
):
    # Each upload triggers a full list_all_flows() + DELETE-all-then-INSERT
    # host_profiles rebuild, so its cost scales with total database size
    # rather than with the size of the file uploaded.
    rate_limit.enforce("upload", current_user.id)

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

        score_new_flows(inserted, feature_rows)

        log_audit(
            request, current_user, "pcap_upload",
            detail={"filename": file.filename, "flow_count": len(inserted)},
        )
        return {"flow_count": len(inserted), "flows": inserted}

    except PcapValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    finally:
        Path(tmp_path).unlink(missing_ok=True)


@router.get("/flows")
def get_flows(
    source_file: str | None = None,
    sort: str = "started_desc",
    current_user: CurrentUser = Depends(get_current_user),
):
    """Flows with their anomaly scores.

    `scored_by` names which model produced the scores. Two algorithms
    score the same flow very differently, so a bare score column with no
    attribution is genuinely ambiguous -- the caller must be able to tell
    which model it is looking at.

    `source_file`/`sort` let an analyst find a specific flow (e.g. for
    verdict testing) beyond the default most-recent-500 view -- see
    list_flows()'s docstring for why a filter or score-sort searches a
    wider slice under the hood.
    """
    if sort not in supabase_client.SORT_OPTIONS:
        raise HTTPException(
            status_code=422,
            detail=f"sort must be one of {supabase_client.SORT_OPTIONS}",
        )

    version = supabase_client.get_active_model_version()
    return {
        "flows": supabase_client.list_flows(source_file=source_file, sort=sort),
        "scored_by": {
            "algorithm": version["algorithm"],
            "variant": version["variant"],
            "model_version_id": version["id"],
            "threshold": version["threshold"],
        } if version else None,
    }


@router.get("/flows/source-files")
def get_source_files(current_user: CurrentUser = Depends(get_current_user)):
    """Distinct source_file values, for the flows table's filter dropdown."""
    return {"source_files": supabase_client.list_source_files()}
