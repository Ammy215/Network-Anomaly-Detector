import asyncio
import json
from typing import AsyncIterator

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.services import live_capture, rate_limit
from app.services.auth import (
    CurrentUser,
    get_current_user,
    get_current_user_from_query,
    log_audit,
    require_role,
)

router = APIRouter(prefix="/api/capture", tags=["capture"])


class StartRequest(BaseModel):
    interface: str


@router.get("/interfaces")
def get_interfaces(current_user: CurrentUser = Depends(get_current_user)):
    """Every capture-capable interface on this machine, human-readable.
    Read-only info -- a viewer can see what's available even though only
    analyst/admin can actually start a capture on one.
    """
    return {"interfaces": live_capture.list_interfaces()}


@router.get("/status")
def get_status(current_user: CurrentUser = Depends(get_current_user)):
    return live_capture.get_session().status()


@router.post("/start")
def start_capture(
    body: StartRequest,
    request: Request,
    current_user: CurrentUser = Depends(require_role("analyst", "admin")),
):
    # The `capture` bucket existed in LIMITS from Phase 12 but was never
    # actually wired to anything, leaving start/stop unthrottled against a
    # process-wide singleton (Phase 13.5, D1).
    rate_limit.enforce("capture", current_user.id)

    session = live_capture.get_session()
    try:
        result = session.start(body.interface, current_user.email)
    except live_capture.CaptureAlreadyRunningError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except live_capture.CaptureInterfaceError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except live_capture.CaptureStartError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    log_audit(request, current_user, "capture_start", detail={"interface": body.interface})
    return result


@router.post("/stop")
def stop_capture(
    request: Request,
    current_user: CurrentUser = Depends(require_role("analyst", "admin")),
):
    rate_limit.enforce("capture", current_user.id)

    session = live_capture.get_session()
    try:
        result = session.stop()
    except live_capture.CaptureError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    log_audit(request, current_user, "capture_stop", detail=result)
    return result


@router.get("/stream")
async def stream_capture(
    request: Request,
    current_user: CurrentUser = Depends(get_current_user_from_query),
):
    """Server-Sent Events feed of flows as they complete during a live
    capture. Auth via `?token=` (Depends(get_current_user_from_query) reads
    it as a query param) rather than the `Authorization` header every other
    endpoint uses -- the browser's `EventSource` API can't set custom
    headers, so this is the one endpoint in the app that authenticates
    differently. See Phase 10 plan for the token-in-URL trade-off this
    accepts (acceptable for a local, single-operator lab tool; would not
    be for an internet-facing multi-tenant product).
    """
    loop = asyncio.get_event_loop()
    events = live_capture.subscribe_events(loop)

    async def event_source() -> AsyncIterator[str]:
        try:
            yield "event: connected\ndata: {}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    item = await asyncio.wait_for(events.get(), timeout=15)
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
                    continue
                if item is None:
                    yield "event: capture-stopped\ndata: {}\n\n"
                    continue
                yield f"data: {json.dumps(item, default=str)}\n\n"
        finally:
            live_capture.unsubscribe_events(events)

    return StreamingResponse(
        event_source(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
