from __future__ import annotations

import asyncio
import ctypes
import logging
import queue
import threading
from datetime import datetime, timezone

from scapy.all import AsyncSniffer

from app.config import settings
from app.services import supabase_client
from app.services.feature_extraction import compute_features
from app.services.flow_assembly import FlowAssembler, extract_packet_info_scapy
from app.services.host_profiles import compute_host_profiles
from app.services.scoring import score_new_flows

logger = logging.getLogger("netsentinel.live_capture")

# How often a running capture checks for flows that have simply gone quiet
# (no RST, no FIN/FIN, just nothing new on that key for a while) -- see
# FlowAssembler.sweep_timeouts()'s docstring for why this can't just rely
# on the next-packet-arrival check the upload path uses.
SWEEP_INTERVAL_SECONDS = 5

# How long to wait for Scapy's sniffer thread to confirm it actually opened
# the interface before treating the attempt as failed.
START_TIMEOUT_SECONDS = 3


class CaptureError(Exception):
    """Base for every live-capture error the router translates into a
    clean HTTP response -- never lets a raw Scapy/Npcap exception surface
    to the client.
    """


class CaptureAlreadyRunningError(CaptureError):
    pass


class CaptureInterfaceError(CaptureError):
    pass


class CaptureStartError(CaptureError):
    """Capture failed to actually start.

    Deliberately NOT split into a separate "permission denied" vs. "other
    failure" exception type. I tested this for real on this machine: a
    non-admin process here can actually open Npcap fine (this Npcap
    install isn't restricted to Administrators), and a bad interface name
    fails with a plain ValueError, not anything permission-shaped -- so
    there's no single, reliable signal to pattern-match "it's specifically
    a privilege problem" across different Npcap configurations. Rather
    than fake a confident 403-vs-500 split I can't actually guarantee
    holds on every install, the error message includes the real underlying
    failure plus an elevation hint when this process isn't running as
    Administrator, and lets a human read both.
    """


def is_elevated() -> bool:
    """Best-effort "is this process running as Administrator" check.
    Purely a diagnostic hint in error messages -- NOT used to block a
    start attempt outright, since a permissive Npcap install can let a
    non-admin process capture just fine (confirmed on this machine).
    """
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


# Windows/Npcap expose every filter-driver layer bound to a real adapter
# (WFP, QoS Scheduler, NDIS lightweight filters, Npcap's own packet driver,
# and -- Wi-Fi specifically -- its Virtual/Native WiFi filter drivers) as
# its own separate pseudo-interface -- one physical NIC can easily produce
# 5-7 of these. None of them are something you'd ever deliberately choose
# to sniff on; they're driver-stack plumbing, not additional network paths.
_PSEUDO_INTERFACE_MARKERS = ("WFP", "QoS", "NDIS", "Npcap Packet Driver", "WiFi Filter Driver")

# Virtual NICs from local virtualization software -- real, Npcap-visible
# interfaces (unlike the pseudo-interfaces above), but not something worth
# offering next to Wi-Fi/Ethernet in a physical-adapter picker.
_VIRTUAL_NIC_MARKERS = ("VMware", "VirtualBox")


def list_interfaces() -> list[dict]:
    """Real, selectable capture interfaces on this machine -- filtered down
    from Npcap's raw list, which also includes every filter-driver pseudo-
    interface (see `_PSEUDO_INTERFACE_MARKERS`) and placeholder adapters
    with no MAC address (loopback, WAN miniports, Teredo/6to4 tunneling
    adapters) that Scapy can enumerate but nothing real ever arrives on.

    `id` is the exact string Scapy needs back via `iface=` to open this
    interface -- the frontend never needs to understand Windows' own
    interface-naming scheme, it just echoes back whichever `id` it was
    given. `name` is a human-readable label built from Npcap's own
    description field, per the hard requirement that interface selection
    never be a raw, opaque identifier.
    """
    try:
        from scapy.arch.windows import get_windows_if_list
        raw = get_windows_if_list()
    except Exception as exc:
        logger.warning("Could not list capture interfaces (Npcap missing or misconfigured?): %s", exc)
        return []

    interfaces = []
    for iface in raw:
        name = iface.get("name")
        if not name:
            continue
        if not iface.get("mac"):
            continue
        if any(marker in name for marker in _PSEUDO_INTERFACE_MARKERS):
            continue
        description = iface.get("description") or name
        if any(marker in description for marker in _VIRTUAL_NIC_MARKERS):
            continue
        interfaces.append({"id": name, "name": f"{description} ({name})"})
    return interfaces


class _EventBus:
    """Broadcasts completed live-capture flows to every open SSE
    connection. `publish()` runs on Scapy's own capture thread (never the
    asyncio event loop), so handing data to an `asyncio.Queue` safely
    requires `call_soon_threadsafe` -- a plain `queue.put_nowait` from a
    non-loop thread is not safe to call on an asyncio.Queue.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._subscribers: list[tuple[asyncio.AbstractEventLoop, "asyncio.Queue"]] = []

    def subscribe(self, loop: asyncio.AbstractEventLoop) -> "asyncio.Queue":
        q: asyncio.Queue = asyncio.Queue()
        with self._lock:
            self._subscribers.append((loop, q))
        return q

    def unsubscribe(self, q: "asyncio.Queue") -> None:
        with self._lock:
            self._subscribers = [(loop, sub) for loop, sub in self._subscribers if sub is not q]

    def publish(self, item) -> None:
        with self._lock:
            subs = list(self._subscribers)
        for loop, q in subs:
            loop.call_soon_threadsafe(q.put_nowait, item)


_event_bus = _EventBus()


def subscribe_events(loop: asyncio.AbstractEventLoop) -> "asyncio.Queue":
    return _event_bus.subscribe(loop)


def unsubscribe_events(q: "asyncio.Queue") -> None:
    _event_bus.unsubscribe(q)


class CaptureSession:
    """One in-memory, process-lifetime capture session.

    Never persisted anywhere (no DB row, no config flag) -- that's what
    guarantees "never on by default": a backend restart has nothing to
    read that would tell it a capture was running before, so it always
    starts idle. Singleton: only one capture at a time, enforced by
    `_lock`; starting a second while one runs is a clean 409, not a second
    concurrent capture.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sniffer: AsyncSniffer | None = None
        self._assembler: FlowAssembler | None = None
        self._sweep_timer: threading.Timer | None = None
        self.interface: str | None = None
        self.started_by: str | None = None
        self.started_at: datetime | None = None
        self.flow_count: int = 0

    @property
    def running(self) -> bool:
        return self._sniffer is not None

    def _status_unlocked(self) -> dict:
        # Callers that already hold `self._lock` (e.g. start(), at the end
        # of its own locked block) must use this instead of `status()` --
        # `threading.Lock` isn't reentrant, so a locked caller re-entering
        # `status()`'s own `with self._lock:` would deadlock itself.
        return {
            "running": self.running,
            "interface": self.interface,
            "started_by": self.started_by,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "flow_count": self.flow_count,
        }

    def status(self) -> dict:
        with self._lock:
            return self._status_unlocked()

    def start(self, interface_id: str, user_email: str) -> dict:
        with self._lock:
            if self.running:
                raise CaptureAlreadyRunningError(
                    "A capture is already running. Stop it before starting another."
                )

            known_ids = {i["id"] for i in list_interfaces()}
            if interface_id not in known_ids:
                raise CaptureInterfaceError(f"Unknown interface: {interface_id!r}.")

            source_label = f"live:{interface_id}:{datetime.now(timezone.utc).isoformat()}"
            assembler = FlowAssembler(
                source_label,
                timeout_seconds=settings.flow_inactivity_timeout_seconds,
                packet_info_extractor=extract_packet_info_scapy,
            )

            started_event = threading.Event()
            sniffer = AsyncSniffer(
                iface=interface_id,
                store=False,
                prn=lambda packet: self._on_packet(assembler, packet),
                started_callback=started_event.set,
            )
            sniffer.start()
            started_ok = started_event.wait(timeout=START_TIMEOUT_SECONDS)

            if not started_ok:
                try:
                    sniffer.stop()
                except Exception:
                    pass
                underlying = str(sniffer.exception) if sniffer.exception else (
                    f"capture did not start within {START_TIMEOUT_SECONDS}s"
                )
                hint = (
                    ""
                    if is_elevated()
                    else (
                        " This backend process is not running as Administrator -- if your "
                        "Npcap install restricts capture to admins, that is the likely cause."
                    )
                )
                raise CaptureStartError(f"Could not start capture on '{interface_id}': {underlying}.{hint}")

            self._sniffer = sniffer
            self._assembler = assembler
            self.interface = interface_id
            self.started_by = user_email
            self.started_at = datetime.now(timezone.utc)
            self.flow_count = 0
            self._schedule_sweep()
            logger.info("Live capture started on %s by %s", interface_id, user_email)
            return self._status_unlocked()

    def _schedule_sweep(self) -> None:
        def sweep():
            with self._lock:
                if not self.running or self._assembler is None:
                    return
                completed = self._assembler.sweep_timeouts(datetime.now(timezone.utc))
            for flow in completed:
                self._persist_flow(flow)
            with self._lock:
                still_running = self.running
            if still_running:
                self._schedule_sweep()

        self._sweep_timer = threading.Timer(SWEEP_INTERVAL_SECONDS, sweep)
        self._sweep_timer.daemon = True
        self._sweep_timer.start()

    def _on_packet(self, assembler: FlowAssembler, packet) -> None:
        # Runs directly on Scapy's own sniffer thread for every captured
        # packet -- a *different* thread from the periodic sweep timer and
        # from whichever request thread might be calling stop() right now,
        # all of which can touch the same assembler's internal dicts. The
        # lock only wraps the assembler mutation itself, never the
        # `_persist_flow` network I/O below -- holding it across a Supabase
        # round trip would stall every other packet/status/stop call for
        # that entire duration, and here it can't stall anything meanwhile.
        try:
            with self._lock:
                completed = assembler.add_packet(packet)
        except Exception as exc:
            logger.warning("Error assembling live packet: %s", exc)
            return
        for flow in completed:
            self._persist_flow(flow)

    def _persist_flow(self, flow: dict) -> None:
        """Mirrors pcap.py's per-flow steps (insert, features, scoring) --
        the same pipeline uploaded PCAPs go through, minus the host_profiles
        rollup, which is deferred to capture-stop (see module docstring /
        Phase 10 plan: too expensive to redo after every single flow).
        """
        try:
            inserted = supabase_client.insert_flows([flow])
            if not inserted:
                return
            feature_rows = [{"flow_id": inserted[0]["id"], **compute_features(flow)}]
            supabase_client.insert_flow_features(feature_rows)
            score_new_flows(inserted, feature_rows)
            with self._lock:
                self.flow_count += 1
            _event_bus.publish(inserted[0])
        except Exception as exc:
            logger.warning("Could not persist live-captured flow: %s", exc)

    def stop(self) -> dict:
        with self._lock:
            if not self.running:
                raise CaptureError("No capture is running.")
            sniffer = self._sniffer
            assembler = self._assembler
            interface = self.interface
            started_at = self.started_at
            self._sniffer = None
            if self._sweep_timer is not None:
                self._sweep_timer.cancel()  # else a pending sweep could race finalize_all below
                self._sweep_timer = None

        try:
            sniffer.stop()  # blocks until Scapy's thread fully exits -- no more add_packet() after this
        except Exception as exc:
            logger.warning("Error stopping sniffer (already stopped?): %s", exc)

        with self._lock:
            completed = assembler.finalize_all("stopped") if assembler else []
        for flow in completed:
            self._persist_flow(flow)

        # One full recompute at stop, same granularity as a single upload
        # event -- see module docstring for why per-flow would be too
        # expensive during a running capture.
        try:
            all_flows = supabase_client.list_all_flows()
            supabase_client.replace_host_profiles(compute_host_profiles(all_flows))
        except Exception as exc:
            logger.warning("Could not recompute host profiles after capture stop: %s", exc)

        with self._lock:
            flow_count = self.flow_count
            self.interface = None
            self.started_by = None
            self.started_at = None
            self.flow_count = 0
            self._assembler = None

        duration_seconds = (
            (datetime.now(timezone.utc) - started_at).total_seconds() if started_at else None
        )
        _event_bus.publish(None)  # sentinel: tells every open stream the session ended
        return {"interface": interface, "duration_seconds": duration_seconds, "flow_count": flow_count}


_session = CaptureSession()


def get_session() -> CaptureSession:
    return _session
