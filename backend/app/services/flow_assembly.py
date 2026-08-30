import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("netsentinel.flow_assembly")


@dataclass
class PacketInfo:
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    timestamp: datetime
    length: int
    tcp_fin: bool = False
    tcp_rst: bool = False
    tcp_syn: bool = False
    tcp_ack: bool = False


def _flag_is_set(value) -> bool:
    """PyShark represents boolean TCP flag fields as the string '1'/'0' in
    some versions and 'True'/'False' in others — normalize both rather
    than assume one.
    """
    return str(value).strip().lower() in ("1", "true")


def extract_packet_info(packet) -> PacketInfo:
    """Pulls the fields flow assembly cares about out of a pyshark packet.

    Raises ValueError for anything that isn't a routable IP packet (no
    flow to assemble) or that's missing fields flow assembly needs — the
    caller treats both as "skip this packet," never a fatal error.
    """
    if hasattr(packet, "ip"):
        src_ip, dst_ip = packet.ip.src, packet.ip.dst
    elif hasattr(packet, "ipv6"):
        src_ip, dst_ip = packet.ipv6.src, packet.ipv6.dst
    else:
        raise ValueError("no IP/IPv6 layer")

    timestamp = datetime.fromtimestamp(float(packet.sniff_timestamp), tz=timezone.utc)
    length = int(packet.length)

    src_port = dst_port = None
    tcp_fin = tcp_rst = tcp_syn = tcp_ack = False

    if hasattr(packet, "tcp"):
        protocol = "TCP"
        src_port = int(packet.tcp.srcport)
        dst_port = int(packet.tcp.dstport)
        tcp_fin = _flag_is_set(getattr(packet.tcp, "flags_fin", "0"))
        tcp_rst = _flag_is_set(getattr(packet.tcp, "flags_reset", "0"))
        tcp_syn = _flag_is_set(getattr(packet.tcp, "flags_syn", "0"))
        tcp_ack = _flag_is_set(getattr(packet.tcp, "flags_ack", "0"))
    elif hasattr(packet, "udp"):
        protocol = "UDP"
        src_port = int(packet.udp.srcport)
        dst_port = int(packet.udp.dstport)
    elif hasattr(packet, "icmp"):
        protocol = "ICMP"
    elif hasattr(packet, "icmpv6"):
        protocol = "ICMPv6"
    else:
        protocol = (getattr(packet, "transport_layer", None) or packet.highest_layer or "OTHER")

    return PacketInfo(
        src_ip, dst_ip, src_port, dst_port, protocol, timestamp, length,
        tcp_fin, tcp_rst, tcp_syn, tcp_ack,
    )


def extract_packet_info_scapy(packet) -> PacketInfo:
    """The same job as `extract_packet_info`, for a live Scapy packet
    instead of a parsed PyShark one -- these are genuinely different
    object APIs (`packet[IP].src` + layer membership vs. `packet.ip.src` +
    `hasattr`), not just a different import, so this can't share a body
    with the PyShark version. The *state machine* that consumes
    `PacketInfo` (FlowAssembler) is fully shared regardless of which
    extractor produced it -- only this parsing step is source-specific.
    """
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import IPv6

    if packet.haslayer(IP):
        src_ip, dst_ip = packet[IP].src, packet[IP].dst
    elif packet.haslayer(IPv6):
        src_ip, dst_ip = packet[IPv6].src, packet[IPv6].dst
    else:
        raise ValueError("no IP/IPv6 layer")

    timestamp = datetime.fromtimestamp(float(packet.time), tz=timezone.utc)
    length = len(packet)

    src_port = dst_port = None
    tcp_fin = tcp_rst = tcp_syn = tcp_ack = False

    if packet.haslayer(TCP):
        protocol = "TCP"
        tcp = packet[TCP]
        src_port = int(tcp.sport)
        dst_port = int(tcp.dport)
        flags = tcp.flags
        tcp_fin = "F" in flags
        tcp_rst = "R" in flags
        tcp_syn = "S" in flags
        tcp_ack = "A" in flags
    elif packet.haslayer(UDP):
        protocol = "UDP"
        src_port = int(packet[UDP].sport)
        dst_port = int(packet[UDP].dport)
    elif packet.haslayer(ICMP):
        protocol = "ICMP"
    elif packet.haslayer(IPv6) and packet[IPv6].nh == 58:  # next-header 58 = ICMPv6
        protocol = "ICMPv6"
    else:
        protocol = packet.lastlayer().name or "OTHER"

    return PacketInfo(
        src_ip, dst_ip, src_port, dst_port, protocol, timestamp, length,
        tcp_fin, tcp_rst, tcp_syn, tcp_ack,
    )


def _canonical_key(info: PacketInfo):
    """Both directions of a conversation must hash to the same key, so an
    A->B packet and a later B->A reply land in the same flow instead of
    two separate ones. Sorting the two endpoints achieves that: whichever
    order the packets actually arrived in, the key is identical.

    Note: this sort order is only for grouping/hashing. It has no relation
    to which endpoint actually initiated the conversation — that's tracked
    separately via the flow's own recorded src_ip/src_port (whoever sent
    the first packet), which is what packets_fwd/bwd below are relative to.
    """
    endpoint_a = (info.src_ip, info.src_port or 0)
    endpoint_b = (info.dst_ip, info.dst_port or 0)
    if endpoint_b < endpoint_a:
        endpoint_a, endpoint_b = endpoint_b, endpoint_a
    return (endpoint_a[0], endpoint_a[1], endpoint_b[0], endpoint_b[1], info.protocol)


def _new_flow(source_file: str, info: PacketInfo) -> dict:
    return {
        "source_file": source_file,
        "src_ip": info.src_ip,
        "dst_ip": info.dst_ip,
        "src_port": info.src_port,
        "dst_port": info.dst_port,
        "protocol": info.protocol,
        "packet_count": 0,
        "byte_count": 0,
        "packets_fwd": 0,
        "packets_bwd": 0,
        "bytes_fwd": 0,
        "bytes_bwd": 0,
        "saw_syn": False,
        "saw_syn_ack": False,
        "close_reason": None,
        "started_at": info.timestamp,
        "ended_at": info.timestamp,
    }


def _apply_packet(flow: dict, info: PacketInfo) -> None:
    """Updates a flow's counters for one packet. Direction (fwd/bwd) is
    relative to the flow's own recorded src_ip/src_port — whoever sent the
    first packet of this flow — not the canonical grouping key, which is
    sorted for hashing purposes and doesn't track who initiated anything.
    """
    flow["packet_count"] += 1
    flow["byte_count"] += info.length
    flow["ended_at"] = info.timestamp

    is_fwd = (info.src_ip, info.src_port) == (flow["src_ip"], flow["src_port"])
    if is_fwd:
        flow["packets_fwd"] += 1
        flow["bytes_fwd"] += info.length
    else:
        flow["packets_bwd"] += 1
        flow["bytes_bwd"] += info.length

    if info.protocol == "TCP" and info.tcp_syn:
        if info.tcp_ack:
            flow["saw_syn_ack"] = True
        else:
            flow["saw_syn"] = True


class FlowAssembler:
    """The same flow-grouping state machine `assemble_flows()` always used,
    pulled out into an object so it can be fed packets incrementally (one at
    a time, indefinitely) instead of only over a finite, fully-in-hand
    iterable. `assemble_flows()` below is now a thin wrapper around this for
    the upload path; Phase 10's live capture is the other caller, feeding
    packets in from a Scapy sniffer thread as they arrive.

    A flow stays open while packets keep arriving within `timeout_seconds`
    of each other. It closes on a TCP RST immediately (unilateral/abortive
    by design), or once BOTH directions have sent a FIN (a real TCP close
    is symmetric — each side independently signals "I'm done sending", so
    closing on the first FIN alone treats half a close as the whole thing
    and fragments a normal connection into extra rows). Otherwise it closes
    implicitly on inactivity timeout or when the packet stream ends — each
    closure records *why* in close_reason, since that's a direct signal of
    abnormal vs. normal behavior downstream. See flow_assembly module
    docstring / PROJECT.md for why flows (not packets) are the unit
    downstream phases build on.
    """

    def __init__(self, source_file: str, timeout_seconds: int = 120, packet_info_extractor=extract_packet_info):
        self.source_file = source_file
        self.timeout_seconds = timeout_seconds
        self.open_flows: dict[tuple, dict] = {}
        self.fin_seen: dict[tuple, set] = {}
        self.skipped = 0
        # Defaults to the PyShark extractor -- assemble_flows() (upload
        # path) never passes this, so it's unaffected. Live capture passes
        # extract_packet_info_scapy explicitly, since a raw Scapy packet
        # and a parsed PyShark packet are different object shapes; see
        # that function's docstring for why this has to be pluggable
        # rather than one function handling both.
        self._extract_packet_info = packet_info_extractor

    def _finalize(self, key, reason: str) -> Optional[dict]:
        flow = self.open_flows.pop(key, None)
        self.fin_seen.pop(key, None)
        if flow is not None:
            flow["close_reason"] = reason
        return flow

    def add_packet(self, packet) -> list[dict]:
        """Processes one packet; returns any flow(s) that just closed as a
        direct result of it (a superseded-by-timeout predecessor, an RST,
        or the second FIN of a pair) -- usually zero, sometimes one, never
        more than two (a timeout-close of the old flow plus an immediate
        RST/FIN-FIN close of the brand new one it started in its place is
        the only way to get two from a single packet).
        """
        completed: list[dict] = []
        try:
            info = self._extract_packet_info(packet)
        except Exception as exc:
            self.skipped += 1
            logger.debug("Skipping packet during flow assembly: %s", exc)
            return completed

        key = _canonical_key(info)
        flow = self.open_flows.get(key)

        if flow is not None and (info.timestamp - flow["ended_at"]).total_seconds() <= self.timeout_seconds:
            _apply_packet(flow, info)
        else:
            if flow is not None:
                closed = self._finalize(key, "timeout")  # previous flow under this key timed out
                if closed is not None:
                    completed.append(closed)
            flow = _new_flow(self.source_file, info)
            _apply_packet(flow, info)
            self.open_flows[key] = flow
            self.fin_seen[key] = set()

        if info.protocol == "TCP":
            if info.tcp_rst:
                closed = self._finalize(key, "rst")
                if closed is not None:
                    completed.append(closed)
            elif info.tcp_fin:
                direction = "a" if (info.src_ip, info.src_port or 0) == (key[0], key[1]) else "b"
                self.fin_seen[key].add(direction)
                if {"a", "b"} <= self.fin_seen[key]:
                    closed = self._finalize(key, "fin_fin")
                    if closed is not None:
                        completed.append(closed)

        return completed

    def sweep_timeouts(self, now: datetime) -> list[dict]:
        """Force-closes any flow that's gone quiet for longer than
        `timeout_seconds`, checked against a wall-clock `now` rather than
        the next packet's arrival.

        `add_packet()`'s timeout check above only fires when a *later*
        packet on the same key actually shows up -- for a finite file
        that's fine, every key's fate is sealed by EOF regardless. A live
        capture has no such guarantee: a key can simply go quiet forever
        while other keys stay busy, and nothing would ever notice it timed
        out. Live capture calls this periodically (e.g. every few seconds)
        against the real clock; the upload path never needs it, since
        `finalize_all("eof")` already accounts for every open flow once
        the file truly ends.
        """
        completed: list[dict] = []
        for key in list(self.open_flows.keys()):
            flow = self.open_flows[key]
            if (now - flow["ended_at"]).total_seconds() > self.timeout_seconds:
                closed = self._finalize(key, "timeout")
                if closed is not None:
                    completed.append(closed)
        return completed

    def finalize_all(self, close_reason: str) -> list[dict]:
        """Force-closes every still-open flow, regardless of timeout.
        `"eof"` for a file that's truly ended; live capture uses `"stopped"`
        when the operator ends the session, since it never actually hits
        end-of-file the way a file capture does.
        """
        completed: list[dict] = []
        for key in list(self.open_flows.keys()):
            closed = self._finalize(key, close_reason)
            if closed is not None:
                completed.append(closed)
        if self.skipped:
            logger.info("Flow assembly skipped %d unparsable/non-IP packets", self.skipped)
            self.skipped = 0
        return completed


def assemble_flows(packets, source_file: str, timeout_seconds: int = 120) -> list[dict]:
    """Groups a finite packet stream (a completed PyShark `FileCapture`)
    into bidirectional flows -- a thin driver over `FlowAssembler`, kept as
    its own function since every existing caller (the PCAP upload path)
    already depends on this exact "hand me an iterable, get a list back"
    shape. See `FlowAssembler` for the actual grouping/closure logic.
    """
    assembler = FlowAssembler(source_file, timeout_seconds)
    completed_flows: list[dict] = []
    for packet in packets:
        completed_flows.extend(assembler.add_packet(packet))
    completed_flows.extend(assembler.finalize_all("eof"))
    return completed_flows
