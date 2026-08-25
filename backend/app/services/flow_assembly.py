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


def assemble_flows(packets, source_file: str, timeout_seconds: int = 120) -> list[dict]:
    """Groups a packet stream into bidirectional flows.

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
    open_flows: dict[tuple, dict] = {}
    fin_seen: dict[tuple, set] = {}
    completed_flows: list[dict] = []
    skipped = 0

    def finalize(key, reason: str):
        flow = open_flows.pop(key, None)
        fin_seen.pop(key, None)
        if flow is not None:
            flow["close_reason"] = reason
            completed_flows.append(flow)

    for packet in packets:
        try:
            info = extract_packet_info(packet)
        except Exception as exc:
            skipped += 1
            logger.debug("Skipping packet during flow assembly: %s", exc)
            continue

        key = _canonical_key(info)
        flow = open_flows.get(key)

        if flow is not None and (info.timestamp - flow["ended_at"]).total_seconds() <= timeout_seconds:
            _apply_packet(flow, info)
        else:
            if flow is not None:
                finalize(key, "timeout")  # previous flow under this key timed out
            flow = _new_flow(source_file, info)
            _apply_packet(flow, info)
            open_flows[key] = flow
            fin_seen[key] = set()

        if info.protocol == "TCP":
            if info.tcp_rst:
                finalize(key, "rst")
            elif info.tcp_fin:
                direction = "a" if (info.src_ip, info.src_port or 0) == (key[0], key[1]) else "b"
                fin_seen[key].add(direction)
                if {"a", "b"} <= fin_seen[key]:
                    finalize(key, "fin_fin")

    for key in list(open_flows.keys()):
        finalize(key, "eof")

    if skipped:
        logger.info("Flow assembly skipped %d unparsable/non-IP packets", skipped)

    return completed_flows
