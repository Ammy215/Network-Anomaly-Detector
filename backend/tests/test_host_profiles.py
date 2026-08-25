from datetime import datetime, timezone

from app.services.host_profiles import compute_host_profiles


def ts(s: str) -> str:
    return f"2026-01-01T{s}+00:00"


# Hand-counted scenario:
#   A (10.0.0.5)      -- local host, initiates flows 1-3, is also contacted in flow 4
#   B (93.184.216.34) -- contacted twice by A on the same port (443)
#   C (8.8.8.8)        -- contacted once by A (DNS)
#   D (203.0.113.9)    -- contacts A once, on a new port (8080)
FLOWS = [
    {  # 1: A -> B, port 443
        "src_ip": "10.0.0.5", "dst_ip": "93.184.216.34", "dst_port": 443,
        "byte_count": 1000, "started_at": ts("00:00:00"), "ended_at": ts("00:00:01"),
    },
    {  # 2: A -> B again, SAME port 443 -- must not double-count the port
        "src_ip": "10.0.0.5", "dst_ip": "93.184.216.34", "dst_port": 443,
        "byte_count": 500, "started_at": ts("00:00:05"), "ended_at": ts("00:00:06"),
    },
    {  # 3: A -> C, port 53 (DNS)
        "src_ip": "10.0.0.5", "dst_ip": "8.8.8.8", "dst_port": 53,
        "byte_count": 200, "started_at": ts("00:00:02"), "ended_at": ts("00:00:02"),
    },
    {  # 4: D -> A, port 8080 (A is contacted, not initiating)
        "src_ip": "203.0.113.9", "dst_ip": "10.0.0.5", "dst_port": 8080,
        "byte_count": 300, "started_at": ts("00:00:10"), "ended_at": ts("00:00:11"),
    },
]


def _find(profiles, ip):
    return next(p for p in profiles if p["ip"] == ip)


def test_host_a_aggregates_across_all_four_flows_it_participates_in():
    profiles = compute_host_profiles(FLOWS)
    a = _find(profiles, "10.0.0.5")

    assert a["flow_count"] == 4  # src in 1,2,3 + dst in 4
    assert a["total_bytes"] == 1000 + 500 + 200 + 300
    # ports contacted AS INITIATOR only: 443 (deduped across flows 1&2) + 53 = 2
    assert a["unique_dst_ports_contacted"] == 2
    assert a["first_seen"] == ts("00:00:00")
    assert a["last_seen"] == ts("00:00:11")  # max across all 4, including flow 4 where A is dst


def test_host_b_is_pure_destination_never_initiates():
    profiles = compute_host_profiles(FLOWS)
    b = _find(profiles, "93.184.216.34")

    assert b["flow_count"] == 2
    assert b["total_bytes"] == 1000 + 500
    assert b["unique_dst_ports_contacted"] == 0  # never the src_ip of any flow
    assert b["first_seen"] == ts("00:00:00")
    assert b["last_seen"] == ts("00:00:06")


def test_host_d_initiates_a_single_new_port():
    profiles = compute_host_profiles(FLOWS)
    d = _find(profiles, "203.0.113.9")

    assert d["flow_count"] == 1
    assert d["total_bytes"] == 300
    assert d["unique_dst_ports_contacted"] == 1  # port 8080


def test_repeated_port_does_not_double_count():
    profiles = compute_host_profiles(FLOWS)
    a = _find(profiles, "10.0.0.5")
    # flows 1 and 2 both target port 443 on B -- must count as one unique port
    assert a["unique_dst_ports_contacted"] == 2  # {443, 53}, not 3
