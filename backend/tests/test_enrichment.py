from app.services.enrichment.ip_classification import external_ip_for_flow, is_external


def test_private_ranges_are_not_external():
    assert is_external("192.168.0.107") is False
    assert is_external("10.0.0.5") is False
    assert is_external("172.16.0.1") is False
    assert is_external("127.0.0.1") is False
    assert is_external("169.254.1.1") is False


def test_public_ips_are_external():
    assert is_external("8.8.8.8") is True
    assert is_external("1.1.1.1") is True


def test_unparseable_input_is_not_external():
    assert is_external("not-an-ip") is False
    assert is_external("") is False


def test_multicast_and_broadcast_are_not_external():
    """LAN discovery chatter (mDNS/SSDP/broadcast) isn't an enrichable IOC
    even though it isn't a private unicast address either.
    """
    assert is_external("224.0.0.251") is False  # mDNS
    assert is_external("239.255.255.250") is False  # SSDP
    assert is_external("255.255.255.255") is False  # limited broadcast


def test_external_ip_for_flow_finds_nothing_when_both_sides_are_private():
    """This project's own test data: an internal host scanning another
    internal host has no external indicator to enrich at all.
    """
    flow = {"src_ip": "192.168.0.107", "dst_ip": "192.168.0.1"}
    assert external_ip_for_flow(flow) is None


def test_external_ip_for_flow_prefers_dst_ip():
    flow = {"src_ip": "192.168.0.107", "dst_ip": "8.8.8.8"}
    assert external_ip_for_flow(flow) == "8.8.8.8"


def test_external_ip_for_flow_falls_back_to_src_ip():
    flow = {"src_ip": "8.8.8.8", "dst_ip": "192.168.0.1"}
    assert external_ip_for_flow(flow) == "8.8.8.8"
