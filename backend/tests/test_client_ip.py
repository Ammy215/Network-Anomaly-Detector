"""client_ip() -- which address the audit log records.

Every audit row in production recorded a Render load-balancer address
(10.x) instead of the user's. The fix was chosen from a one-shot capture of
real production headers; the header values below mirror that capture
(documentation-range IPs stand in for the real client address).
"""
import pytest
from starlette.requests import Request

from app.services.auth import client_ip

REAL = "198.51.100.20"        # the client, as Cloudflare saw it
CF_EDGE = "172.71.202.166"    # a Cloudflare edge, as it appeared in XFF
RENDER_LB = "10.30.148.4"     # the socket peer for proxied traffic
FORGED = "203.0.113.7"


def make_request(peer, headers=None):
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
        "client": (peer, 12345) if peer is not None else None,
    }
    return Request(scope)


def test_proxied_request_records_cf_connecting_ip_not_the_load_balancer():
    req = make_request(RENDER_LB, {
        "CF-Connecting-IP": REAL,
        "X-Forwarded-For": f"{REAL}, {CF_EDGE}, {RENDER_LB}",
    })
    assert client_ip(req) == REAL


def test_forged_leftmost_xff_is_never_consulted():
    # The exact shape production delivered when a client sent its own XFF:
    # the forged value survives at the left of the chain.
    req = make_request(RENDER_LB, {
        "CF-Connecting-IP": REAL,
        "X-Forwarded-For": f"{FORGED},{REAL}, {CF_EDGE}, {RENDER_LB}",
    })
    assert client_ip(req) == REAL


def test_cloudflare_edge_is_never_returned():
    # What a 10.0.0.0/8-only FORWARDED_ALLOW_IPS would have produced.
    req = make_request(RENDER_LB, {
        "CF-Connecting-IP": REAL,
        "X-Forwarded-For": f"{REAL}, {CF_EDGE}, {RENDER_LB}",
    })
    assert client_ip(req) != CF_EDGE


@pytest.mark.parametrize("peer", ["127.0.0.1", "192.168.0.10", "8.8.8.8", "::1"])
def test_header_ignored_when_peer_is_not_render_internal(peer):
    # A direct connection -- local dev, or anything that didn't come through
    # Cloudflare -- controls every header it sends, so none are believed.
    req = make_request(peer, {"CF-Connecting-IP": FORGED, "X-Forwarded-For": FORGED})
    assert client_ip(req) == peer


@pytest.mark.parametrize("value", [
    f"{FORGED}, {REAL}",          # a list smuggled into a single-value header
    "not-an-ip",
    "<script>alert(1)</script>",
    "999.1.1.1",
    "",
    "   ",
])
def test_malformed_header_falls_back_to_peer(value):
    req = make_request(RENDER_LB, {"CF-Connecting-IP": value})
    assert client_ip(req) == RENDER_LB


def test_render_health_checker_without_headers_records_its_peer():
    # Render's internal health checker hits the container directly every 5s
    # with no proxy headers at all.
    assert client_ip(make_request("10.236.25.95")) == "10.236.25.95"


def test_ipv6_client_is_accepted_and_normalised():
    req = make_request(RENDER_LB, {"CF-Connecting-IP": " 2001:DB8::0001 "})
    assert client_ip(req) == "2001:db8::1"


def test_non_ip_peer_is_returned_unchanged():
    # Starlette's TestClient reports its peer as the literal "testclient".
    req = make_request("testclient", {"CF-Connecting-IP": FORGED})
    assert client_ip(req) == "testclient"


def test_no_client_returns_none():
    assert client_ip(make_request(None)) is None
