import pytest

from bgp_prefix_monitor.ripestat import RipeStatClient, RoutingDataError


def routing_status(origins, seeing, total, family="v4"):
    other = "v6" if family == "v4" else "v4"
    return {
        "status": "ok",
        "data": {
            "origins": [{"origin": asn} for asn in origins],
            "visibility": {
                family: {"ris_peers_seeing": seeing, "total_ris_peers": total},
                other: {"ris_peers_seeing": 0, "total_ris_peers": 0},
            },
        },
    }


def rpki(status):
    return {"status": "ok", "data": {"status": status}}


class FakeApi:
    def __init__(self, routing, rpki_by_origin):
        self._routing = routing
        self._rpki_by_origin = rpki_by_origin
        self.requested_urls = []

    def __call__(self, url):
        self.requested_urls.append(url)
        if "/routing-status/" in url:
            return self._routing
        origin = int(url.split("resource=")[1].split("&")[0])
        return rpki(self._rpki_by_origin[origin])


def test_builds_snapshot_from_routing_status_and_rpki():
    api = FakeApi(routing_status([3333, 64666], seeing=300, total=320), {3333: "valid", 64666: "invalid"})

    snapshot = RipeStatClient(fetch=api).snapshot("193.0.0.0/21")

    assert snapshot.origins == {3333, 64666}
    assert (snapshot.peers_seeing, snapshot.total_peers) == (300, 320)
    assert snapshot.rpki_invalid_origins == {64666}


def test_uses_ipv6_visibility_for_ipv6_prefixes():
    api = FakeApi(routing_status([3333], seeing=250, total=260, family="v6"), {3333: "valid"})

    snapshot = RipeStatClient(fetch=api).snapshot("2001:67c:2e8::/48")

    assert snapshot.peers_seeing == 250


def test_identifies_itself_to_ripestat():
    api = FakeApi(routing_status([3333], 1, 1), {3333: "valid"})

    RipeStatClient(fetch=api, source_app="my-noc").snapshot("193.0.0.0/21")

    assert all("sourceapp=my-noc" in url for url in api.requested_urls)


def test_error_status_raises_routing_data_error():
    client = RipeStatClient(fetch=lambda url: {"status": "error", "messages": [["error", "bad"]]})

    with pytest.raises(RoutingDataError):
        client.snapshot("193.0.0.0/21")
