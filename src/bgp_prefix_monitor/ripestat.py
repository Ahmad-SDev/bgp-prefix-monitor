import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Any, Protocol

from .models import RoutingSnapshot

JsonFetcher = Callable[[str], dict[str, Any]]


class RoutingDataError(Exception):
    pass


class RoutingDataSource(Protocol):
    def snapshot(self, prefix: str) -> RoutingSnapshot: ...


def fetch_json(url: str, timeout_seconds: float = 20) -> dict[str, Any]:
    request = urllib.request.Request(url, headers={"User-Agent": "bgp-prefix-monitor"})
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            return json.load(response)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
        raise RoutingDataError(f"request to {url} failed: {error}") from error


class RipeStatClient:
    BASE_URL = "https://stat.ripe.net/data"

    def __init__(self, fetch: JsonFetcher = fetch_json, source_app: str = "bgp-prefix-monitor") -> None:
        self._fetch = fetch
        self._source_app = source_app

    def snapshot(self, prefix: str) -> RoutingSnapshot:
        status = self._data("routing-status", resource=prefix)
        origins = frozenset(entry["origin"] for entry in status.get("origins", []))
        address_family = "v6" if ":" in prefix else "v4"
        visibility = status["visibility"][address_family]

        return RoutingSnapshot(
            prefix=prefix,
            origins=origins,
            peers_seeing=visibility["ris_peers_seeing"],
            total_peers=visibility["total_ris_peers"],
            rpki_invalid_origins=frozenset(
                origin for origin in origins if self._rpki_status(origin, prefix) == "invalid"
            ),
        )

    def _rpki_status(self, origin: int, prefix: str) -> str:
        return self._data("rpki-validation", resource=str(origin), prefix=prefix).get("status", "unknown")

    def _data(self, endpoint: str, **params: str) -> dict[str, Any]:
        query = urllib.parse.urlencode({**params, "sourceapp": self._source_app})
        payload = self._fetch(f"{self.BASE_URL}/{endpoint}/data.json?{query}")
        if payload.get("status") != "ok" or "data" not in payload:
            raise RoutingDataError(f"RIPEstat {endpoint} returned status {payload.get('status')!r}")
        return payload["data"]
