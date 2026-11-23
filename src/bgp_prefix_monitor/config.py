import ipaddress
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import WatchedPrefix


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class MonitorConfig:
    prefixes: tuple[WatchedPrefix, ...]
    interval_seconds: int = 300
    discord_webhook: str | None = None


def load_config(path: Path) -> MonitorConfig:
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ConfigError(f"cannot read {path}: {error}") from error
    return parse_config(raw)


def parse_config(raw: dict[str, Any]) -> MonitorConfig:
    entries = raw.get("prefix", [])
    if not entries:
        raise ConfigError("add at least one [[prefix]] block")

    interval_seconds = int(raw.get("interval_seconds", 300))
    if interval_seconds < 60:
        raise ConfigError("interval_seconds must be at least 60 (RIPEstat data refreshes slowly)")

    return MonitorConfig(
        prefixes=tuple(_parse_prefix(entry) for entry in entries),
        interval_seconds=interval_seconds,
        discord_webhook=raw.get("discord_webhook") or None,
    )


def _parse_prefix(entry: dict[str, Any]) -> WatchedPrefix:
    try:
        prefix = str(ipaddress.ip_network(entry["prefix"]))
    except (KeyError, ValueError) as error:
        raise ConfigError(f"invalid prefix entry {entry}: {error}") from error

    origins = entry.get("origins")
    if not origins:
        raise ConfigError(f"{prefix}: list the ASNs allowed to originate it in 'origins'")

    min_visibility = float(entry.get("min_visibility", 0.9))
    if not 0 < min_visibility <= 1:
        raise ConfigError(f"{prefix}: min_visibility must be between 0 and 1")

    return WatchedPrefix(
        prefix=prefix,
        expected_origins=frozenset(int(asn) for asn in origins),
        min_visibility=min_visibility,
    )
