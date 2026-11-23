from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    WARNING = "warning"
    CRITICAL = "critical"


class AlertKind(str, Enum):
    NOT_ANNOUNCED = "not_announced"
    LOW_VISIBILITY = "low_visibility"
    UNEXPECTED_ORIGIN = "unexpected_origin"
    RPKI_INVALID = "rpki_invalid"


@dataclass(frozen=True)
class WatchedPrefix:
    prefix: str
    expected_origins: frozenset[int]
    min_visibility: float = 0.9


@dataclass(frozen=True)
class RoutingSnapshot:
    prefix: str
    origins: frozenset[int]
    peers_seeing: int
    total_peers: int
    rpki_invalid_origins: frozenset[int] = frozenset()

    @property
    def visibility(self) -> float:
        if self.total_peers == 0:
            return 0.0
        return self.peers_seeing / self.total_peers


AlertKey = tuple[str, AlertKind]


@dataclass(frozen=True)
class Alert:
    prefix: str
    kind: AlertKind
    severity: Severity
    message: str

    @property
    def key(self) -> AlertKey:
        return self.prefix, self.kind
