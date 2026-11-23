from typing import Protocol

from .models import Alert, AlertKind, RoutingSnapshot, Severity, WatchedPrefix


class RoutingCheck(Protocol):
    def evaluate(self, watched: WatchedPrefix, snapshot: RoutingSnapshot) -> Alert | None: ...


def _format_asns(asns: frozenset[int]) -> str:
    return ", ".join(f"AS{asn}" for asn in sorted(asns))


class NotAnnouncedCheck:
    def evaluate(self, watched: WatchedPrefix, snapshot: RoutingSnapshot) -> Alert | None:
        if snapshot.origins and snapshot.peers_seeing > 0:
            return None
        return Alert(
            prefix=watched.prefix,
            kind=AlertKind.NOT_ANNOUNCED,
            severity=Severity.CRITICAL,
            message=f"{watched.prefix} is not seen by any RIS peer",
        )


class VisibilityCheck:
    def evaluate(self, watched: WatchedPrefix, snapshot: RoutingSnapshot) -> Alert | None:
        if snapshot.peers_seeing == 0 or snapshot.visibility >= watched.min_visibility:
            return None
        return Alert(
            prefix=watched.prefix,
            kind=AlertKind.LOW_VISIBILITY,
            severity=Severity.WARNING,
            message=(
                f"{watched.prefix} is seen by {snapshot.peers_seeing}/{snapshot.total_peers} peers "
                f"({snapshot.visibility:.0%}, expected at least {watched.min_visibility:.0%})"
            ),
        )


class UnexpectedOriginCheck:
    def evaluate(self, watched: WatchedPrefix, snapshot: RoutingSnapshot) -> Alert | None:
        unexpected = snapshot.origins - watched.expected_origins
        if not unexpected:
            return None
        return Alert(
            prefix=watched.prefix,
            kind=AlertKind.UNEXPECTED_ORIGIN,
            severity=Severity.CRITICAL,
            message=f"{watched.prefix} is originated by {_format_asns(unexpected)}, possible hijack",
        )


class RpkiInvalidCheck:
    def evaluate(self, watched: WatchedPrefix, snapshot: RoutingSnapshot) -> Alert | None:
        if not snapshot.rpki_invalid_origins:
            return None
        return Alert(
            prefix=watched.prefix,
            kind=AlertKind.RPKI_INVALID,
            severity=Severity.CRITICAL,
            message=f"{watched.prefix} from {_format_asns(snapshot.rpki_invalid_origins)} is RPKI invalid",
        )


DEFAULT_CHECKS: tuple[RoutingCheck, ...] = (
    NotAnnouncedCheck(),
    VisibilityCheck(),
    UnexpectedOriginCheck(),
    RpkiInvalidCheck(),
)
