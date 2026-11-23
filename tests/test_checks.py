import pytest

from bgp_prefix_monitor.checks import (
    NotAnnouncedCheck,
    RpkiInvalidCheck,
    UnexpectedOriginCheck,
    VisibilityCheck,
)
from bgp_prefix_monitor.models import AlertKind, RoutingSnapshot, Severity, WatchedPrefix

WATCHED = WatchedPrefix(prefix="203.0.113.0/24", expected_origins=frozenset({64500}), min_visibility=0.9)


def snapshot(origins=frozenset({64500}), peers_seeing=100, total_peers=100, rpki_invalid=frozenset()):
    return RoutingSnapshot(
        prefix=WATCHED.prefix,
        origins=origins,
        peers_seeing=peers_seeing,
        total_peers=total_peers,
        rpki_invalid_origins=rpki_invalid,
    )


@pytest.mark.parametrize(
    "check",
    [NotAnnouncedCheck(), VisibilityCheck(), UnexpectedOriginCheck(), RpkiInvalidCheck()],
)
def test_healthy_prefix_raises_nothing(check):
    assert check.evaluate(WATCHED, snapshot()) is None


def test_withdrawn_prefix_is_critical():
    alert = NotAnnouncedCheck().evaluate(WATCHED, snapshot(origins=frozenset(), peers_seeing=0))

    assert alert.kind is AlertKind.NOT_ANNOUNCED
    assert alert.severity is Severity.CRITICAL


def test_visibility_below_threshold_warns():
    alert = VisibilityCheck().evaluate(WATCHED, snapshot(peers_seeing=80))

    assert alert.kind is AlertKind.LOW_VISIBILITY
    assert "80/100" in alert.message


def test_visibility_check_stays_quiet_when_prefix_is_withdrawn():
    assert VisibilityCheck().evaluate(WATCHED, snapshot(origins=frozenset(), peers_seeing=0)) is None


def test_foreign_origin_is_reported_as_possible_hijack():
    alert = UnexpectedOriginCheck().evaluate(WATCHED, snapshot(origins=frozenset({64500, 64666})))

    assert alert.kind is AlertKind.UNEXPECTED_ORIGIN
    assert "AS64666" in alert.message
    assert "AS64500" not in alert.message


def test_rpki_invalid_origin_is_critical():
    alert = RpkiInvalidCheck().evaluate(WATCHED, snapshot(rpki_invalid=frozenset({64500})))

    assert alert.kind is AlertKind.RPKI_INVALID
    assert alert.severity is Severity.CRITICAL
