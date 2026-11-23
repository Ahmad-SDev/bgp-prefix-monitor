from bgp_prefix_monitor.models import AlertKind, RoutingSnapshot, WatchedPrefix
from bgp_prefix_monitor.monitor import PrefixMonitor
from bgp_prefix_monitor.ripestat import RoutingDataError

PREFIX = "203.0.113.0/24"
WATCHED = WatchedPrefix(prefix=PREFIX, expected_origins=frozenset({64500}))

HEALTHY = RoutingSnapshot(prefix=PREFIX, origins=frozenset({64500}), peers_seeing=100, total_peers=100)
HIJACKED = RoutingSnapshot(prefix=PREFIX, origins=frozenset({64500, 64666}), peers_seeing=100, total_peers=100)


class ScriptedSource:
    def __init__(self, *responses):
        self._responses = list(responses)

    def snapshot(self, prefix):
        response = self._responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class RecordingNotifier:
    def __init__(self):
        self.raised = []
        self.resolved = []

    def alerts_raised(self, alerts):
        self.raised.append([alert.kind for alert in alerts])

    def alerts_resolved(self, keys):
        self.resolved.append([kind for _, kind in keys])


def test_healthy_prefix_sends_nothing():
    notifier = RecordingNotifier()
    PrefixMonitor(ScriptedSource(HEALTHY), notifier).run_once([WATCHED])

    assert notifier.raised == []
    assert notifier.resolved == []


def test_alert_is_sent_once_while_it_stays_active():
    notifier = RecordingNotifier()
    monitor = PrefixMonitor(ScriptedSource(HIJACKED, HIJACKED), notifier)

    monitor.run_once([WATCHED])
    monitor.run_once([WATCHED])

    assert notifier.raised == [[AlertKind.UNEXPECTED_ORIGIN]]


def test_recovery_is_reported():
    notifier = RecordingNotifier()
    monitor = PrefixMonitor(ScriptedSource(HIJACKED, HEALTHY), notifier)

    monitor.run_once([WATCHED])
    monitor.run_once([WATCHED])

    assert notifier.resolved == [[AlertKind.UNEXPECTED_ORIGIN]]


def test_failed_lookup_neither_resolves_nor_repeats_active_alerts():
    notifier = RecordingNotifier()
    monitor = PrefixMonitor(ScriptedSource(HIJACKED, RoutingDataError("timeout"), HIJACKED), notifier)

    for _ in range(3):
        monitor.run_once([WATCHED])

    assert notifier.raised == [[AlertKind.UNEXPECTED_ORIGIN]]
    assert notifier.resolved == []
