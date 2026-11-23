import logging
from collections.abc import Iterable, Sequence

from .checks import DEFAULT_CHECKS, RoutingCheck
from .models import Alert, AlertKey, WatchedPrefix
from .notifiers import Notifier
from .ripestat import RoutingDataError, RoutingDataSource

log = logging.getLogger(__name__)


class PrefixMonitor:
    """Runs routing checks and only notifies when an alert starts or clears."""

    def __init__(
        self,
        source: RoutingDataSource,
        notifier: Notifier,
        checks: Sequence[RoutingCheck] = DEFAULT_CHECKS,
    ) -> None:
        self._source = source
        self._notifier = notifier
        self._checks = checks
        self._active: set[AlertKey] = set()

    def run_once(self, watched_prefixes: Iterable[WatchedPrefix]) -> list[Alert]:
        current_alerts: list[Alert] = []
        unreachable_prefixes: set[str] = set()

        for watched in watched_prefixes:
            try:
                current_alerts.extend(self._evaluate(watched))
            except RoutingDataError as error:
                log.warning("skipping %s this round: %s", watched.prefix, error)
                unreachable_prefixes.add(watched.prefix)

        self._publish_changes(current_alerts, unreachable_prefixes)
        return current_alerts

    def _evaluate(self, watched: WatchedPrefix) -> list[Alert]:
        snapshot = self._source.snapshot(watched.prefix)
        results = (check.evaluate(watched, snapshot) for check in self._checks)
        return [alert for alert in results if alert is not None]

    def _publish_changes(self, current_alerts: list[Alert], unreachable_prefixes: set[str]) -> None:
        # Alerts for prefixes we could not query keep their last known state.
        carried_over = {key for key in self._active if key[0] in unreachable_prefixes}
        current_keys = {alert.key for alert in current_alerts} | carried_over

        raised = [alert for alert in current_alerts if alert.key not in self._active]
        resolved = sorted(self._active - current_keys)
        self._active = current_keys

        if raised:
            self._notifier.alerts_raised(raised)
        if resolved:
            self._notifier.alerts_resolved(resolved)
