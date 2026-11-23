import json
import urllib.request
from collections.abc import Sequence
from typing import Protocol

from .models import Alert, AlertKey, Severity

_SEVERITY_ICON = {Severity.WARNING: "⚠️", Severity.CRITICAL: "🚨"}


class Notifier(Protocol):
    def alerts_raised(self, alerts: Sequence[Alert]) -> None: ...

    def alerts_resolved(self, keys: Sequence[AlertKey]) -> None: ...


def describe_raised(alert: Alert) -> str:
    return f"{_SEVERITY_ICON[alert.severity]} [{alert.severity.value}] {alert.message}"


def describe_resolved(key: AlertKey) -> str:
    prefix, kind = key
    return f"✅ [resolved] {prefix}: {kind.value.replace('_', ' ')}"


class ConsoleNotifier:
    def alerts_raised(self, alerts: Sequence[Alert]) -> None:
        for alert in alerts:
            print(describe_raised(alert), flush=True)

    def alerts_resolved(self, keys: Sequence[AlertKey]) -> None:
        for key in keys:
            print(describe_resolved(key), flush=True)


class DiscordWebhookNotifier:
    MAX_MESSAGE_LENGTH = 2000

    def __init__(self, webhook_url: str, timeout_seconds: float = 10) -> None:
        self._webhook_url = webhook_url
        self._timeout_seconds = timeout_seconds

    def alerts_raised(self, alerts: Sequence[Alert]) -> None:
        self._post([describe_raised(alert) for alert in alerts])

    def alerts_resolved(self, keys: Sequence[AlertKey]) -> None:
        self._post([describe_resolved(key) for key in keys])

    def _post(self, lines: list[str]) -> None:
        content = "\n".join(lines)[: self.MAX_MESSAGE_LENGTH]
        request = urllib.request.Request(
            self._webhook_url,
            data=json.dumps({"content": content}).encode(),
            headers={"Content-Type": "application/json", "User-Agent": "bgp-prefix-monitor"},
        )
        urllib.request.urlopen(request, timeout=self._timeout_seconds).close()


class CompositeNotifier:
    def __init__(self, notifiers: Sequence[Notifier]) -> None:
        self._notifiers = notifiers

    def alerts_raised(self, alerts: Sequence[Alert]) -> None:
        for notifier in self._notifiers:
            notifier.alerts_raised(alerts)

    def alerts_resolved(self, keys: Sequence[AlertKey]) -> None:
        for notifier in self._notifiers:
            notifier.alerts_resolved(keys)
