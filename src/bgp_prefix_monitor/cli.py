import argparse
import logging
import sys
import time
from pathlib import Path

from .config import ConfigError, MonitorConfig, load_config
from .monitor import PrefixMonitor
from .notifiers import CompositeNotifier, ConsoleNotifier, DiscordWebhookNotifier, Notifier
from .ripestat import RipeStatClient


def build_notifier(config: MonitorConfig) -> Notifier:
    notifiers: list[Notifier] = [ConsoleNotifier()]
    if config.discord_webhook:
        notifiers.append(DiscordWebhookNotifier(config.discord_webhook))
    return CompositeNotifier(notifiers)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="bgp-prefix-monitor",
        description="Watch your prefixes for hijacks, withdrawals and RPKI-invalid announcements.",
    )
    parser.add_argument("config", type=Path, help="path to the TOML config file")
    parser.add_argument("--once", action="store_true", help="run a single check and exit")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    try:
        config = load_config(args.config)
    except ConfigError as error:
        print(f"config error: {error}", file=sys.stderr)
        return 2

    monitor = PrefixMonitor(source=RipeStatClient(), notifier=build_notifier(config))

    if args.once:
        alerts = monitor.run_once(config.prefixes)
        if not alerts:
            print(f"all {len(config.prefixes)} prefixes look healthy")
        return 1 if alerts else 0

    logging.info("watching %d prefixes every %ds", len(config.prefixes), config.interval_seconds)
    try:
        while True:
            monitor.run_once(config.prefixes)
            time.sleep(config.interval_seconds)
    except KeyboardInterrupt:
        return 0
