# bgp-prefix-monitor

Watches your BGP prefixes through [RIPEstat](https://stat.ripe.net/) and tells you when something is wrong:

- **Not announced**: no RIS peer sees the prefix anymore
- **Low visibility**: fewer peers than you expect are seeing it
- **Unexpected origin**: an ASN you didn't list is announcing it (possible hijack)
- **RPKI invalid**: an origin is announcing it in a way your ROAs don't allow

You only get a message when an alert starts or clears, not on every check. If RIPEstat is unreachable for a round, active alerts stay as they are instead of flapping.

No dependencies outside the Python standard library (3.11+).

## Usage

```bash
pip install git+https://github.com/Ahmad-SDev/bgp-prefix-monitor
cp config.example.toml config.toml   # list your prefixes and origin ASNs
bgp-prefix-monitor config.toml --once
bgp-prefix-monitor config.toml       # keeps running, checks every interval_seconds
```

`--once` exits with code 1 if anything is wrong, so it also works from cron or a Nagios-style check.

```toml
interval_seconds = 300
discord_webhook = "https://discord.com/api/webhooks/..."

[[prefix]]
prefix = "203.0.113.0/24"
origins = [64500]
min_visibility = 0.9
```

Example output:

```
🚨 [critical] 203.0.113.0/24 is originated by AS64666, possible hijack
⚠️ [warning] 203.0.113.0/24 is seen by 251/322 peers (78%, expected at least 90%)
✅ [resolved] 203.0.113.0/24: unexpected origin
```

## Adding a check

Checks are small classes with an `evaluate(watched, snapshot)` method that returns an `Alert` or `None`. Pass your own list to `PrefixMonitor(checks=...)`, no changes to the monitor needed. The same goes for notifiers (`alerts_raised` / `alerts_resolved`) if you want Slack, Telegram or email.

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT
