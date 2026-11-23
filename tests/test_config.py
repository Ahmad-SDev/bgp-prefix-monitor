from pathlib import Path

import pytest

from bgp_prefix_monitor.config import ConfigError, load_config, parse_config


def test_example_config_loads():
    config = load_config(Path(__file__).parent.parent / "config.example.toml")

    assert [watched.prefix for watched in config.prefixes] == ["193.0.0.0/21", "2001:67c:2e8::/48"]
    assert config.prefixes[1].min_visibility == 0.9


def test_prefix_is_normalised():
    config = parse_config({"prefix": [{"prefix": "2001:DB8:0::/32", "origins": [64500]}]})

    assert config.prefixes[0].prefix == "2001:db8::/32"


@pytest.mark.parametrize(
    "raw",
    [
        {},
        {"prefix": [{"prefix": "not-a-prefix", "origins": [64500]}]},
        {"prefix": [{"prefix": "203.0.113.0/24"}]},
        {"prefix": [{"prefix": "203.0.113.0/24", "origins": [64500], "min_visibility": 1.5}]},
        {"interval_seconds": 5, "prefix": [{"prefix": "203.0.113.0/24", "origins": [64500]}]},
    ],
)
def test_invalid_config_is_rejected(raw):
    with pytest.raises(ConfigError):
        parse_config(raw)
