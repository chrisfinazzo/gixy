import json
import os
from os import path

import pytest

from gixy.core.config import Config
from gixy.core.manager import Manager as Gixy
from gixy.core.plugins_manager import PluginsManager
from gixy.formatters import BaseFormatter

from ..utils import *


def generate_config_test_cases():
    tested_plugins = set()
    tested_fp_plugins = set()

    config_cases = []
    config_fp_cases = []

    conf_dir = path.join(path.dirname(__file__), "simply")
    for plugin in os.listdir(conf_dir):
        if plugin in (".", ".."):
            continue

        plugin_path = path.join(conf_dir, plugin)
        if not path.isdir(plugin_path):
            continue

        config = {}
        if path.exists(path.join(plugin_path, "config.json")):
            with open(path.join(plugin_path, "config.json")) as file:
                config = json.loads(file.read())

        for test_case in os.listdir(plugin_path):
            if not test_case.endswith(".conf"):
                continue

            config_path = path.join(plugin_path, test_case)
            if not test_case.endswith("_fp.conf"):
                # Not False Positive test
                tested_plugins.add(plugin)
                config_cases.append((plugin, config_path, config))
            else:
                tested_fp_plugins.add(plugin)
                config_fp_cases.append((plugin, config_path, config))

    manager = PluginsManager()
    for plugin in manager.plugins:
        if getattr(plugin, "skip_test", False):
            continue
        plugin = plugin.name
        assert (
            plugin in tested_plugins
        ), f"Plugin {plugin!r} should have at least one simple test config"
        assert (
            plugin in tested_fp_plugins
        ), f"Plugin {plugin!r} should have at least one simple test config with false positive"

    return config_cases, config_fp_cases


all_config_cases, all_config_fp_cases = generate_config_test_cases()


def _read_header_directive(config_path, prefix):
    """Read a `# <prefix>: {...}` JSON directive from the first few lines.

    Scans the leading non-blank lines so `# Options:` and `# Expected:`
    can appear in any order at the top of a fixture.
    """
    with open(config_path) as f:
        for _ in range(3):
            line = f.readline()
            if not line:
                break
            if line.startswith(prefix):
                return json.loads(line[len(prefix) :])
    return None


def parse_plugin_options(config_path):
    return _read_header_directive(config_path, "# Options: ")


def parse_expected_directive(config_path):
    """Read the optional `# Expected: {...}` header from a fixture.

    Currently supports the ``issues`` key (int) — overrides the default
    "exactly one issue per non-FP fixture" assertion. Returns an empty
    dict when absent so callers can use ``.get("issues", 1)``.
    """
    return _read_header_directive(config_path, "# Expected: ") or {}


def yoda_provider(plugin, plugin_options=None):
    # Allow tests to opt-in to following includes via special option
    allow_includes = False
    cleaned_plugin_options = None
    if plugin_options:
        cleaned_plugin_options = dict(plugin_options)
        if "__allow_includes" in cleaned_plugin_options:
            allow_includes = bool(cleaned_plugin_options.pop("__allow_includes"))

    config = Config(allow_includes=allow_includes, plugins=[plugin])
    if cleaned_plugin_options:
        config.set_for(plugin, cleaned_plugin_options)
    return Gixy(config=config)


@pytest.mark.parametrize("plugin,config_path,test_config", all_config_cases)
def test_configuration(plugin, config_path, test_config):
    plugin_options = parse_plugin_options(config_path)
    expected = parse_expected_directive(config_path)
    expected_count = expected.get("issues", 1)
    with yoda_provider(plugin, plugin_options) as yoda:
        yoda.audit(config_path, open(config_path))
        formatter = BaseFormatter()
        formatter.feed(config_path, yoda)
        _, results = formatter.reports.popitem()

        assert (
            len(results) == expected_count
        ), f"Expected {expected_count} report(s), got {len(results)}"
        result = results[0]

        if "severity" in test_config:
            if not hasattr(test_config["severity"], "__iter__"):
                assert result["severity"] == test_config["severity"]
            else:
                assert result["severity"] in test_config["severity"]
        assert result["plugin"] == plugin
        assert result["summary"]
        assert result["description"]
        assert result["config"]
        assert result["help_url"].startswith(
            "https://"
        ), "help_url must starts with https://. It'is URL!"


@pytest.mark.parametrize("plugin,config_path,test_config", all_config_fp_cases)
def test_configuration_fp(plugin, config_path, test_config):
    plugin_options = parse_plugin_options(config_path)
    with yoda_provider(plugin, plugin_options) as yoda:
        yoda.audit(config_path, open(config_path))
        assert (
            len(list(yoda.results)) == 0
        ), "False positive configuration must not trigger any plugins"
