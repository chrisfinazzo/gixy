"""Explicit nginx version shared by the QUIC and CVE checks."""

import io
import json
import subprocess
import sys

import pytest

from gixy.core.config import Config
from gixy.core.manager import Manager


CONFIG = b"""worker_processes 2;
quic_bpf on;
events {}
http {
    server {
        listen 443 quic reuseport;
        location / { return 200 ok; }
    }
}
"""


def _quic_count(config):
    with Manager(config=config) as manager:
        manager.audit("example.invalid.conf", io.BytesIO(CONFIG), is_stdin=True)
        return sum(
            len(plugin.issues)
            for plugin in manager.auditor.plugins
            if plugin.name == "quic_bpf_reuseport"
        )


@pytest.mark.parametrize(
    "version,expected",
    [
        (None, 1),
        ("invalid", 1),
        ("1.².7", 1),
        ("1.31.6", 1),
        ("1.31.7", 0),
        ("1.31.8", 0),
        ("1.30.9", 1),
    ],
)
def test_explicit_upstream_version_boundary(version, expected):
    assert _quic_count(Config(nginx_version=version)) == expected


def test_legacy_version_is_shared_fallback():
    config = Config()
    config.set_for("nginx_cves", {"version": "1.31.7"})
    assert _quic_count(config) == 0


def test_global_version_precedes_legacy_even_when_invalid():
    config = Config(nginx_version="invalid")
    config.set_for("nginx_cves", {"version": "1.31.7"})
    assert _quic_count(config) == 1


@pytest.mark.parametrize(
    "flags,expected",
    [
        (["--nginx-version", "1.31.7"], 0),
        (["--nginx-cves-version", "1.31.7"], 0),
        (["--nginx-version", "invalid", "--nginx-cves-version", "1.31.7"], 1),
    ],
)
def test_server_startup_shares_only_explicit_version(flags, expected):
    request = (
        json.dumps({"id": "sample", "method": "analyze", "content": CONFIG.decode()})
        + "\n"
    )
    process = subprocess.run(  # noqa: UP022 - capture_output requires Python 3.7.
        [sys.executable, "-m", "gixy.cli.main", "--server"] + flags,
        input=request,
        universal_newlines=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        check=True,
    )
    responses = [json.loads(line) for line in process.stdout.splitlines()]
    assert responses[0]["ready"] is True
    assert (
        sum(issue["plugin"] == "quic_bpf_reuseport" for issue in responses[1]["issues"])
        == expected
    )
