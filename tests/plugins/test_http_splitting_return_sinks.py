"""Distinguish return response bodies from redirect Location headers."""

import io

import pytest

from gixy.core.config import Config
from gixy.core.context import purge_context
from gixy.core.manager import Manager


@pytest.mark.parametrize(
    "arguments,expected",
    [
        ("200 $uri", 0),
        ("400 $uri", 0),
        ("403 $uri", 0),
        ("500 $uri", 0),
        ("201 $uri", 0),
        ("304 $uri", 0),
        ("301 http://example.com$uri", 1),
        ("302 $uri", 1),
        ("303 $uri", 1),
        ("307 $uri", 1),
        ("308 $uri", 1),
        ("http://example.com$uri", 1),
        ("https://example.com$uri", 1),
        ("$scheme://example.com$uri", 1),
        ("301 https://example.com$request_uri", 0),
        ("0301 $uri", 1),
        ("0302 $uri", 1),
        ("0303 $uri", 1),
        ("0307 $uri", 1),
        ("0308 $uri", 1),
        ("00301 $uri", 1),
        ("00302 $uri", 1),
        ("00303 $uri", 1),
        ("00307 $uri", 1),
        ("00308 $uri", 1),
        ("00200 $uri", 0),
        ("00304 $uri", 0),
        ("0302x $uri", 0),
        ("-0302 $uri", 0),
    ],
)
def test_only_redirect_return_values_are_splitting_sinks(arguments, expected):
    try:
        manager = Manager(Config(plugins=["http_splitting"]))
        manager.audit(
            "inline.conf",
            io.StringIO("http { server { return %s; } }" % arguments),
            is_stdin=True,
        )
        assert sum(len(plugin.issues) for plugin in manager.results) == expected
    finally:
        purge_context()
