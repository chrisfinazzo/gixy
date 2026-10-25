"""Map capture bounds follow the entire source expression and owning entry."""

import io

import pytest

from gixy.core.config import Config
from gixy.core.manager import Manager


def _splitting_count(map_source, entries, output="301 $redirect_uri"):
    source = (
        "events {}\nhttp {\n"
        "map " + map_source + " $redirect_uri {\n" + entries + "\n}\n"
        "server { listen 80; return " + output + "; }\n}\n"
    )
    with Manager(config=Config(plugins=["http_splitting"])) as manager:
        manager.audit(
            "example.invalid.conf", io.BytesIO(source.encode()), is_stdin=True
        )
        return sum(len(plugin.issues) for plugin in manager.auditor.plugins)


@pytest.mark.parametrize(
    "map_source,entry,expected",
    [
        (
            '"$request_method:$request_uri"',
            '"~^GET:/platform/current/(.*)$" /platform/stable/$1;',
            0,
        ),
        (
            '"$request_method:$uri"',
            '"~^GET:/platform/current/(.*)$" /platform/stable/$1;',
            1,
        ),
        ("$request_uri", "~^/current/(?<tail>.*)$ /stable/$tail;", 0),
        ("$uri", "~^/current/(?<tail>.*)$ /stable/$tail;", 1),
        ("$unknown_source", "~^/current/(.*)$ /stable/$1;", 1),
        ('"$request_uri\r"', '"~^/p([\\s\\S])$" $1;', 1),
    ],
)
def test_capture_inherits_whole_source_alphabet(map_source, entry, expected):
    assert _splitting_count(map_source, 'default "";\n' + entry) == expected


def test_safe_capture_does_not_hide_unsafe_default():
    entries = 'default $uri;\n"~^GET:/current/(.*)$" /stable/$1;'
    assert _splitting_count('"$request_method:$request_uri"', entries) == 1


def test_identical_patterns_in_distinct_maps_keep_source_scope():
    source = b"""events {}\nhttp {
map $request_uri $safe { default ""; ~^/current/(.*)$ /stable/$1; }
map $uri $unsafe { default ""; ~^/current/(.*)$ /stable/$1; }
server { listen 80; return 301 $safe; return 301 $unsafe; }
}
"""
    with Manager(config=Config(plugins=["http_splitting"])) as manager:
        manager.audit("example.invalid.conf", io.BytesIO(source), is_stdin=True)
        assert sum(len(plugin.issues) for plugin in manager.auditor.plugins) == 1


@pytest.mark.parametrize(
    "source,expected",
    [
        (
            "map $request_uri $gate { default 0; ~^/platform/current/ 1; }\n"
            'map "$gate:$request_uri" $redirect_uri { default ""; '
            '"~^1:/platform/current/(.*)$" /platform/stable/$1; }',
            0,
        ),
        (
            'map $request_uri $stage { default ""; '
            "~^/platform/current/(.*)$ /platform/stable/$1; }\n"
            'map $stage $redirect_uri { default ""; '
            "~^/platform/stable/(.*)$ /ready/$1; }",
            0,
        ),
        (
            'map $second $first { default ""; ~^(.*)$ $1; }\n'
            'map $first $second { default ""; ~^(.*)$ $1; }\n'
            'map $first $redirect_uri { default ""; ~^(.*)$ $1; }',
            1,
        ),
    ],
)
def test_nested_boolean_and_cycle_sources(source, expected):
    config = (
        "events {}\nhttp {\n" + source + "\nserver { return 301 $redirect_uri; }\n}"
    )
    with Manager(config=Config(plugins=["http_splitting"])) as manager:
        manager.audit(
            "example.invalid.conf", io.BytesIO(config.encode()), is_stdin=True
        )
        assert sum(len(plugin.issues) for plugin in manager.auditor.plugins) == expected


@pytest.mark.parametrize("source,expected", [("$request_uri", 0), ("$uri", 1)])
def test_capture_from_included_map_entry(tmp_path, source, expected):
    entries = tmp_path / "entries.conf"
    entries.write_text('default "";\n~^/current/(.*)$ /stable/$1;\n')
    config = tmp_path / "nginx.conf"
    config.write_text(
        "events {}\nhttp { map "
        + source
        + " $redirect_uri { include "
        + str(entries)
        + "; } server { return 301 $redirect_uri; } }"
    )
    with Manager(config=Config(plugins=["http_splitting"])) as manager:
        with config.open("rb") as stream:
            manager.audit(str(config), stream)
        assert sum(len(plugin.issues) for plugin in manager.auditor.plugins) == expected


@pytest.mark.parametrize(
    "producer",
    [
        'server { set $literal "x\r"; return 301 $redirect_uri; }',
        'map $request_uri $literal { default "x\r"; }\n'
        "server { return 301 $redirect_uri; }",
    ],
)
def test_literal_in_source_variable_is_part_of_capture_alphabet(producer):
    source = (
        "events {}\nhttp {\n"
        'map $literal $redirect_uri { default ""; "~^([\\s\\S]*)$" $1; }\n'
        + producer
        + "\n}"
    )
    with Manager(config=Config(plugins=["http_splitting"])) as manager:
        manager.audit(
            "example.invalid.conf", io.BytesIO(source.encode()), is_stdin=True
        )
        assert sum(len(plugin.issues) for plugin in manager.auditor.plugins) == 1
