"""Tests for graceful handling of malformed nginx configurations."""

import io

import pytest

from gixy.core.exceptions import InvalidConfiguration
from gixy.directives.block import LocationBlock, MapBlock, IfBlock
from gixy.directives.directive import (
    AddHeaderDirective,
    SetDirective,
    RewriteDirective,
)
from gixy.parser.nginx_parser import NginxParser


def _parse(config):
    return NginxParser(cwd="", allow_includes=False).parse_string(config)


class TestMalformedDirectives:
    """Directives with an argument count nginx itself rejects are skipped.

    nginx would refuse to load such a config, so the directive can never
    influence runtime behavior; gixy drops it with a warning instead of
    crashing or hard-failing (nixpkgs' writeNginxConfig relies on this).
    """

    def test_add_header_missing_value(self):
        """add_header requires 2-3 args."""
        tree = _parse("add_header X-Test;")
        assert tree.children == []

    def test_add_header_no_args(self):
        """add_header with no args is skipped."""
        tree = _parse("add_header;")
        assert tree.children == []

    def test_set_missing_value(self):
        """set requires exactly 2 args."""
        tree = _parse("set $foo;")
        assert tree.children == []

    def test_set_no_args(self):
        """set with no args is skipped."""
        tree = _parse("set;")
        assert tree.children == []

    def test_auth_request_set_missing_value(self):
        """auth_request_set requires exactly 2 args."""
        tree = _parse("auth_request_set $foo;")
        assert tree.children == []

    def test_perl_set_missing_value(self):
        """perl_set requires exactly 2 args."""
        tree = _parse("perl_set $foo;")
        assert tree.children == []

    def test_set_by_lua_missing_value(self):
        """set_by_lua requires 2+ args."""
        with pytest.raises(
            InvalidConfiguration, match='Failed to parse "set_by_lua" directive'
        ):
            _parse("set_by_lua $foo;")

    def test_rewrite_missing_replacement(self):
        """rewrite requires 2-3 args."""
        tree = _parse("rewrite ^/old;")
        assert tree.children == []

    def test_rewrite_no_args(self):
        """rewrite with no args is skipped."""
        tree = _parse("rewrite;")
        assert tree.children == []


class TestMalformedBlocks:
    """Blocks with an argument count nginx itself rejects are skipped."""

    def test_location_no_args(self):
        """location requires 1-2 args."""
        tree = _parse("location {}")
        assert tree.children == []

    def test_map_missing_destination(self):
        """map requires exactly 2 args - Jim's original bug case."""
        tree = _parse("map $uri {}")
        assert tree.children == []

    def test_map_no_args(self):
        """map with no args is skipped."""
        tree = _parse("map {}")
        assert tree.children == []

    def test_include_no_args(self):
        """include requires exactly 1 arg."""
        with pytest.raises(
            InvalidConfiguration, match='Failed to parse "include" directive'
        ):
            _parse("include;")

    def test_if_invalid_args(self):
        """if with 4+ args should fail."""
        with pytest.raises(InvalidConfiguration, match='Unknown "if" definition'):
            _parse("if ($a = b c d) {}")


class TestValidEdgeCases:
    """Test that valid edge cases still work correctly."""

    def test_location_with_modifier(self):
        """location ~ /regex should work."""
        tree = _parse("location ~ ^/api { }")
        location = tree.children[0]
        assert isinstance(location, LocationBlock)
        assert location.modifier == "~"
        assert location.path == "^/api"

    def test_location_without_modifier(self):
        """location /path should work."""
        tree = _parse("location /api { }")
        location = tree.children[0]
        assert isinstance(location, LocationBlock)
        assert location.modifier is None
        assert location.path == "/api"

    def test_location_exact_match(self):
        """location = /exact should work."""
        tree = _parse("location = /exact { }")
        location = tree.children[0]
        assert isinstance(location, LocationBlock)
        assert location.modifier == "="
        assert location.path == "/exact"

    def test_rewrite_with_flag(self):
        """rewrite with flag should work."""
        tree = _parse("rewrite ^/old /new permanent;")
        rewrite = tree.children[0]
        assert isinstance(rewrite, RewriteDirective)
        assert rewrite.pattern == "^/old"
        assert rewrite.replace == "/new"
        assert rewrite.flag == "permanent"

    def test_rewrite_without_flag(self):
        """rewrite without flag should work."""
        tree = _parse("rewrite ^/old /new;")
        rewrite = tree.children[0]
        assert isinstance(rewrite, RewriteDirective)
        assert rewrite.pattern == "^/old"
        assert rewrite.replace == "/new"
        assert rewrite.flag is None

    def test_add_header_with_always(self):
        """add_header with always flag should work."""
        tree = _parse("add_header X-Test value always;")
        add_header = tree.children[0]
        assert isinstance(add_header, AddHeaderDirective)
        assert add_header.header == "x-test"
        assert add_header.value == "value"
        assert add_header.always is True

    def test_add_header_without_always(self):
        """add_header without always flag should work."""
        tree = _parse("add_header X-Test value;")
        add_header = tree.children[0]
        assert isinstance(add_header, AddHeaderDirective)
        assert add_header.header == "x-test"
        assert add_header.value == "value"
        assert add_header.always is False

    def test_set_directive(self):
        """set with 2 args should work."""
        tree = _parse("set $foo bar;")
        set_dir = tree.children[0]
        assert isinstance(set_dir, SetDirective)
        assert set_dir.variable == "foo"
        assert set_dir.value == "bar"

    def test_map_block(self):
        """map with 2 args should work."""
        tree = _parse("map $uri $mapped { default 0; }")
        map_block = tree.children[0]
        assert isinstance(map_block, MapBlock)
        assert map_block.source == "$uri"
        assert map_block.variable == "mapped"

    def test_map_empty_source_valid(self):
        """Jim's valid pattern: map "" $myvar should work."""
        tree = _parse('map "" $myvar { default ""; }')
        map_block = tree.children[0]
        assert isinstance(map_block, MapBlock)
        assert map_block.source == ""
        assert map_block.variable == "myvar"

    def test_if_single_variable(self):
        """if ($var) should work."""
        tree = _parse("if ($slow) { }")
        if_block = tree.children[0]
        assert isinstance(if_block, IfBlock)
        assert if_block.variable == "$slow"

    def test_if_file_check(self):
        """if (-f $file) should work."""
        tree = _parse("if (-f $request_filename) { }")
        if_block = tree.children[0]
        assert isinstance(if_block, IfBlock)
        assert if_block.operand == "-f"
        assert if_block.value == "$request_filename"

    def test_if_comparison(self):
        """if ($var = value) should work."""
        tree = _parse("if ($request_method = POST) { }")
        if_block = tree.children[0]
        assert isinstance(if_block, IfBlock)
        assert if_block.variable == "$request_method"
        assert if_block.operand == "="
        assert if_block.value == "POST"

    def test_if_regex(self):
        """if ($var ~ regex) should work."""
        tree = _parse("if ($request_uri ~ ^/admin) { }")
        if_block = tree.children[0]
        assert isinstance(if_block, IfBlock)
        assert if_block.variable == "$request_uri"
        assert if_block.operand == "~"
        assert if_block.value == "^/admin"


class TestNginxRejectedDirectives:
    """Regression tests for the nixpkgs writeNginxConfig scenario.

    NixOS builds intentionally-broken configs (nixosTests.nginx) through
    "gixy config" and expects gixy to survive them: nginx -t reports the
    breakage at runtime. See https://github.com/NixOS/nixpkgs/pull/568041
    where gixy 0.2.54 crashed with IndexError on a bare "proxy_pass;".
    """

    NIXOS_CONFIG = """
        http {
            server_tokens off;
            server {
                listen 0.0.0.0:80 default_server;
                server_name !@$$(#*%;
                location ~@#*$*!) {
                    proxy_pass;;;;
                }
            }
        }
    """

    def test_bare_proxy_pass_is_skipped(self):
        tree = _parse(self.NIXOS_CONFIG)
        location = tree.children[0].children[-1].children[-1]
        assert location.name == "location"
        assert "proxy_pass" not in [child.name for child in location.children]

    def test_full_audit_does_not_crash_and_reports_nothing(self):
        from gixy.core.config import Config
        from gixy.core.manager import Manager

        with Manager(config=Config(allow_includes=False)) as yoda:
            yoda.audit("<test>", io.BytesIO(self.NIXOS_CONFIG.encode()))
            assert sum(yoda.stats.values()) == 0

    def test_block_where_simple_directive_expected_is_skipped(self):
        tree = _parse("proxy_pass { }")
        assert tree.children == []
