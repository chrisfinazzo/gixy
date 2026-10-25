"""Exercise source-constrained module models through real parser and audits."""

import io
import logging

import pytest

from gixy.core.config import Config
from gixy.core.context import get_context, purge_context
from gixy.core.manager import Manager
from gixy.core.variable_catalog import VariableCatalog

VTS = (
    "request_counter in_bytes out_bytes 1xx_counter 2xx_counter 3xx_counter "
    "4xx_counter 5xx_counter request_time_counter request_time cache_miss_counter "
    "cache_bypass_counter cache_expired_counter cache_stale_counter "
    "cache_updating_counter cache_revalidated_counter cache_hit_counter "
    "cache_scarce_counter"
).split()
NUMERIC = {
    "zstd_ratio": "09.",
    "gzip_ratio": "09.",
    "brotli_ratio": "09.",
    "srcache_expire": "-09",
    "echo_timer_elapsed": "09.",
    "echo_incr": "09",
    "echo_response_status": "09",
    "geoip_area_code": "-09",
    "geoip_dma_code": "-09",
    "ssl_session_id": "09af",
    "ssl_client_fingerprint": "09af",
    "ssl_session_reused": "r.",
    "ssl_early_data": "1",
    "ssl_client_v_remain": "09",
    "ssl_preread_protocol": "Az09.",
    "jwt_nowtime": "09",
}
NUMERIC.update({"vts_" + name: "09" for name in VTS})
OPAQUE = (
    "echo_request_method echo_client_request_method echo_cacheable_request_uri "
    "echo_request_uri echo_request_body echo_client_request_headers echo_it "
    "geoip_country_code geoip_country_code3 geoip_country_name geoip_org "
    "geoip_city_continent_code geoip_city_country_code geoip_city_country_code3 "
    "geoip_city_country_name geoip_region geoip_region_name geoip_city "
    "geoip_postal_code geoip_latitude geoip_longitude "
    "ssl_protocol ssl_cipher ssl_ciphers ssl_curve ssl_curves ssl_sigalg "
    "ssl_server_name ssl_alpn_protocol ssl_ech_status ssl_ech_outer_server_name "
    "ssl_client_cert ssl_client_raw_cert ssl_client_escaped_cert ssl_client_s_dn "
    "ssl_client_i_dn ssl_client_s_dn_legacy ssl_client_i_dn_legacy "
    "ssl_client_serial ssl_client_verify ssl_client_v_start ssl_client_v_end "
    "ssl_client_sigalg ssl_preread_server_name ssl_preread_alpn_protocols "
    "jwt_claim_backend jwt_header_backend jwt_headers jwt_payload jwt_claims"
).split()


@pytest.fixture(autouse=True)
def clean_context():
    purge_context()
    yield
    purge_context()


def audit(content, plugins=("http_splitting", "ssrf", "missing_resolver"), **kwargs):
    manager = Manager(Config(plugins=list(plugins), **kwargs))
    observed = []
    original = manager.auditor.audit

    def capture(node):
        if node.name == "probe":
            observed.append(
                [get_context().get_var(name.lstrip("$")) for name in node.args]
            )
        original(node)

    manager.auditor.audit = capture
    manager.audit("inline.conf", io.StringIO(content), is_stdin=True)
    counts = {
        plugin.__class__.__name__: len(plugin.issues) for plugin in manager.results
    }
    return manager, observed, counts


@pytest.mark.parametrize("name,alphabet", sorted(NUMERIC.items()))
def test_numeric_alphabets_and_empty(name, alphabet):
    var = VariableCatalog.bundled().variable(name)
    assert var is not None
    assert var.regexp is not None
    assert not var.regexp.must_contain(
        "0"
    )  # absent/empty getter result remains possible
    for char in alphabet:
        assert var.regexp.can_contain(char, skip_literal=False), (name, char)
    for char in "\r\n/$!":
        assert not var.can_contain(char), (name, char)


@pytest.mark.parametrize("name", OPAQUE)
def test_opaque_fixed_models_retain_findings(name):
    var = VariableCatalog.bundled().variable(name)
    assert var is not None
    for char in "\r\n/$!":
        assert var.can_contain(char), (name, char)
    _, _, counts = audit(
        "http { server { proxy_set_header X $%s; proxy_pass http://$%s; } }"
        % (name, name)
    )
    assert counts["http_splitting"] == 2
    assert counts["ssrf"] == 1


@pytest.mark.parametrize(
    "name",
    [
        "geoip_typo",
        "ssl_typo",
        "jwt_type",
        "jwt_now",
        "zstd_typo",
        "vts_typo",
        "srcache_typo",
        "echo_typo",
    ],
)
def test_no_invented_safe_prefixes(name, caplog):
    caplog.set_level(logging.INFO)
    _, observed, _ = audit(
        "http { server { probe $%s; add_header X $%s; } }" % (name, name)
    )
    assert observed == [[None]]
    assert "Can't find variable '%s'" % name in caplog.text


@pytest.mark.parametrize("directive", ["add_header", "proxy_set_header"])
def test_reported_two_locations(directive, caplog):
    caplog.set_level(logging.INFO)
    _, _, counts = audit(
        """events {} http {
      geoip2 /nonexistent.mmdb { $geoip2_data_country_code default=US country iso_code; }
      server { location = / { %s X $geoip2_data_country_code; }
      location /repo-subscribe { %s X $geoip2_data_country_code; } }
    }"""
        % (directive, directive),
        load_default_vars=False,
    )
    assert "Can't find variable 'geoip2_data_country_code'" not in caplog.text
    assert counts["http_splitting"] == 2


@pytest.mark.parametrize(
    "declaration,tainted",
    [
        ("$MiXeD default=US country iso_code;", True),
        ("$MiXeD source=$http_x_ip default=US country iso_code;", True),
        ("$MiXeD default=$uri source=$arg_ip$arg_suffix custom bytes;", True),
        ("$MiXeD metadata build_epoch;", False),
        ("$MiXeD metadata last_check;", False),
        ("$MiXeD metadata last_change;", False),
        ("$MiXeD metadata unsupported;", True),
        ("$MiXeD metadata build_epoch extra;", True),
        ("$MiXeD default=US metadata build_epoch;", True),
        ("$MiXeD;", True),
    ],
)
def test_geoip_alias_models(declaration, tainted):
    _, rows, _ = audit(
        "http { geoip2 missing { %s } server { probe $mixed $MIXED; } }" % declaration
    )
    assert rows[0][0] is not None
    assert rows[0][0] is rows[0][1]
    assert rows[0][0].can_contain("\n") is tainted
    assert rows[0][0].provider.file == "inline.conf"


@pytest.mark.parametrize(
    "first,last,tainted",
    [
        ("metadata build_epoch", "country iso_code", True),
        ("country iso_code", "metadata build_epoch", False),
    ],
)
def test_final_geoip_duplicate_visible_before_between_after(first, last, tainted):
    consumer = "server { probe $value; }"
    _, rows, _ = audit(
        "http { %s geoip2 a { $VALUE %s; } %s geoip2 b { $value %s; } %s }"
        % (consumer, first, consumer, last, consumer)
    )
    assert len(rows) == 3
    assert all(
        row[0] is not None and row[0].can_contain("\n") is tainted for row in rows
    )


@pytest.mark.parametrize(
    "other",
    [
        "map $uri $value { default fixed; }",
        "geo $value { default fixed; }",
        "js_set $value handler;",
        "js_var $value fixed;",
        "perl_set $value handler;",
    ],
)
@pytest.mark.parametrize("reverse", [False, True])
def test_cross_provider_collision_conservative(other, reverse, caplog):
    declaration = "geoip2 db { $value metadata build_epoch; }"
    providers = [declaration, other]
    if reverse:
        providers.reverse()
    _, rows, counts = audit(
        "http { server { probe $value; add_header X $value; } %s server { probe $value; } }"
        % " ".join(providers)
    )
    assert all(row[0].can_contain("\n") for row in rows)
    assert len(rows[0][0].providers) == 2
    assert counts["http_splitting"] == 1
    assert "collision" in caplog.text.lower()


@pytest.mark.parametrize(
    "declaration",
    [
        'set_by_lua $result "return ngx.var.uri";',
        "set_by_lua_file $result /nonexistent.lua;",
        "set_by_lua_block $result { return ngx.var.uri }",
        "js_set $result handler nocache;",
        "js_var $result fixed;",
        'perl_set $result "sub { return $r->uri; }";',
    ],
)
def test_opaque_scripts(declaration):
    _, rows, counts = audit(
        "http { server { %s probe $result; proxy_set_header X $result; proxy_pass http://$result; } }"
        % declaration
    )
    assert rows[0][0] is not None
    assert rows[0][0].can_contain("\n")
    assert rows[0][0].provider.name == declaration.split()[0]
    assert counts["http_splitting"] == 2
    assert counts["ssrf"] == 1
    assert counts["missing_resolver"] == 1


def test_dynamic_map_nested_resolver():
    _, _, counts = audit(
        "http { map $uri $backend { default $http_host; } server { set $nested $backend; proxy_pass http://$nested; } }"
    )
    assert counts["ssrf"] == 1
    assert "missing_resolver" in counts
    assert counts["missing_resolver"] == 1


@pytest.mark.parametrize(
    "name,pattern",
    [
        ("srcache_fetch_status", "BYPASS|MISS|HIT"),
        ("srcache_store_status", "BYPASS|STORE"),
    ],
)
def test_cache_status_enum_defaults(name, pattern):
    var = VariableCatalog.bundled().variable(name)
    assert VariableCatalog.bundled().resolve(name).value == pattern
    for char in "\r\n/$09":
        assert not var.can_contain(char)
    _, _, counts = audit("http { server { proxy_set_header X $%s; } }" % name)
    assert counts == {}


@pytest.mark.parametrize("name", sorted(NUMERIC))
def test_numeric_plugin_splitting_excluded(name):
    _, _, counts = audit("http { server { proxy_set_header X $%s; } }" % name)
    assert counts == {}


def test_geoip_metadata_signed_and_unsigned():
    _, rows, _ = audit(
        "http { geoip2 db { $epoch metadata build_epoch; $checked metadata last_check; $changed metadata last_change; } server { probe $epoch $checked $changed; } }"
    )
    epoch, checked, changed = rows[0]
    assert not epoch.can_contain("-")
    assert checked.can_contain("-") and changed.can_contain("-")
    assert all(var.can_contain("9") and not var.can_contain("\n") for var in rows[0])


@pytest.mark.parametrize(
    "container",
    [
        "http { server { %s } }",
        "http { server { location / { %s } } }",
        "stream { server { %s } }",
        "%s",
    ],
)
def test_geoip_rejects_non_main_context(container):
    _, rows, _ = audit(
        container % "geoip2 db { $local country iso_code; } probe $local;"
    )
    assert rows == [[None]]


def test_http_stream_sibling_and_local_override_isolation():
    _, rows, _ = audit(
        """http {
      geoip2 db { $VALUE country iso_code; }
      server { set $value fixed; probe $VALUE; }
      server { probe $value; }
    } stream { server { probe $value; } } http { server { probe $value; } }"""
    )
    assert rows[0][0].value == "fixed"
    assert rows[1][0].can_contain("\n")
    assert rows[2:] == [[None], [None]]


def test_named_numeric_and_map_capture_keys_remain_distinct():
    from gixy.core.context import Context
    from gixy.core.variable import Variable

    ctx = Context()
    named = Variable("MiXeD", value="global", have_script=False)
    scoped = Variable("MIXED", value="scoped", have_script=False, ctx="~MiXeD")
    numeric = Variable(1, value="capture", have_script=False, ctx="~MiXeD")
    ctx.add_var("MiXeD", named).add_var("MIXED", scoped).add_var("1", numeric)
    assert ctx.get_var("mixed") is named
    assert ctx.get_var("mIxEd", ctx="~MiXeD") is scoped
    assert ctx.get_var("MIXED", ctx="~mixed") is named
    assert ctx.get_var(1, ctx="~MiXeD") is numeric
    assert (
        ctx.get_var("SSL_CLIENT_RAW_CERT") is None
    )  # catalog case behavior is unchanged


def test_catalog_cannot_override_config_declaration(tmp_path):
    policy = tmp_path / "policy"
    policy.mkdir()
    (policy / "model.cfg").write_text("named none\n")
    _, rows, counts = audit(
        "http { geoip2 db { $named default=US country iso_code; } server { probe $named; add_header X $named; } }",
        vars_dirs=[str(policy)],
        load_default_vars=False,
    )
    assert rows[0][0].can_contain("\n")
    assert counts["http_splitting"] == 1


def test_outer_file_include_final_order_and_provenance(tmp_path):
    (tmp_path / "a.conf").write_text("geoip2 db { $value country iso_code; }")
    (tmp_path / "b.conf").write_text("geoip2 db { $value metadata build_epoch; }")
    _, rows, _ = audit(
        "http { server { probe $value; } include %s/a.conf; server { probe $value; } include %s/b.conf; server { probe $value; } }"
        % (tmp_path, tmp_path)
    )
    assert len(rows) == 3
    assert all(not row[0].can_contain("\n") for row in rows)
    assert rows[0][0].provider.file == str(tmp_path / "b.conf")


@pytest.mark.parametrize("enabled", [False, True])
def test_invalid_inner_include_never_resolves_file(tmp_path, enabled, caplog):
    path = tmp_path / "inner.conf"
    path.write_text("$injected metadata build_epoch;")
    _, rows, _ = audit(
        "http { geoip2 db { include %s; $ok country iso_code; } server { probe $ok $injected; } }"
        % path,
        allow_includes=enabled,
    )
    assert rows[0][0].can_contain("\n")
    assert rows[0][1] is None
    assert "invalid include inside geoip2" in caplog.text


def test_dump_outer_and_inner_include_with_files_disabled(caplog):
    content = """# configuration file /etc/nginx/nginx.conf:
http { include /etc/nginx/data.conf; server { probe $value $injected; } }
# configuration file /etc/nginx/data.conf:
geoip2 db { $value country iso_code; include /etc/nginx/inner.conf; }
# configuration file /etc/nginx/inner.conf:
$injected metadata build_epoch;
"""
    _, rows, _ = audit(content, allow_includes=False)
    assert rows[0][0].can_contain("\n") and rows[0][1] is None
    assert rows[0][0].provider.file == "/etc/nginx/data.conf"
    assert "invalid include inside geoip2" in caplog.text


def test_repeated_audits_and_parse_failure_clear_declarations():
    from gixy.core.context import CONTEXTS
    from gixy.core.exceptions import InvalidConfiguration

    manager, _, _ = audit(
        "http { geoip2 db { $value country iso_code; } map $uri $value { default fixed; } }"
    )
    assert manager._declaration_overrides
    with pytest.raises(InvalidConfiguration):
        manager.audit("bad.conf", io.StringIO("set_by_lua $foo;"), is_stdin=True)
    assert manager._declaration_overrides == {}
    assert CONTEXTS == []
    manager.audit("next.conf", io.StringIO("http {}"), is_stdin=True)
    assert get_context().get_var("value") is None


@pytest.mark.parametrize(
    "directive",
    [
        "js_set $bad;",
        "js_set $bad fn invalid;",
        "js_var;",
        "js_var $bad a b;",
        "set_by_lua_file $bad;",
    ],
)
def test_malformed_new_script_forms_do_not_register(directive):
    _, rows, _ = audit("http { server { %s probe $bad; } }" % directive)
    assert rows == [[None]]


@pytest.mark.parametrize(
    "main,scope,valid",
    [
        ("http", "server", True),
        ("http", "location", True),
        ("stream", "server", True),
        ("stream", "location", False),
    ],
)
def test_njs_scopes(main, scope, valid):
    body = "js_var $value fixed; probe $value;"
    body = ("location / { %s }" if scope == "location" else "server { %s }") % body
    if main == "http" and scope == "location":
        body = "server { %s }" % body
    _, rows, _ = audit("%s { %s }" % (main, body))
    assert (rows[0][0] is not None) is valid


def test_raw_lua_header_body_and_content_contract():
    from gixy.parser.raw_parser import RawParser

    nodes = RawParser().parse(
        'set_by_lua_block $value { return ngx.var.uri } content_by_lua_block { ngx.say("ok") }'
    )
    assert nodes[0]["args"] == ["$value"]
    assert nodes[0]["raw"] == ["return ngx.var.uri"]
    assert nodes[1]["args"] == []
    assert nodes[1]["raw"] == ['ngx.say("ok")']


@pytest.mark.parametrize(
    "target,expected",
    [("127.0.0.1", False), ("backend", False), ("$http_host", True), ("$uri", True)],
)
def test_map_literal_ip_upstream_or_dynamic_resolution(target, expected):
    _, _, counts = audit(
        "http { upstream backend { server 127.0.0.1; } map $uri $value { default %s; } server { proxy_pass http://$value; } }"
        % target
    )
    assert (counts.get("missing_resolver", 0) == 1) is expected


def test_dynamic_resolver_configured():
    _, _, counts = audit(
        "http { geoip2 db { $value country iso_code; } server { resolver 127.0.0.1; proxy_pass http://$value; } }"
    )
    assert counts.get("missing_resolver", 0) == 0
    assert counts["ssrf"] == 1


def test_generated_alias_and_declaration_permutations():
    import itertools

    for index, order in enumerate(
        itertools.permutations(["declare", "consumer", "other"])
    ):
        alias = "VaLuE_%s" % index
        statements = {
            "declare": "geoip2 missing { $%s default=$uri source=$arg_ip$arg_suffix custom bytes; }"
            % alias,
            "consumer": "server { probe $%s; proxy_set_header X $%s; }"
            % (alias.lower(), alias.upper()),
            "other": "geoip2 other { $different metadata build_epoch; }",
        }
        _, rows, counts = audit(
            "http { %s }" % " ".join(statements[key] for key in order)
        )
        assert rows[0][0].can_contain("\n")
        assert counts["http_splitting"] == 1


def test_wildcard_include_final_declaration_uses_lexical_order(tmp_path):
    # Deliberately create reverse order: NGINX glob expansion is lexical.
    (tmp_path / "z.conf").write_text("geoip2 db { $value metadata build_epoch; }")
    (tmp_path / "a.conf").write_text("geoip2 db { $value country iso_code; }")
    _, rows, _ = audit(
        "http { server { probe $value; } include %s/*.conf; server { probe $value; } }"
        % tmp_path
    )
    assert len(rows) == 2
    assert all(not row[0].can_contain("\n") for row in rows)
    assert rows[0][0].provider.file == str(tmp_path / "z.conf")


def test_actual_stream_main_declaration():
    _, rows, counts = audit(
        "stream { geoip2 db { $value custom bytes; } server { probe $value; proxy_pass $value; } } http { server { probe $value; } }"
    )
    assert rows[0][0].can_contain("\n")
    assert rows[1] == [None]
    assert counts["ssrf"] == 1
    assert counts["missing_resolver"] == 1


def test_geoip_collision_ignores_source_names_captures_and_local_override(caplog):
    _, rows, _ = audit(
        """http {
      geoip2 db { $value country iso_code; }
      map $value $other { default fixed; ~(?<value>[0-9]+) $value; }
      server { set $value fixed; probe $value; }
      server { probe $value; }
    }"""
    )
    assert rows[0][0].value == "fixed"
    assert rows[1][0].can_contain("\n")
    assert "collision" not in caplog.text.lower()


def test_malformed_lua_block_normalized_header_does_not_gain_provider(caplog):
    from gixy.directives.block import Root
    from gixy.parser.nginx_parser import NginxParser

    root = Root()
    NginxParser().parse_block(
        [
            {
                "kind": "block",
                "name": "set_by_lua_block",
                "args": [],
                "children": [],
                "line": 1,
            }
        ],
        root,
    )
    assert root.children == []
    assert "malformed set_by_lua_block" in caplog.text
