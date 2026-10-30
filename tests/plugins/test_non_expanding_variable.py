import os
import tempfile

import pytest

from gixy.core.config import Config
from gixy.core.manager import Manager


def _audit_issues(config_text):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as f:
        f.write(config_text)
        path = f.name

    try:
        config = Config(plugins=["non_expanding_variable"])
        with Manager(config=config) as manager:
            with open(path) as fdata:
                manager.audit(path, fdata)
            return [issue for plugin in manager.results for issue in plugin.issues]
    finally:
        os.unlink(path)


def test_geo_rate_limit_key_reports_shared_bucket():
    issues = _audit_issues(
        """
        http {
            geo $limit_key {
                default $binary_remote_addr;
                127.0.0.1 "";
            }
            limit_req_zone $limit_key zone=dynamic:10m rate=5r/s;
            limit_conn_zone ${limit_key} zone=conn:10m;
        }
        """
    )

    assert len(issues) == 1
    assert issues[0].severity == "HIGH"
    assert "ONE limit bucket" in issues[0].reason
    assert "limit_req_zone, limit_conn_zone" in issues[0].reason
    assert "map $limit $limit_key" in issues[0].reason


def test_geo_rate_limit_key_through_map_chain():
    issues = _audit_issues(
        """
        http {
            geo $limit_key {
                default $binary_remote_addr;
            }
            map $request_method $post_limit_key {
                default "";
                POST $limit_key;
            }
            map $http_user_agent $search_key {
                default "${post_limit_key}";
            }
            limit_req_zone $search_key zone=search:10m rate=60r/m;
        }
        """
    )

    assert len(issues) == 1
    assert "feeds the key of limit_req_zone" in issues[0].reason


def test_map_keyed_by_geo_variable_does_not_inherit_literal():
    issues = _audit_issues(
        """
        http {
            geo $limit_key {
                default $binary_remote_addr;
            }
            map $limit_key $classified {
                default $remote_addr;
            }
            limit_req_zone $classified zone=one:10m rate=1r/s;
        }
        """
    )

    assert len(issues) == 1
    assert "limit bucket" not in issues[0].reason


def test_geo_without_rate_limit_omits_bucket_warning():
    issues = _audit_issues(
        """
        http {
            geo $client {
                default $remote_addr;
            }
            limit_req_zone $client_id zone=other:10m rate=5r/s;
        }
        """
    )

    assert len(issues) == 1
    assert "limit bucket" not in issues[0].reason


@pytest.mark.parametrize(
    "value",
    ["literal", '""', '"$5"', '"price: $"'],
)
def test_geo_values_without_variable_names_are_ignored(value):
    issues = _audit_issues(
        f"""
        http {{
            geo $g {{
                default {value};
            }}
        }}
        """
    )

    assert issues == []


@pytest.mark.parametrize(
    "directive",
    [
        "error_log /var/log/nginx/$host.log",
        "client_body_temp_path /tmp/$host",
        "fastcgi_cache_path /var/cache/${server_name} keys_zone=f:1m",
    ],
)
def test_literal_path_directives_report_low(directive):
    issues = _audit_issues(f"http {{ {directive}; }}")

    assert len(issues) == 1
    assert issues[0].severity == "LOW"


def test_variable_in_later_cache_path_argument_is_ignored():
    issues = _audit_issues(
        "http { proxy_cache_path /var/cache/nginx keys_zone=$x:1m; }"
    )

    assert issues == []


def test_env_placeholder_in_geo_reported_once_as_template():
    issues = _audit_issues(
        """
        http {
            geo $limit_key {
                default ${CLIENT_KEY};
            }
        }
        """
    )

    assert len(issues) == 1
    assert issues[0].severity == "MEDIUM"
    assert "envsubst" in issues[0].reason


@pytest.mark.parametrize(
    "config",
    [
        "http { server { set $BACKEND 127.0.0.1; location / { proxy_pass http://$BACKEND; } } }",
        "http { server { location / { add_header X-Host $HOST; return 200; } } }",
        "http { server { location / { content_by_lua_block { ngx.say('${X}') } } } }",
        'http { server { location / { CheckRule "$SQL >= 8" BLOCK; } } }',
        "http { server { location / { proxy_pass http://$UPSTREAM_FROM_INCLUDE; } } }",
        "http { server { server_name $hostname; } }",
    ],
)
def test_declared_or_builtin_upper_case_names_are_not_placeholders(config):
    assert _audit_issues(config) == []


def test_auth_request_with_variable_is_high():
    issues = _audit_issues(
        "http { server { location / { auth_request /auth/$host; } } }"
    )

    assert len(issues) == 1
    assert issues[0].severity == "HIGH"


@pytest.mark.parametrize(
    "pattern,names",
    [
        (r"^/$p/x", ["$p"]),
        (r"^/${p}x", ["${p}"]),
        (r"\.php$", []),
        (r"^/(a|b)$", []),
        (r"^/a[$]b", []),
        (r"^/a[]$b]c", []),
        (r"^/a[^]$b]c", []),
        (r"^/price\$usd", []),
        (r"^/a\\$p", ["$p"]),
    ],
)
def test_regex_dollar_tokens(pattern, names):
    from gixy.plugins.non_expanding_variable import _regex_dollar_tokens

    assert _regex_dollar_tokens(pattern) == names


def test_server_name_checks_entries_after_regex():
    issues = _audit_issues(
        r"http { server { server_name ~^a\.example$ $tenant.example; } }"
    )

    assert len(issues) == 1
    assert "$tenant.example" in issues[0].reason
