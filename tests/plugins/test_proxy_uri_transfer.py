"""Prove proxy URI safety only across the local rewrite phase."""

import io

import pytest

from gixy.core.config import Config
from gixy.core.manager import Manager


def _splitting_count(location_body, modifier="=", path="/synthetic-token/"):
    source = (
        "events {}\nhttp { server { listen 80;\n"
        "location " + modifier + " " + path + " {\n" + location_body + "\n}\n} }\n"
    )
    with Manager(config=Config(plugins=["http_splitting"])) as manager:
        manager.audit(
            "example.invalid.conf", io.BytesIO(source.encode()), is_stdin=True
        )
        return sum(
            issue.directives[0].name == "proxy_pass"
            for plugin in manager.auditor.plugins
            for issue in plugin.issues
        )


@pytest.mark.parametrize(
    "body",
    [
        "rewrite ^ $request_uri;\nrewrite ^/synthetic-token/ / break;\n"
        "return 400;\nproxy_pass http://example.invalid$uri;",
        "proxy_pass http://example.invalid$uri;\nrewrite ^ /safe break;",
        "rewrite ^ $request_uri break;\nproxy_pass http://example.invalid$document_uri;",
    ],
)
def test_all_paths_reaching_proxy_have_safe_uri(body):
    assert _splitting_count(body) == 0


@pytest.mark.parametrize(
    "body",
    [
        "proxy_pass http://example.invalid$uri;",
        "rewrite ^ $uri break;\nreturn 400;\nproxy_pass http://example.invalid$uri;",
        "rewrite ^/synthetic-token/ /safe break;\nproxy_pass http://example.invalid$uri;",
        "if ($arg_x) { rewrite ^ /safe break; }\nproxy_pass http://example.invalid$uri;",
        "rewrite ^ /safe;\nrewrite ^ $uri$arg_x break;\nproxy_pass http://example.invalid$uri;",
        "rewrite ^ /safe last;\nproxy_pass http://example.invalid$uri;",
        'rewrite ^ /safe break;\nrewrite_by_lua "ngx.req.set_uri(ngx.var.arg_x)";\n'
        "proxy_pass http://example.invalid$uri;",
        'rewrite ^ /safe break;\naccess_by_lua "ngx.req.set_uri(ngx.var.arg_x)";\n'
        "proxy_pass http://example.invalid$uri;",
        'rewrite ^ "/safe\r" break;\nproxy_pass http://example.invalid$uri;',
    ],
)
def test_unproved_or_tainted_path_keeps_warning(body):
    assert _splitting_count(body) == 1


def test_rewrite_in_sibling_location_does_not_prove_this_proxy_safe():
    source = b"""events {}\nhttp { server { listen 80;
location = /safe { rewrite ^ /safe break; }
location = /unsafe { proxy_pass http://example.invalid$uri; }
} }
"""
    with Manager(config=Config(plugins=["http_splitting"])) as manager:
        manager.audit("example.invalid.conf", io.BytesIO(source), is_stdin=True)
        assert sum(len(plugin.issues) for plugin in manager.auditor.plugins) == 1
