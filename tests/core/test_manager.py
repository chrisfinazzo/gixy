"""Tests for cross-scope variable visibility in Manager._audit_recursive.

See issue #100: variables defined via `set` (and similar) directives must be
visible to nested blocks regardless of source order, matching nginx's
parse-time variable registration semantics.
"""

import io
import logging

import pytest

from gixy.core.context import purge_context
from gixy.core.manager import Manager


def _audit_string(config_text, caplog=None):
    """Run a Manager audit on an in-memory config string.

    Args:
        config_text: Raw nginx config text.
        caplog: Optional pytest caplog fixture; when provided, INFO records
            from `gixy.core.variable` are captured.

    Returns:
        The Manager instance after audit (for inspecting results).
    """
    if caplog is not None:
        caplog.set_level(logging.INFO, logger="gixy.core.variable")
    manager = Manager()
    manager.audit("inline.conf", io.StringIO(config_text), is_stdin=True)
    return manager


def _missing_var_records(caplog):
    """Return INFO log records about missing variables."""
    return [
        r
        for r in caplog.records
        if r.name == "gixy.core.variable"
        and r.levelno == logging.INFO
        and "Can't find variable" in r.getMessage()
    ]


@pytest.fixture(autouse=True)
def _reset_context():
    yield
    purge_context()


def test_set_after_location_in_server_scope_is_visible(caplog):
    config = """
http {
    server {
        location @error {
            root $Root_Path/server-error-pages/_site;
        }
        set $Root_Path /usr/share/nginx/html;
        root $Root_Path;
    }
}
"""
    _audit_string(config, caplog)
    assert _missing_var_records(caplog) == []


def test_set_after_location_referenced_via_proxy_header(caplog):
    config = """
http {
    server {
        location / {
            proxy_set_header X-Tag $Tag;
        }
        set $Tag "value-after-location";
    }
}
"""
    _audit_string(config, caplog)
    assert _missing_var_records(caplog) == []


def test_set_inside_if_block_visible_in_sibling_location(caplog):
    config = """
http {
    server {
        location / {
            return 200 $Mode;
        }
        if ($host = "example.com") {
            set $Mode "prod";
        }
    }
}
"""
    _audit_string(config, caplog)
    assert _missing_var_records(caplog) == []


def test_set_in_one_location_does_not_leak_to_sibling(caplog):
    config = """
http {
    server {
        location /a {
            set $LocalOnly "secret";
        }
        location /b {
            return 200 $LocalOnly;
        }
    }
}
"""
    _audit_string(config, caplog)
    missing = _missing_var_records(caplog)
    assert any(
        "LocalOnly" in r.getMessage() for r in missing
    ), "sibling locations must not share `set` vars"


def test_root_provides_document_root_in_nested_location_when_root_after(caplog):
    config = """
http {
    server {
        location /a {
            return 200 $document_root/page.html;
        }
        root /var/www/site;
    }
}
"""
    _audit_string(config, caplog)
    assert _missing_var_records(caplog) == []


def test_chained_set_with_forward_ref_does_not_log(caplog):
    """`$X = $Y/sub` where `set $Y` follows in source order should not warn."""
    config = """
http {
    server {
        set $X "$Y/sub";
        set $Y "/base";
        location / {
            return 200 $X;
        }
    }
}
"""
    _audit_string(config, caplog)
    assert _missing_var_records(caplog) == []


def test_named_capture_group_in_if_resolves(caplog):
    """Named regex capture in `if` must be visible to `set` inside the if.

    Regression for issue #111: gixy logged "Can't find variable 'path'" for
    the named group, because server-scope prepopulate descended into the
    IfBlock and evaluated the inner `set` before the if's capture groups
    were registered.
    """
    config = r"""
http {
    server {
        server_name example.com;
        if ($http_referer ~ "^https?://example\.com(?P<path>.*)") {
            set $normalised_referrer $path;
        }
    }
}
"""
    _audit_string(config, caplog)
    assert _missing_var_records(caplog) == []


def test_numbered_capture_group_in_if_resolves(caplog):
    """Numbered backreference in `if` must also resolve cleanly (sanity check)."""
    config = r"""
http {
    server {
        server_name example.com;
        if ($request_uri ~ "^/old/(.*)$") {
            set $new_uri $1;
        }
    }
}
"""
    _audit_string(config, caplog)
    assert _missing_var_records(caplog) == []
