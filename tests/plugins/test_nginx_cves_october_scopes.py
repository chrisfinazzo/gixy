"""Exercise October CVE prerequisites through the real parser and auditor."""

import pytest

from gixy.core.config import Config
from gixy.core.manager import Manager


@pytest.fixture
def audit(tmp_path):
    def run(cve, body, version="1.31.6"):
        path = tmp_path / "nginx.conf"
        path.write_text("events {}\n" + body, encoding="utf-8")
        config = Config(allow_includes=False, plugins=["nginx_cves"])
        config.set_for("nginx_cves", {"version": version})
        with Manager(config=config) as manager:
            with path.open(encoding="utf-8") as source:
                manager.audit(str(path), source)
            return [
                issue
                for issue in manager.auditor.plugins[0].issues
                if issue.reason.startswith(cve + ":")
            ]

    return run


TLS = "CVE-2026-97629"
ALIAS = "CVE-2026-15176"
HTTP3 = "CVE-2026-95101"
SSI = "CVE-2026-97205"
CACHE = "ssl_session_cache shared:TLS:10m;"
PROXY = "proxy_pass http://backend;"
ALIAS_BASE = "alias /srv/files/; rewrite ^ /file break;"


@pytest.mark.parametrize("version", ["1.23.2", "1.30.5", "1.31.6"])
def test_tls_automatic_rotation_and_anchor(audit, version):
    issues = audit(TLS, "http { " + CACHE + " server { listen 443 ssl; } }", version)
    assert len(issues) == 1
    assert [d.name for d in issues[0].directives] == ["ssl_session_cache", "server"]


@pytest.mark.parametrize(
    "setting",
    [
        "ssl_session_ticket_key /key1; ssl_session_ticket_key /key2;",
        "ssl_session_tickets off; ssl_session_ticket_key /key;",
        "ssl_session_tickets off;",
        "ssl_session_cache off;",
    ],
)
def test_tls_local_exclusions_override_shared_cache(audit, setting):
    assert not audit(
        TLS, "http { " + CACHE + " server { listen 443 ssl; " + setting + " } }"
    )


@pytest.mark.parametrize(
    "body",
    [
        "http { "
        + CACHE
        + " ssl_session_ticket_key /key; server { listen 443 ssl; } }",
        "http { " + CACHE + " ssl_session_tickets off; server { listen 443 ssl; } }",
        "http { " + CACHE + " server { listen 80; } }",
        "http { server { listen 443 ssl; } server { listen 80; " + CACHE + " } }",
        "stream { server { listen 443 ssl; " + CACHE + " } }",
    ],
)
def test_tls_inheritance_and_server_isolation(audit, body):
    assert not audit(TLS, body)


def test_tls_local_on_overrides_inherited_off(audit):
    assert audit(
        TLS,
        "http { " + CACHE + " ssl_session_tickets off; "
        "server { listen 443 ssl; ssl_session_tickets on; } }",
    )


@pytest.mark.parametrize(
    "consumer",
    [
        "set $path $request_filename;",
        "return 200 ${request_filename};",
        "access_log /logs/access filename;",
        "access_log /logs/one combined; access_log /logs/two filename;",
    ],
)
def test_alias_requires_an_applicable_consumer(audit, consumer):
    body = "http { log_format filename '${request_filename}'; server { "
    body += "location / { " + ALIAS_BASE + consumer + " } } }"
    issues = audit(ALIAS, body)
    assert len(issues) == 1
    assert issues[0].directives[0].name == "alias"


@pytest.mark.parametrize(
    "extra, consumer",
    [
        ("", ""),
        ("log_format unused '$request_filename';", "access_log /logs/access combined;"),
        (
            "log_format filename '$request_filename'; access_log /logs/access filename;",
            "access_log off;",
        ),
        (
            "log_format filename '$request_filename'; access_log /logs/access filename;",
            "access_log /logs/access combined;",
        ),
        ("", "set $path $request_filename_suffix;"),
    ],
)
def test_alias_ignores_absent_inactive_or_overridden_consumers(audit, extra, consumer):
    assert not audit(
        ALIAS,
        "http { "
        + extra
        + " server { location / { "
        + ALIAS_BASE
        + consumer
        + " } } }",
    )


@pytest.mark.parametrize(
    "other",
    [
        "location /other { return 200 $request_filename; }",
        "location /other { access_log /logs/access filename; }",
    ],
)
def test_alias_consumers_in_sibling_locations_do_not_combine(audit, other):
    assert not audit(
        ALIAS,
        "http { log_format filename '$request_filename'; server { "
        "location / { " + ALIAS_BASE + " } " + other + " } }",
    )


def test_alias_consumers_in_other_server_do_not_combine(audit):
    assert not audit(
        ALIAS,
        "http { server { location / { "
        + ALIAS_BASE
        + " } } server { return 200 $request_filename; } }",
    )


def test_alias_does_not_combine_sibling_rewrite(audit):
    assert not audit(
        ALIAS,
        "http { server { location / { alias /srv/; "
        "return 200 $request_filename; } location /other { "
        "rewrite ^ /file break; } } }",
    )


def test_alias_inherited_log_and_rewrite_are_applicable(audit):
    assert (
        len(
            audit(
                ALIAS,
                "http { log_format filename '$request_filename'; "
                "access_log /logs/access filename; server { rewrite ^ /file break; "
                "location / { alias /srv/; } } }",
            )
        )
        == 1
    )


def test_alias_child_override_uses_its_own_configuration(audit):
    issues = audit(
        ALIAS,
        "http { server { location / { "
        + ALIAS_BASE
        + " location /nested/ { alias /other/; return 200 $request_filename; } "
        "} } }",
    )
    assert len(issues) == 1
    assert issues[0].directives[0].args == ["/other/"]


@pytest.mark.parametrize("extra", ["", "http3 on;", "proxy_request_buffering on;"])
def test_http3_buffered_proxy(audit, extra):
    issues = audit(
        HTTP3,
        "http { server { listen 443 quic; "
        + extra
        + " location / { "
        + PROXY
        + " } } }",
    )
    assert len(issues) == 1
    assert [d.name for d in issues[0].directives] == ["proxy_pass", "listen"]


@pytest.mark.parametrize(
    "body",
    [
        "http { server { listen 443 quic; } }",
        "http { server { http3 on; location / { " + PROXY + " } } }",
        "http { server { listen 443 quic; http3 off; location / { " + PROXY + " } } }",
        "http { http3 off; server { listen 443 quic; location / { " + PROXY + " } } }",
        "http { proxy_request_buffering off; server { listen 443 quic; location / { "
        + PROXY
        + " } } }",
        "http { server { listen 443 quic; location / { proxy_request_buffering off; "
        + PROXY
        + " } } }",
        "http { server { listen 443 quic; } server { location / { " + PROXY + " } } }",
        "stream { server { listen 443 quic; " + PROXY + " } }",
    ],
)
def test_http3_requires_same_server_effective_settings(audit, body):
    assert not audit(HTTP3, body)


def test_http3_nearer_on_overrides_inherited_off(audit):
    assert audit(
        HTTP3,
        "http { http3 off; proxy_request_buffering off; "
        "server { listen 443 quic; http3 on; location / { "
        "proxy_request_buffering on; " + PROXY + " } } }",
    )


@pytest.mark.parametrize("aio", ["on", "threads", "threads=pool"])
def test_ssi_inheritance_in_both_directions_and_no_duplicates(audit, aio):
    issues = audit(
        SSI,
        "http { ssi on; server { listen 80; aio "
        + aio
        + "; location / {} location /other {} } }",
    )
    assert len(issues) == 1
    assert [d.name for d in issues[0].directives] == ["ssi", "aio"]


@pytest.mark.parametrize(
    "body",
    [
        "http { ssi on; server { location / { ssi off; aio threads; } } }",
        "http { aio threads; server { location / { ssi on; aio off; } } }",
        "http { server { ssi on; } server { aio threads; } }",
        "http { server { location / { ssi on; } location /other { aio on; } } }",
        "stream { server { ssi on; aio threads; } }",
    ],
)
def test_ssi_effective_off_and_context_isolation(audit, body):
    assert not audit(SSI, body)


@pytest.mark.parametrize(
    "cve,body,lower",
    [
        (TLS, "http { server { listen 443 ssl; " + CACHE + " } }", "1.23.1"),
        (
            ALIAS,
            "http { server { location / { "
            + ALIAS_BASE
            + "return 200 $request_filename; } } }",
            "0.1.28",
        ),
        (
            HTTP3,
            "http { server { listen 443 quic; location / { " + PROXY + " } } }",
            "1.24.0",
        ),
        (SSI, "http { ssi on; server { aio threads; } }", "0.8.10"),
    ],
)
def test_latest_prerequisites_affected_and_fixed_boundaries(audit, cve, body, lower):
    for version in ("1.30.5", "1.31.6"):
        assert audit(cve, body, version), version
    for version in (lower, "1.30.6", "1.31.7"):
        assert not audit(cve, body, version), version


@pytest.mark.parametrize(
    "path_setting, expected",
    [
        ("", "/srv/files/"),
        ("root /srv/root;", None),
        (
            "root /srv/root; location /nested/deeper/ { alias /restored/; "
            "return 200 $request_filename; }",
            "/restored/",
        ),
    ],
)
def test_nearer_root_masks_alias_and_nearer_alias_restores_it(
    audit, path_setting, expected
):
    body = "http { server { location / { " + ALIAS_BASE
    body += " location /nested/ { " + path_setting
    body += " return 200 $request_filename; } } } }"
    issues = audit(ALIAS, body)
    if expected is None:
        assert issues == []
    else:
        assert len(issues) == 1
        assert issues[0].directives[0].args == [expected]


@pytest.mark.parametrize(
    "logs",
    [
        "access_log off; access_log /logs/access filename;",
        "access_log /logs/access filename; access_log off;",
    ],
)
def test_access_log_off_cancels_every_log_at_its_scope(audit, logs):
    assert not audit(
        ALIAS,
        "http { log_format filename '$request_filename'; "
        "server { location / { " + ALIAS_BASE + logs + " } } }",
    )


@pytest.mark.parametrize(
    "consumer",
    [
        "set $path $request_filename;",
        "return 200 ${request_filename};",
    ],
)
def test_access_log_off_does_not_cancel_direct_consumers(audit, consumer):
    assert audit(
        ALIAS,
        "http { log_format filename '$request_filename'; "
        "server { location / { "
        + ALIAS_BASE
        + consumer
        + " access_log off; access_log /logs/access filename; } } }",
    )


@pytest.mark.parametrize(
    "child_logs, expected",
    [
        ("", False),
        ("access_log /logs/child filename;", True),
    ],
)
def test_inherited_access_log_off_allows_a_child_override(audit, child_logs, expected):
    issues = audit(
        ALIAS,
        "http { log_format filename '$request_filename'; "
        "access_log /logs/parent filename; access_log off; "
        "server { location / { " + ALIAS_BASE + child_logs + " } } }",
    )
    assert bool(issues) == expected


@pytest.mark.parametrize(
    "definition, reference",
    [
        ("filename", "FILENAME"),
        ("FileName", "fIlEnAmE"),
    ],
)
def test_access_log_format_names_are_ascii_case_insensitive(
    audit, definition, reference
):
    assert audit(
        ALIAS,
        "http { log_format " + definition + " '$request_filename'; "
        "server { location / { "
        + ALIAS_BASE
        + "access_log /logs/access "
        + reference
        + "; } } }",
    )


@pytest.mark.parametrize(
    "formats, expected",
    [
        ("log_format FileName '$uri'; log_format filename '$request_filename';", False),
        ("log_format FileName '$request_filename'; log_format filename '$uri';", True),
    ],
)
def test_access_log_format_lookup_preserves_first_matching_definition(
    audit, formats, expected
):
    issues = audit(
        ALIAS,
        "http { "
        + formats
        + " server { location / { "
        + ALIAS_BASE
        + "access_log /logs/access FILENAME; } } }",
    )
    assert bool(issues) == expected


def test_access_log_format_lookup_does_not_fold_non_ascii(audit):
    assert not audit(
        ALIAS,
        "http { log_format ÄNAME '$request_filename'; "
        "server { location / { " + ALIAS_BASE + "access_log /logs/access äname; } } }",
    )
