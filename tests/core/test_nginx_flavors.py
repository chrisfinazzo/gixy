"""Exercise bundled flavor evidence and pure identity parsing."""

import io
import json
import pkgutil

import pytest

from gixy.core import nginx_flavors
from gixy.core.config import Config
from gixy.core.manager import Manager


@pytest.fixture
def definitions():
    return json.loads(pkgutil.get_data("gixy", "data/nginx-flavors.json").decode())


def test_bundled_registry_contains_only_evidenced_fix(definitions):
    registry = nginx_flavors.validate_definitions(definitions)
    assert set(registry) == {"upstream", "nginx-mod"}
    assert registry["upstream"] == {
        "flavor": "upstream",
        "banner_prefix": "nginx/",
        "fixed_in": {},
    }
    assert set(registry["nginx-mod"]["fixed_in"]) == {"quic_bpf_reuseport"}
    assert (
        registry["nginx-mod"]["fixed_in"]["quic_bpf_reuseport"]["version"] == "1.30.6"
    )
    assert len(registry["nginx-mod"]["fixed_in"]["quic_bpf_reuseport"]["sources"]) == 3


@pytest.mark.parametrize(
    "output,expected",
    [
        ("nginx version: nginx/1.31.7", ("1.31.7", "upstream")),
        (
            "nginx version: nginx-mod by GetPageSpeed.com/1.30.6",
            ("1.30.6", "nginx-mod"),
        ),
        ("nginx version: nginx/1.24.0 (Ubuntu)", ("1.24.0", "upstream")),
        ("nginx version: vendor/1.30.6", ("1.30.6", "upstream")),
        (
            "built by gcc/12.1.0\nOpenSSL/3.0.1\nnginx version: nginx/1.30.6\nconfigure arguments: /foo/1.40.0",
            ("1.30.6", "upstream"),
        ),
        ("built by gcc/12.1.0\nOpenSSL/3.0.1", None),
        ("prefix nginx version: nginx/1.30.6", None),
        ("nginx version: nginx/1.30.6.4", None),
        ("nginx version: nginx/1.30.6-unknown", None),
        ("nginx version: nginx/v1.30.6", None),
        ("nginx version: nginx/invalid (OpenSSL/3.0.1)", None),
        ("nginx version: nginx/1.30.6 (OpenSSL/3.0.1)", ("1.30.6", "upstream")),
        ("nginx version: nginx/1.².6", None),
        ("nginx version: nginx/1.30", None),
        ("nginx/1.30.6", None),
    ],
)
def test_parse_only_banner_version(output, expected):
    assert (
        nginx_flavors.parse_banner(output, nginx_flavors.load_definitions()) == expected
    )


@pytest.mark.parametrize("value", [None, {}, [], [None], ["upstream"]])
def test_registry_rejects_non_records(value):
    with pytest.raises(ValueError, match="NGINX flavor definitions"):
        nginx_flavors.validate_definitions(value)


@pytest.mark.parametrize(
    "field,value",
    [
        ("flavor", None),
        ("flavor", ""),
        ("flavor", 3),
        ("banner_prefix", None),
        ("banner_prefix", 4),
        ("banner_prefix", "nginx"),
        ("banner_prefix", "/"),
        ("banner_prefix", "foo\n/"),
        ("fixed_in", None),
        ("fixed_in", []),
    ],
)
def test_registry_rejects_bad_fields(definitions, field, value):
    definitions[1][field] = value
    with pytest.raises(ValueError, match="NGINX flavor definitions"):
        nginx_flavors.validate_definitions(definitions)


@pytest.mark.parametrize("field", ["flavor", "banner_prefix"])
def test_registry_rejects_duplicates(definitions, field):
    definitions[1][field] = definitions[0][field]
    with pytest.raises(ValueError, match="duplicate"):
        nginx_flavors.validate_definitions(definitions)


def test_registry_requires_upstream(definitions):
    with pytest.raises(ValueError, match="upstream"):
        nginx_flavors.validate_definitions(definitions[1:])


@pytest.mark.parametrize(
    "fix",
    [
        None,
        "1.30.6",
        {},
        {"version": None},
        {"version": "v1.30.6", "sources": ["https://vendor.example/fix"]},
        {"version": "1.30", "sources": ["https://vendor.example/fix"]},
        {"version": "1.30.6", "sources": []},
        {"version": "1.30.6", "sources": "https://vendor.example/fix"},
        {"version": "1.30.6", "sources": [None]},
        {"version": "1.30.6", "sources": ["file:///fix"]},
        {"version": "1.30.6", "sources": ["https://"]},
        {"version": "1.30.6", "sources": ["https://vendor.example/bad url"]},
        {"version": "1.30.6", "sources": ["https://[broken"]},
    ],
)
def test_registry_rejects_bad_fix_records(definitions, fix):
    definitions[1]["fixed_in"]["quic_bpf_reuseport"] = fix
    with pytest.raises(ValueError, match="NGINX flavor definitions"):
        nginx_flavors.validate_definitions(definitions)


@pytest.mark.parametrize("key", ["CVE-*", "CVE-2026-", "", "quic-bpf-reuseport", "*"])
def test_registry_rejects_nonexact_fix_keys(definitions, key):
    definitions[1]["fixed_in"][key] = definitions[1]["fixed_in"]["quic_bpf_reuseport"]
    with pytest.raises(ValueError, match="exact CVE IDs"):
        nginx_flavors.validate_definitions(definitions)


@pytest.mark.parametrize("data", [None, b"{", b"\xff", b"{}"])
def test_resource_errors_are_clear(monkeypatch, data):
    monkeypatch.setattr(nginx_flavors.pkgutil, "get_data", lambda *args: data)
    with pytest.raises(ValueError, match="NGINX flavor definitions"):
        nginx_flavors.load_definitions()


def test_missing_resource_is_clear(monkeypatch):
    def missing(*args):
        raise OSError("missing resource")

    monkeypatch.setattr(nginx_flavors.pkgutil, "get_data", missing)
    with pytest.raises(ValueError, match="Cannot load NGINX flavor definitions"):
        nginx_flavors.load_definitions()


@pytest.mark.parametrize("flavor", ["typo", "", "NGINX-MOD", [], {}, 4])
def test_core_rejects_invalid_explicit_flavor(flavor):
    with pytest.raises(ValueError, match="Unknown NGINX flavor"):
        Config(nginx_flavor=flavor)


def test_data_only_flavor_and_exact_cve_scope(monkeypatch, definitions):
    definitions.append(
        {
            "flavor": "example-vendor",
            "banner_prefix": "Example Vendor/",
            "fixed_in": {
                "CVE-2026-93479": {
                    "version": "1.30.5",
                    "sources": ["https://vendor.example/fix"],
                }
            },
        }
    )
    resource = json.dumps(definitions).encode()
    monkeypatch.setattr(nginx_flavors.pkgutil, "get_data", lambda *args: resource)
    registry = nginx_flavors.load_definitions()
    assert nginx_flavors.parse_banner(
        "nginx version: Example Vendor/1.30.5", registry
    ) == ("1.30.5", "example-vendor")
    from gixy.cli.main import _get_cli_parser

    assert (
        _get_cli_parser()
        .parse_args(["--nginx-flavor=example-vendor"], env_vars={})
        .nginx_flavor
        == "example-vendor"
    )
    config = Config(
        plugins=["nginx_cves", "quic_bpf_reuseport"],
        nginx_version="1.30.5",
        nginx_flavor="example-vendor",
    )
    assert config.resolved_nginx_version == (1, 30, 5)
    assert config.nginx_has_fix("CVE-2026-93479")
    content = b"worker_processes 2; quic_bpf on; events {} http { server { listen 443 quic reuseport; location / { proxy_pass http://backend; } } }"
    with Manager(config=config) as manager:
        manager.audit("example.conf", io.BytesIO(content), is_stdin=True)
        plugins = {plugin.name: plugin for plugin in manager.auditor.plugins}
        reasons = " ".join(issue.reason for issue in plugins["nginx_cves"].issues)
        assert "CVE-2026-93479" not in reasons
        assert "CVE-2026-95101" in reasons  # An unrelated triggered CVE remains.
        assert "CVE-2026-15176" not in reasons  # Its configuration trigger is absent.
        assert "CVE-2026-97629" not in reasons  # Its TLS trigger is absent.
        assert len(plugins["quic_bpf_reuseport"].issues) == 1
    # Same real CVE is reported before the flavor fix threshold.
    older = Config(
        plugins=["nginx_cves"], nginx_version="1.30.4", nginx_flavor="example-vendor"
    )
    with Manager(config=older) as manager:
        manager.audit("example.conf", io.BytesIO(content), is_stdin=True)
        assert any(
            "CVE-2026-93479" in issue.reason
            for plugin in manager.auditor.plugins
            for issue in plugin.issues
        )


def test_quic_flavor_fix_preserves_other_findings(monkeypatch, definitions):
    definitions.append(
        {
            "flavor": "test-vendor",
            "banner_prefix": "Test Vendor/",
            "fixed_in": {
                "quic_bpf_reuseport": {
                    "version": "1.30.5",
                    "sources": ["https://vendor.example/quic-fix"],
                }
            },
        }
    )
    resource = json.dumps(definitions).encode()
    monkeypatch.setattr(nginx_flavors.pkgutil, "get_data", lambda *args: resource)
    config = Config(
        plugins=["nginx_cves", "quic_bpf_reuseport", "version_disclosure"],
        nginx_version="1.30.5",
        nginx_flavor="test-vendor",
    )
    content = b"worker_processes 2; quic_bpf on; events {} http { server { listen 443 quic reuseport; server_tokens on; } }"
    with Manager(config=config) as manager:
        manager.audit("example.conf", io.BytesIO(content), is_stdin=True)
        plugins = {plugin.name: plugin for plugin in manager.auditor.plugins}
        assert not plugins["quic_bpf_reuseport"].issues
        assert any(
            "CVE-2026-93479" in issue.reason for issue in plugins["nginx_cves"].issues
        )
        assert plugins["version_disclosure"].issues
