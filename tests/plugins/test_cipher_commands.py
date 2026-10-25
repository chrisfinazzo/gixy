"""OpenSSL cipher expression behavior in the weak TLS check."""

import io

import pytest

from gixy.core.config import Config
from gixy.core.manager import Manager


def _weak_cipher_count(expression):
    config = Config(plugins=["weak_ssl_tls"])
    source = (
        "events {}\nhttp { server { listen 80; "
        "ssl_protocols TLSv1.2 TLSv1.3; "
        'ssl_ciphers "' + expression + '"; } }\n'
    )
    with Manager(config=config) as manager:
        manager.audit(
            "example.invalid.conf", io.BytesIO(source.encode()), is_stdin=True
        )
        return sum(len(plugin.issues) for plugin in manager.auditor.plugins)


@pytest.mark.parametrize(
    "expression",
    [
        "AES128-SHA:DES-CBC3-SHA:!3DES",
        "AES128-SHA:ADH-AES128-SHA:!aNULL",
        "AES128-SHA:CAMELLIA128-SHA:-CAMELLIA",
        "AES128-SHA:+CAMELLIA",
        "AES128+CAMELLIA",
        "ADH-AES128-SHA:!aNULL:ADH-AES128-SHA",
        "CAMELLIA:!ALL",
        "DEFAULT:!ALL",
        "kRSA+eNULL:!eNULL",
        "kDHE+aNULL:!aNULL",
        "AES128-SHA+AES128-SHA",
        "AES128-SHA+AES256-SHA",
        "CAMELLIA128-SHA+CAMELLIA256-SHA",
        "AES128-GCM-SHA128",
        "AES128-SHA128",
        "DHE-RSA-AES128-GCM-SHA128",
        "AES256+EDH",
        "AES256+EECDH",
        "EDH+AESGCM",
        "EECDH+AESGCM",
        "AESGCM+EDH",
        "AESGCM+EECDH",
    ],
)
def test_weak_selection_removed_or_never_added(expression):
    assert _weak_cipher_count(expression) == 0


@pytest.mark.parametrize(
    "expression",
    [
        "aNULL",
        "eNULL",
        "NULL",
        "ADH-AES128-SHA",
        "AES128-SHA:DES-CBC3-SHA:-3DES:DES-CBC3-SHA",
        "AES128-SHA:CAMELLIA128-SHA:+CAMELLIA",
        "DES-CBC3-SHA:!BOGUS",
        "CAMELLIA128-SHA:!CAMELLIA128-SHA+BOGUS",
        "kRSA",
        "kRSA+eNULL",
        "kDHE+aNULL",
        "kDHE:!aNULL",
        "kECDHE:!aNULL",
        "kRSA:!ALL",
        "eNULL:!ALL",
        "kDHE+AESGCM",
        "HIGH",
    ],
)
def test_weak_selection_remains_enabled(expression):
    assert _weak_cipher_count(expression) == 1


@pytest.mark.parametrize(
    "suite,family",
    [
        ("DES-CBC3-SHA", "3DES"),
        ("CAMELLIA128-SHA", "CAMELLIA"),
        ("ADH-AES128-SHA", "aNULL"),
        ("NULL-SHA", "eNULL"),
    ],
)
def test_permanent_and_reversible_exclusions_for_supported_families(suite, family):
    """Exercise the operator algebra across unrelated weak families."""
    strong = "AES128-SHA"
    assert _weak_cipher_count(f"{strong}:{suite}:!{family}:{suite}") == 0
    assert _weak_cipher_count(f"{strong}:{suite}:-{family}") == 0
    assert _weak_cipher_count(f"{strong}:{suite}:-{family}:{suite}") == 1
    assert _weak_cipher_count(f"{strong}:+{suite}") == 0
    assert _weak_cipher_count(f"{suite}:+{family}") == 1
