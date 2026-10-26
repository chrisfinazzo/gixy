"""Read bundled NGINX flavor identities and narrowly scoped fix evidence."""

import json
import pkgutil
import re
from urllib.parse import urlsplit

from gixy.core.nginx_version import parse_oss


_RESOURCE = "data/nginx-flavors.json"
_VERSION = r"[0-9]+\.[0-9]+\.[0-9]+"
_BANNER = re.compile(r"^\s*nginx version:\s*(.+?)\s*$")
_IDENTITY = re.compile(r"^([^/]+/)(" + _VERSION + r")(?:\s+.*)?$")
_FIX_KEY = re.compile(r"(?:[a-z][a-z0-9_]*|CVE-[0-9]{4}-[0-9]{4,})\Z")


def validate_definitions(definitions):
    """Validate decoded flavor records and index them by name.

    Args:
        definitions (object): Decoded JSON resource.

    Returns:
        dict: Flavor names mapped to validated definition records.

    Raises:
        ValueError: If any definition, fix version or source is malformed.
    """

    def invalid(message):
        raise ValueError("Invalid NGINX flavor definitions: " + message)

    if not isinstance(definitions, list) or not definitions:
        invalid("expected a nonempty list")
    flavors = {}
    prefixes = set()
    for record in definitions:
        if not isinstance(record, dict):
            invalid("each flavor must be an object")
        name = record.get("flavor")
        prefix = record.get("banner_prefix")
        fixes = record.get("fixed_in")
        if not isinstance(name, str) or not name or name.strip() != name:
            invalid("flavor must be a nonempty name")
        if name in flavors:
            invalid("duplicate flavor " + name)
        if (
            not isinstance(prefix, str)
            or len(prefix) < 2
            or not prefix.endswith("/")
            or any(c in prefix for c in "\r\n")
            or prefix.strip() != prefix
        ):
            invalid("banner_prefix must be a nonempty prefix ending in /")
        if prefix in prefixes:
            invalid("duplicate banner_prefix " + prefix)
        if not isinstance(fixes, dict):
            invalid("fixed_in must be an object for " + name)
        for key, fix in fixes.items():
            if not isinstance(key, str) or not _FIX_KEY.fullmatch(key):
                invalid("fix keys must be check names or exact CVE IDs")
            if not isinstance(fix, dict):
                invalid("fix must be an object for " + key)
            version = fix.get("version")
            if not isinstance(version, str) or not re.fullmatch(_VERSION, version):
                invalid("fix version must be X.Y.Z for " + key)
            if parse_oss(version) is None:
                invalid("unparseable fix version for " + key)
            sources = fix.get("sources")
            if not isinstance(sources, list) or not sources:
                invalid("fix sources must be a nonempty list for " + key)
            for source in sources:
                if not isinstance(source, str) or any(c.isspace() for c in source):
                    invalid("fix source must be an HTTP(S) URL for " + key)
                try:
                    url = urlsplit(source)
                except ValueError:
                    invalid("invalid fix source URL for " + key)
                if url.scheme not in ("https", "http") or not url.netloc:
                    invalid("fix source must be an HTTP(S) URL for " + key)
        flavors[name] = record
        prefixes.add(prefix)
    if "upstream" not in flavors:
        invalid("upstream flavor is required")
    return flavors


def load_definitions():
    """Load and validate the packaged flavor registry.

    Returns:
        dict: Flavor names mapped to validated records.

    Raises:
        ValueError: If the bundled resource is missing or malformed.
    """
    try:
        data = pkgutil.get_data("gixy", _RESOURCE)
        if data is None:
            raise ValueError("missing resource")
        definitions = json.loads(data.decode("utf-8"))
    except (OSError, ValueError, UnicodeError) as error:
        raise ValueError(f"Cannot load NGINX flavor definitions: {error}")
    return validate_definitions(definitions)


def parse_banner(output, definitions):
    """Parse only an NGINX version banner, retaining the advertised version.

    Args:
        output (str): Captured nginx -V output from either stream.
        definitions (dict): Validated bundled flavor records.

    Returns:
        tuple: Version string and flavor name, or None for an invalid banner.
    """
    for line in output.splitlines():
        banner = _BANNER.fullmatch(line)
        if banner is None:
            continue
        identity = _IDENTITY.fullmatch(banner.group(1))
        if identity is None:
            continue
        prefix, version = identity.groups()
        if parse_oss(version) is None:
            continue
        flavor = next(
            (
                name
                for name, record in definitions.items()
                if record["banner_prefix"] == prefix
            ),
            "upstream",
        )
        return version, flavor
    return None
