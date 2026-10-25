"""Load data-only variable policy into an audit-owned, layered catalog."""

import errno
import logging
import os
import re
import stat
from collections import namedtuple

from gixy.core import builtin_variables
from gixy.core.regexp import Regexp
from gixy.core.sre_parse.sre_constants import error as RegexSyntaxError
from gixy.core.variable import Variable

LOG = logging.getLogger(__name__)
DEFAULT_VARIABLE_DIRS = ("/usr/share/gixy/vars.d", "/etc/gixy/vars.d")
Definition = namedtuple("Definition", "name kind value source line layer")
_LINE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)(?:\s*[=:]\s*|\s+)(.*?)\s*$")


class VariableCatalog:
    """Keep policy layers separate so specificity never crosses a layer."""

    def __init__(self, layers=None):
        self.layers = layers or []

    @classmethod
    def bundled(cls):
        """Return a fresh catalog of curated fallback definitions."""
        definitions = {}
        for name, value in builtin_variables.BUILTIN_VARIABLES.items():
            kind = "regex" if value else "trusted"
            definitions[name] = Definition(
                name, kind, value, builtin_variables.__file__, 0, 0
            )
        return cls([definitions])

    def resolve(self, name):
        """Select the highest matching layer, then exact or longest prefix."""
        if isinstance(name, int):
            return None
        for definitions in reversed(self.layers):
            exact = definitions.get(name)
            if exact is not None:
                return exact
            matches = [
                key for key in definitions if key.endswith("_") and name.startswith(key)
            ]
            if matches:
                return definitions[max(matches, key=len)]
        return None

    def variable(self, name):
        """Instantiate a model without interpreting literals as NGINX scripts."""
        definition = self.resolve(name)
        if definition is None:
            return None
        if definition.kind == "regex":
            return Variable(
                name, Regexp(definition.value, strict=True, case_sensitive=False)
            )
        value = definition.value if definition.kind == "literal" else "builtin"
        return Variable(name, value, have_script=False)


def _normalize_value_token(token):
    """Return a kind/value pair, retaining quoted text without Python evaluation."""
    token = token.strip()
    if token.endswith(","):
        token = token[:-1].rstrip()
    if not token:
        raise ValueError(
            "missing value; use none, null, or quoted empty text explicitly"
        )
    if token.lower() in ("none", "null"):
        return "trusted", None
    raw = len(token) > 1 and token[0] in "rR" and token[1] in "\"'"
    quoted = token[1:] if raw else token
    if quoted[0] in "\"'":
        quote = quoted[0]
        escaped = False
        closing = None
        for index, character in enumerate(quoted[1:], 1):
            if character == quote and not escaped:
                closing = index
                break
            escaped = character == "\\" and not escaped
        if closing != len(quoted) - 1:
            raise ValueError("unmatched quote or text after quoted value")
        value = quoted[1:-1]
        if not value:
            return "trusted", None
        return ("regex" if raw else "literal"), value
    if token[-1] in "\"'":
        raise ValueError("unmatched quote")
    return "regex", token


def _parse_dropin(stream, source, layer):
    """Parse valid lines independently, preserving previous valid definitions."""
    definitions = {}
    for line_number, raw_line in enumerate(stream, 1):
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        try:
            match = _LINE.match(line)
            if match is None:
                raise ValueError(
                    "expected an ASCII variable name and an explicit value"
                )
            name, token = match.groups()
            kind, value = _normalize_value_token(token)
            if kind == "regex":
                # Parse the AST only. Never execute a supplied regex on strings.
                _ = Regexp(value, strict=True, case_sensitive=False).parsed
            definitions[name] = Definition(
                name, kind, value, source, line_number, layer
            )
        except (ValueError, RegexSyntaxError, OverflowError, RecursionError) as error:
            LOG.warning(
                "%s:%d: invalid variable definition: %s", source, line_number, error
            )
    return definitions


def _check_system_stat(info, path, directory):
    """Require root ownership, safe modes and the expected filesystem type."""
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(info.st_mode):
        raise ValueError(
            "{} must be a {}".format(path, "directory" if directory else "regular file")
        )
    if info.st_uid != 0 or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError(f"{path} must be root-owned and not group/world writable")


def _open_system_directory(path):
    """Walk ancestors using held no-follow descriptors to prevent path races."""
    if os.open not in os.supports_dir_fd or not hasattr(os, "O_NOFOLLOW"):
        raise ValueError(
            "safe no-follow directory loading is unavailable on this platform"
        )
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open(os.path.sep, flags)
    try:
        _check_system_stat(os.fstat(descriptor), os.path.sep, True)
        current = os.path.sep
        for component in os.path.abspath(path).split(os.path.sep):
            if not component:
                continue
            current = os.path.join(current, component)
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            _check_system_stat(os.fstat(descriptor), current, True)
        return descriptor
    except (OSError, ValueError):
        os.close(descriptor)
        raise


def _load_directory(path, layer, system=False):
    """Read one policy layer, warning on unsafe or unreadable definitions."""
    definitions = {}
    directory_fd = None
    expanded = os.path.abspath(os.path.expanduser(path))
    try:
        if system:
            # Absence is normal even below a platform symlink such as macOS
            # /etc. This precheck establishes no trust: an existing path must
            # still pass the descriptor-based, no-follow traversal below.
            try:
                os.lstat(expanded)
            except FileNotFoundError:
                return definitions
            directory_fd = _open_system_directory(expanded)
            entries = sorted(os.listdir(directory_fd))
        else:
            entries = sorted(os.listdir(expanded))
        for filename in entries:
            if not filename.endswith((".cfg", ".conf")):
                continue
            source = os.path.join(expanded, filename)
            try:
                flags = os.O_RDONLY | os.O_NONBLOCK
                if system:
                    descriptor = os.open(
                        filename, flags | os.O_NOFOLLOW, dir_fd=directory_fd
                    )
                else:
                    descriptor = os.open(source, flags)
                with os.fdopen(descriptor, encoding="utf-8") as stream:
                    info = os.fstat(stream.fileno())
                    if system:
                        _check_system_stat(info, source, False)
                    elif not stat.S_ISREG(info.st_mode):
                        raise ValueError("definition must be a regular file")
                    definitions.update(_parse_dropin(stream, source, layer))
            except (OSError, ValueError, UnicodeError) as error:
                LOG.warning("Cannot load variable policy %s: %s", source, error)
    except (OSError, ValueError) as error:
        if not (system and isinstance(error, OSError) and error.errno == errno.ENOENT):
            LOG.warning("Cannot load variable policy directory %s: %s", expanded, error)
    finally:
        if directory_fd is not None:
            os.close(directory_fd)
    return definitions


def load_variable_catalog(paths=None, load_default_vars=False):
    """Materialize a fresh catalog with optional system and explicit layers.

    Args:
        paths: Optional iterable of operator-selected directory strings.
        load_default_vars: Boolean enabling trusted system directory discovery.

    Returns:
        VariableCatalog: A catalog belonging to one audit.
    """
    catalog = VariableCatalog.bundled()
    directories = (
        [(path, True) for path in DEFAULT_VARIABLE_DIRS] if load_default_vars else []
    )
    directories.extend((path, False) for path in (paths or []) if path)
    for layer, (path, system) in enumerate(directories, 1):
        catalog.layers.append(_load_directory(path, layer, system))
    return catalog
