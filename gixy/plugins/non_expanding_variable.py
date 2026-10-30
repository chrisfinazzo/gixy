"""Detect variables written where NGINX stores the text literally."""

import re

import gixy
from gixy.core.context import get_context
from gixy.directives.block import GeoBlock, IfBlock, IncludeBlock, LocationBlock
from gixy.plugins.plugin import Plugin

VARIABLE_RE = re.compile(r"\$(?:\{[A-Za-z_]\w*\}|[A-Za-z_]\w*)")

# envsubst/Docker template placeholder: ${BACKEND_HOST}
ENV_PLACEHOLDER_RE = re.compile(r"\$\{([A-Z][A-Z0-9_]*)\}\Z")

REGEX_IF_OPERATORS = frozenset(["~", "~*", "!~", "!~*"])

# Directives whose arguments carry embedded code rather than NGINX values
CODE_DIRECTIVE_SUFFIXES = ("_by_lua", "_by_lua_block", "_by_lua_file")

# naxsi rules use "$NAME" for their own score names, e.g. CheckRule "$SQL >= 8"
NAXSI_DIRECTIVES = frozenset(
    ["BasicRule", "CheckRule", "MainRule", "basic_rule", "check_rule", "main_rule"]
)

# geo parameters whose argument is not a resulting value
GEO_KEYWORDS = frozenset(["delete", "proxy", "proxy_recursive", "ranges"])

# Directives whose path argument (the first one) is never compiled as a script.
# Verified on nginx 1.31.8: the files/directories are created with "$" in the name.
LITERAL_PATH_DIRECTIVES = frozenset(
    [
        "error_log",
        "client_body_temp_path",
        "proxy_temp_path",
        "fastcgi_temp_path",
        "uwsgi_temp_path",
        "scgi_temp_path",
        "proxy_cache_path",
        "fastcgi_cache_path",
        "uwsgi_cache_path",
        "scgi_cache_path",
    ]
)

RATE_LIMIT_ZONES = ("limit_req_zone", "limit_conn_zone")


class non_expanding_variable(Plugin):
    """Detect variables in directive values that NGINX never expands."""

    summary = "Variable used where NGINX does not expand variables"
    severity = gixy.severity.HIGH
    description = (
        "Unlike map, many NGINX positions take their text literally: geo and "
        "split_clients values, location and server_name matches, rewrite and if "
        "regexes, the auth_request URI and paths such as error_log. A value such "
        'as "$binary_remote_addr" becomes that literal string, and "$name" in a '
        "regex is an end-of-string anchor that can never match."
    )
    # Every directive: environment placeholders can appear anywhere
    directives = []

    def audit(self, directive):
        """Dispatch a directive to the checks for its literal positions.

        Args:
            directive: Any parsed directive or block.
        """
        if self._audit_env_placeholders(directive):
            return
        if directive.name in LITERAL_PATH_DIRECTIVES:
            self._audit_path(directive)
        elif isinstance(directive, GeoBlock):
            self._audit_geo(directive)
        elif directive.name == "split_clients":
            self._audit_split_clients(directive)
        elif isinstance(directive, LocationBlock):
            self._audit_location(directive)
        elif directive.name == "server_name":
            self._audit_server_name(directive)
        elif directive.name == "rewrite":
            self._audit_regex(directive, directive.args[0] if directive.args else "")
        elif isinstance(directive, IfBlock):
            if directive.operand in REGEX_IF_OPERATORS:
                self._audit_regex(directive, directive.value)
        elif directive.name == "auth_request":
            self._audit_auth_request(directive)

    def _audit_env_placeholders(self, directive):
        """Report $UPPER_CASE names that no NGINX variable defines.

        NGINX never reads environment variables, so such a name is almost
        always a template placeholder (envsubst, Docker templates) that was
        never rendered.

        Args:
            directive: Any parsed directive or block.

        Returns:
            bool: True when an issue was reported for the directive.
        """
        if directive.name in NAXSI_DIRECTIVES or (
            directive.name and directive.name.endswith(CODE_DIRECTIVE_SUFFIXES)
        ):
            return False
        names = []
        for arg in directive.args:
            for token in _variable_tokens(arg):
                name = _strip(token)
                if _is_env_placeholder(token) and name not in names:
                    names.append(name)
        if not names:
            return False

        listed = ", ".join("${" + name + "}" for name in names)
        self.add_issue(
            severity=gixy.severity.MEDIUM,
            directive=[directive],
            reason=(
                f"{listed} is not an NGINX variable; it looks like an "
                "environment-variable placeholder left unrendered. NGINX does not "
                "read environment variables in its configuration: render the "
                "template with envsubst (the official Docker image does this for "
                "/etc/nginx/templates/*.template) before NGINX starts."
            ),
        )
        return True

    def _audit_location(self, block):
        """Report variables in a location match, which is never expanded.

        Args:
            block: Parsed location block.
        """
        if block.is_regex:
            self._audit_regex(block, block.path)
        elif not block.path.startswith("@") and _literal_variables(block.path):
            self.add_issue(
                severity=gixy.severity.MEDIUM,
                directive=[block],
                reason=(
                    f'location "{block.path}" is matched literally: NGINX does not '
                    "expand variables in location prefixes, so it only matches "
                    'URIs containing the text "$". Use a regex location or a map.'
                ),
            )

    def _audit_server_name(self, directive):
        """Report variables in server_name entries.

        Args:
            directive: Parsed server_name directive.
        """
        for name in directive.args:
            if name.lower() == "$hostname":
                # Documented special name: the machine's hostname
                continue
            if name.startswith("~"):
                self._audit_regex(directive, name[1:])
                continue
            if _literal_variables(name):
                self.add_issue(
                    severity=gixy.severity.MEDIUM,
                    directive=[directive],
                    reason=(
                        f'server_name "{name}" is matched literally: NGINX does not '
                        "expand variables in server names, so this server only "
                        'answers a Host header containing the text "$". Generate '
                        "the names with a template or use a regex/wildcard name."
                    ),
                )
                return

    def _audit_regex(self, directive, pattern):
        """Report an unescaped "$name" in a regex, which can never match.

        Args:
            directive: Directive that owns the regex.
            pattern (str): Regular expression text.
        """
        anchors = [
            _strip(token)
            for token in _regex_dollar_tokens(pattern)
            if not _is_env_placeholder(token)
        ]
        if not anchors:
            return

        self.add_issue(
            severity=gixy.severity.MEDIUM,
            directive=[directive],
            reason=(
                f'The regex "{pattern}" contains ${anchors[0]}, but NGINX does not '
                'expand variables in regexes: "$" is the end-of-string anchor, so '
                "this part of the pattern can never match. Escape it as \\$ for a "
                "literal dollar sign, or compare against a variable with map."
            ),
        )

    def _audit_auth_request(self, directive):
        """Report variables in the auth_request subrequest URI.

        Args:
            directive: Parsed auth_request directive.
        """
        if not directive.args or not _literal_variables(directive.args[0]):
            return

        self.add_issue(
            severity=gixy.severity.HIGH,
            directive=[directive],
            reason=(
                f"auth_request sends its subrequest to the literal URI "
                f'"{directive.args[0]}": the URI is not expanded. If any location '
                "answers that URI with a 2xx status, every request is authorized. "
                "Use a fixed URI and pass request data to the auth location with "
                "proxy_set_header or variables inside that location."
            ),
        )

    def _audit_geo(self, block):
        """Report geo values containing variable references.

        Args:
            block: Parsed geo block, including entries from included files.
        """
        entries = [
            entry
            for entry in block.gather_geo_directives(block.children)
            if entry.src_val not in GEO_KEYWORDS
            and entry.dest_val
            and _literal_variables(entry.dest_val)
        ]
        if not entries:
            return

        variable = block.variable
        values = ", ".join(sorted({entry.dest_val for entry in entries}))
        reason = (
            f"geo ${variable} stores the value(s) {values} as literal text: the geo "
            "module never expands variables in its values. "
        )
        zones = self._rate_limit_zones(block, variable)
        if zones:
            reason += (
                f"${variable} feeds the key of "
                f"{', '.join(dict.fromkeys(z.name for z in zones))}, so "
                "every matching client shares ONE limit bucket: a single busy "
                "client exhausts the limit for everyone. "
            )
        reason += (
            "Let geo only classify clients and expand the variable in a chained "
            "map, e.g. geo $limit { default 1; 127.0.0.1 0; } "
            'map $limit $limit_key { 0 ""; 1 $binary_remote_addr; }'
        )
        self.add_issue(
            severity=self.severity,
            directive=[block] + entries + zones,
            reason=reason,
        )

    def _audit_split_clients(self, block):
        """Report split_clients values containing variable references.

        Args:
            block: Parsed split_clients block.
        """
        entries = [
            entry
            for entry in self._gather_entries(block.children)
            if any(_literal_variables(arg) for arg in entry.args)
        ]
        if not entries:
            return

        variable = block.args[-1] if block.args else ""
        self.add_issue(
            severity=self.severity,
            directive=[block] + entries,
            reason=(
                f"split_clients {variable} stores its values as literal text; "
                "variables in them are never expanded. Return a literal marker "
                "and expand the variable in a chained map instead."
            ),
        )

    def _audit_path(self, directive):
        """Report a variable in a path argument that NGINX never expands.

        Args:
            directive: Parsed error_log, *_temp_path or *_cache_path directive.
        """
        if not directive.args or not _literal_variables(directive.args[0]):
            return

        self.add_issue(
            severity=gixy.severity.LOW,
            directive=[directive],
            reason=(
                f"{directive.name} does not support variables: NGINX uses the path "
                f'"{directive.args[0]}" literally, with "$" in the file name.'
            ),
        )

    def _gather_entries(self, nodes):
        """Yield plain entries, descending into included files.

        Args:
            nodes: Children of a block.

        Yields:
            Non-block directives.
        """
        for node in nodes:
            if isinstance(node, IncludeBlock):
                yield from self._gather_entries(node.children)
            elif not node.is_block:
                yield node

    @staticmethod
    def _rate_limit_zones(block, variable):
        """Find limit_req_zone/limit_conn_zone directives keyed by a variable.

        Maps whose values reference the variable pass the literal on, so the
        search follows map chains such as ``map $request_method $post_key
        { POST $limit_key; }``.

        Args:
            block: Any directive in the parsed tree.
            variable: Variable name without the leading "$".

        Returns:
            list: Zone directives whose key references the variable, directly
            or through maps.
        """
        root = block
        while root.parent is not None:
            root = root.parent

        derived = {variable}
        maps = root.find_recursive("map")
        changed = True
        while changed:
            changed = False
            for map_block in maps:
                if map_block.variable in derived:
                    continue
                values = [
                    entry.dest_val
                    for entry in map_block.gather_map_directives(map_block.children)
                    if entry.dest_val
                ]
                if any(_references(value, derived) for value in values):
                    derived.add(map_block.variable)
                    changed = True

        zones = []
        for name in RATE_LIMIT_ZONES:
            for zone in root.find_recursive(name):
                if zone.args and _references(zone.args[0], derived):
                    zones.append(zone)
        return zones


def _references(value, names):
    """Return whether a value references any of the given variables.

    Args:
        value (str): Directive argument.
        names (set): Variable names without the leading "$".

    Returns:
        bool: True when ``value`` contains ``$name`` or ``${name}``.
    """
    return any(_strip(token) in names for token in _variable_tokens(value))


def _variable_tokens(value):
    """List the variable references in a value.

    Args:
        value (str): Directive argument.

    Returns:
        list: References as written, e.g. ``$host`` or ``${host}``.
    """
    return VARIABLE_RE.findall(value)


def _strip(token):
    """Return the variable name of a reference.

    Args:
        token (str): Reference such as ``$host`` or ``${host}``.

    Returns:
        str: Name without the leading "$" or braces.
    """
    return token.strip("${}")


def _is_env_placeholder(token):
    """Return whether a reference is an unrendered ${UPPER_CASE} placeholder.

    NGINX variable names are case-insensitive, so ${HOST} is $host; only
    names that resolve to nothing are treated as template placeholders.

    Args:
        token (str): Reference such as ``${BACKEND_HOST}``.

    Returns:
        bool: True for an unresolvable braced all-caps name.
    """
    match = ENV_PLACEHOLDER_RE.match(token)
    return bool(match) and not get_context().get_var(match.group(1).lower())


def _literal_variables(value):
    """List variable names in a value, excluding template placeholders.

    Args:
        value (str): Directive argument stored literally by NGINX.

    Returns:
        list: Names reported by the literal-position checks.
    """
    return [
        _strip(token)
        for token in _variable_tokens(value)
        if not _is_env_placeholder(token)
    ]


def _regex_dollar_tokens(pattern):
    """List variable references after an unescaped "$" outside character classes.

    Args:
        pattern (str): Regular expression text.

    Returns:
        list: References that the regex treats as text after an end anchor.
    """
    tokens = []
    in_class = False
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\":
            index += 2
            continue
        if in_class:
            in_class = char != "]"
        elif char == "[":
            in_class = True
            # A "]" right after "[" or "[^" is a literal member
            if pattern[index + 1 : index + 2] == "^":
                index += 1
            if pattern[index + 1 : index + 2] == "]":
                index += 1
        elif char == "$":
            match = VARIABLE_RE.match(pattern, index)
            if match:
                tokens.append(match.group(0))
        index += 1
    return tokens
