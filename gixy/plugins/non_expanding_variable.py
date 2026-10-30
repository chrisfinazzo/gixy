"""Detect variables written where NGINX stores the text literally."""

import re

import gixy
from gixy.directives.block import GeoBlock, IncludeBlock
from gixy.plugins.plugin import Plugin

VARIABLE_RE = re.compile(r"\$(?:\{[A-Za-z_]\w*\}|[A-Za-z_]\w*)")

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
        "Unlike map, the geo and split_clients modules and file path directives "
        "such as error_log store their values as plain text. A value such as "
        '"$binary_remote_addr" becomes that literal string for every request.'
    )
    directives = ["geo", "split_clients"] + sorted(LITERAL_PATH_DIRECTIVES)

    def audit(self, directive):
        """Dispatch a geo, split_clients or literal-path directive to its check.

        Args:
            directive: Parsed directive or block named in ``directives``.
        """
        if directive.name in LITERAL_PATH_DIRECTIVES:
            self._audit_path(directive)
        elif isinstance(directive, GeoBlock):
            self._audit_geo(directive)
        elif directive.name == "split_clients":
            self._audit_split_clients(directive)

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
            and VARIABLE_RE.search(entry.dest_val)
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
            if any(VARIABLE_RE.search(arg) for arg in entry.args)
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
        if not directive.args or not VARIABLE_RE.search(directive.args[0]):
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
    return any(
        match.group(0).strip("${}") in names for match in VARIABLE_RE.finditer(value)
    )
