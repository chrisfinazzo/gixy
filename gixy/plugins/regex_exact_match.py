"""Module for regex_exact_match plugin."""

import gixy
from gixy.directives.block import LocationBlock
from gixy.plugins.plugin import Plugin


class regex_exact_match(Plugin):
    r"""
    Insecure example:
        location ~ ^/api/health$ {
        }
    """

    summary = "Regex location can be replaced with exact match"
    severity = gixy.severity.LOW
    description = (
        "A regex location that matches a single literal path can be "
        "replaced with an exact-match location (=) for better performance."
    )
    directives = ["location"]

    def audit(self, directive: LocationBlock):
        path = directive.exact_match_path()
        if not path:
            return

        self.add_issue(
            severity=gixy.severity.LOW,
            directive=[directive],
            reason=f"Use 'location = {path}' instead of 'location ~ {directive.path}'",
            fixes=[
                self.make_fix(
                    title="Convert to exact-match location",
                    search=f"location ~ {directive.path}",
                    replace=f"location = {path}",
                    description="Exact-match locations are faster than regex",
                ),
            ],
        )
