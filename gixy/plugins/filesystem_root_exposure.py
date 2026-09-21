"""Detect document mappings that resolve to the filesystem root."""

import posixpath

import gixy
from gixy.plugins.plugin import Plugin


class filesystem_root_exposure(Plugin):
    """Detect root and alias directives mapped to the filesystem root."""

    summary = "Filesystem root used as a document path"
    severity = gixy.severity.MEDIUM
    description = (
        "Mapping request paths to the filesystem root may expose sensitive files "
        "when request routing and access controls permit them to be served."
    )
    directives = ["root", "alias"]

    def audit(self, directive):
        """Report a constant path that resolves to the POSIX filesystem root.

        Args:
            directive: Parsed root or alias directive.
        """
        if not self._is_filesystem_root(directive.path):
            return

        self.add_issue(
            severity=self.severity,
            directive=[directive],
            reason=(
                f'The "{directive.name}" directive maps requests to the filesystem '
                "root. Sensitive files may become reachable depending on the "
                "surrounding location and access controls."
            ),
        )

    @staticmethod
    def _is_filesystem_root(path):
        """Return whether a constant POSIX path resolves to the root directory.

        Args:
            path: Path argument from a root or alias directive.

        Returns:
            True when the variable-free path resolves to the filesystem root.
        """
        if "$" in path:
            return False

        normalized = posixpath.normpath(path)
        return normalized.startswith("/") and not normalized.strip("/")
