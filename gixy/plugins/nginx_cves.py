"""Unified nginx CVE advisor: version-range + config-pattern checks."""

import re

import gixy
from gixy.plugins.plugin import Plugin


def _parse_oss(version_str):
    """Parse an nginx OSS version string like '1.29.8' to a tuple.

    Args:
        version_str: Version in 'X.Y.Z' form. Leading 'v' tolerated.

    Returns:
        Tuple of three ints, or None if the string isn't parseable.
    """
    if not version_str:
        return None
    cleaned = version_str.strip().lstrip("v")
    parts = cleaned.split(".")
    if len(parts) != 3:
        return None
    try:
        return tuple(int(p) for p in parts)
    except ValueError:
        return None


def _in_range(version, low, high):
    """Check whether ``version`` falls within the inclusive [low, high] range.

    Args:
        version: Parsed version tuple.
        low: Inclusive lower bound tuple.
        high: Inclusive upper bound tuple.

    Returns:
        True iff low <= version <= high.
    """
    return low <= version <= high


_UNNAMED_BACKREF = re.compile(r"\$(?:[1-9]|\{[1-9]\})")
_SCRIPT_ENGINE_TRIGGERS = ("rewrite", "if", "set")


def _check_cve_2026_42945(root):
    """Find rewrite directives that trigger CVE-2026-42945 in the parsed tree.

    The trigger is: a rewrite whose replacement contains both an unnamed
    PCRE backreference ($1..$9 or ${1}..${9}) and a literal '?', followed
    by another rewrite/if/set sibling in the same parent context.

    Args:
        root: Root Block of the parsed nginx config.

    Yields:
        (rewrite_directive, follow_up_sibling) tuples for each match.
    """
    for rewrite in root.find_recursive("rewrite"):
        if len(rewrite.args) < 2:
            continue
        replace = rewrite.args[1]
        if "?" not in replace:
            continue
        if not _UNNAMED_BACKREF.search(replace):
            continue
        parent = rewrite.parent
        if parent is None or not parent.children:
            continue
        siblings = parent.children
        idx = next((i for i, c in enumerate(siblings) if c is rewrite), None)
        if idx is None:
            continue
        follow_up = next(
            (c for c in siblings[idx + 1 :] if c.name in _SCRIPT_ENGINE_TRIGGERS),
            None,
        )
        if follow_up is None:
            continue
        yield rewrite, follow_up


# CVE database. Append future entries here; the plugin auto-walks this.
#   id:           CVE identifier
#   nickname:     short marketing name (or '')
#   summary:      one-line issue description
#   severity:     gixy severity constant
#   advisory:     authoritative URL
#   affected_oss: (low, high) inclusive version tuples; None if not OSS
#   fixed_oss:    iterable of fixed OSS versions (string form, for messages)
#   fixed_plus:   iterable of fixed Plus versions (string form, for messages)
#   config_check: callable(root) yielding (primary, related) directive
#                 pairs, or None if the CVE is binary-only
_CVES = (
    {
        "id": "CVE-2026-42945",
        "nickname": "NGINX Rift",
        "summary": "Heap overflow in ngx_http_rewrite_module.",
        "severity": gixy.severity.HIGH,
        "advisory": "https://nvd.nist.gov/vuln/detail/CVE-2026-42945",
        "affected_oss": ((0, 6, 27), (1, 30, 0)),
        "fixed_oss": ("1.30.1", "1.31.0"),
        "fixed_plus": ("R32 P6", "R36 P4"),
        "config_check": _check_cve_2026_42945,
    },
)


class nginx_cves(Plugin):
    """Advise on nginx CVEs by binary version, with config-trigger enrichment.

    Pass ``--nginx-version=1.29.8`` to enable the check. Every CVE whose
    affected range covers the supplied version is reported with the
    upgrade target. For CVEs that also have a config-pattern trigger
    (e.g. CVE-2026-42945), the report enriches with the offending
    directives.

    Without ``--nginx-version``, the check stays silent: gixy is
    config-static and has no view of the binary, so there is nothing
    safe to assert.
    """

    summary = "Known nginx CVE affects your installed version."
    severity = gixy.severity.HIGH
    description = (
        "Maintains a database of nginx CVEs. When --nginx-version is "
        "supplied, every CVE fixed in a later release is reported. "
        "CVEs that also have a config-pattern trigger enrich the "
        "report with the offending directives. Without a version, the "
        "check is silent."
    )
    options = {
        "version": "",
    }
    options_help = {
        "version": "Installed nginx Open Source version (e.g. 1.29.8).",
    }
    supports_full_config = True

    # Per-directive audit() is unused — all logic runs in post_audit().
    directives = []

    def __init__(self, config):
        """Initialize and parse the user-supplied nginx version.

        Args:
            config: gixy plugin Config; reads the 'version' key.
        """
        super().__init__(config)
        self._oss_version = _parse_oss(self.config.get("version"))

    def post_audit(self, root):
        """Walk the CVE database against the supplied version and config.

        Args:
            root: Root Block of the parsed nginx config tree.
        """
        if self._oss_version is None:
            return
        for cve in _CVES:
            self._evaluate_cve(cve, root)

    def _evaluate_cve(self, cve, root):
        """Decide whether a single CVE applies and emit issues if so.

        Args:
            cve: CVE record from the _CVES tuple.
            root: Root Block of the parsed config.
        """
        affected_oss = cve["affected_oss"]
        if affected_oss is None:
            return
        if not _in_range(self._oss_version, affected_oss[0], affected_oss[1]):
            return

        pattern_matches = []
        if cve["config_check"] is not None:
            pattern_matches = list(cve["config_check"](root))

        upgrade_targets = ", ".join(cve["fixed_oss"])
        if cve["fixed_plus"]:
            upgrade_targets += " (Plus: " + ", ".join(cve["fixed_plus"]) + ")"

        nickname = f' ("{cve["nickname"]}")' if cve["nickname"] else ""
        if pattern_matches:
            qualifier = (
                "your installed version is vulnerable AND the trigger "
                "pattern is present in this config"
            )
        else:
            qualifier = "your installed version falls in the affected range"

        reason = (
            f"{cve['id']}{nickname}: {cve['summary']} "
            f"{qualifier.capitalize()}. Fixed in: {upgrade_targets}. "
            f"Advisory: {cve['advisory']}."
        )

        if pattern_matches:
            for primary, related in pattern_matches:
                self.add_issue(
                    directive=[primary, related],
                    severity=cve["severity"],
                    reason=reason,
                    help_url=cve["advisory"],
                )
            return

        # Version-only branch: attach to the first server block so the
        # report renders something visible (Root / HttpBlock are skipped
        # by formatter.skip_parents).
        anchor = self._pick_anchor(root)
        if anchor is None:
            return
        self.add_issue(
            directive=[anchor],
            severity=cve["severity"],
            reason=reason,
            help_url=cve["advisory"],
        )

    def _pick_anchor(self, root):
        """Pick a directive to attach a version-only issue to.

        Args:
            root: Root Block of the parsed config.

        Returns:
            A server block if one exists, otherwise the first non-http
            child of root, otherwise None.
        """
        servers = root.find_recursive("server")
        if servers:
            return servers[0]
        for child in root.children:
            if child.name != "http":
                return child
        return None
