"""Unified nginx CVE advisor: version-range + config-pattern checks."""

import gixy
from gixy.plugins._nginx_cves_db import CVES, in_any_range, parse_oss
from gixy.plugins.plugin import Plugin


class nginx_cves(Plugin):
    """Advise on nginx CVEs by binary version, with config-trigger enrichment.

    Pass ``--nginx-version=1.29.8`` to enable the check. Every CVE whose
    affected range covers the supplied version is reported with the
    upgrade target. For CVEs that also have a config-pattern trigger
    (e.g. CVE-2026-42945, mp4-module CVEs, resolver CVEs, HTTP/2 and
    HTTP/3 issues), the report attaches to the offending directives.

    Without ``--nginx-version``, the check stays silent: gixy is
    config-static and has no view of the binary, so there is nothing
    safe to assert.

    The CVE database lives in
    :mod:`gixy.plugins._nginx_cves_db`; append entries there.
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
    # Old binaries trigger several CVEs from a single config — the
    # generic simply-test harness expects exactly one issue per fixture
    # and would fail on those. ``tests/plugins/test_nginx_cves.py``
    # exercises the plugin directly with per-fixture issue counts.
    skip_test = True

    # Per-directive audit() is unused — all logic runs in post_audit().
    directives = []

    def __init__(self, config):
        """Initialize and parse the user-supplied nginx version.

        Args:
            config: gixy plugin Config; reads the ``version`` key.
        """
        super().__init__(config)
        self._oss_version = parse_oss(self.config.get("version"))

    def post_audit(self, root):
        """Walk the CVE database against the supplied version and config.

        Args:
            root: Root Block of the parsed nginx config tree.
        """
        if self._oss_version is None:
            return
        for cve in CVES:
            self._evaluate_cve(cve, root)

    def _evaluate_cve(self, cve, root):
        """Decide whether a single CVE applies and emit issues if so.

        Args:
            cve: CVE record from the ``CVES`` tuple.
            root: Root Block of the parsed config.
        """
        affected_oss = cve["affected_oss"]
        if affected_oss is None:
            return
        if not in_any_range(self._oss_version, affected_oss):
            return

        has_config_check = cve["config_check"] is not None
        pattern_matches = list(cve["config_check"](root)) if has_config_check else []
        # Gating: if a CVE has a config-pattern trigger, suppress when the
        # trigger is absent — the binary may still be vulnerable, but no
        # exploitable surface exists in this config. Pure binary-level
        # CVEs (config_check=None) always fire on a version match.
        if has_config_check and not pattern_matches:
            return

        upgrade_targets = ", ".join(cve["fixed_oss"])
        if cve["fixed_plus"]:
            upgrade_targets += " (Plus: " + ", ".join(cve["fixed_plus"]) + ")"

        nickname = f' ("{cve["nickname"]}")' if cve["nickname"] else ""
        if pattern_matches:
            qualifier = (
                "your installed version is vulnerable and the trigger "
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

        # Pure version-only branch: attach to the first server block so
        # the report renders something visible (Root / HttpBlock are
        # skipped by formatter.skip_parents).
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
            A server block if one exists, otherwise the first non-``http``
            child of root, otherwise ``None``.
        """
        servers = root.find_recursive("server")
        if servers:
            return servers[0]
        for child in root.children:
            if child.name != "http":
                return child
        return None
