"""
Plugin to detect missing or weak HSTS configuration in NGINX.

Checks for:
- Missing Strict-Transport-Security header on HTTPS servers
- Weak Strict-Transport-Security max-age values
"""

import re

import gixy
from gixy.plugins.plugin import Plugin


class hsts_header(Plugin):
    """
    Detects missing or weak HSTS configuration.

    HSTS (HTTP Strict Transport Security) is delivered via the
    Strict-Transport-Security response header and instructs browsers to only
    use HTTPS for a given host for a period of time.
    """

    summary = "Missing or weak HSTS configuration detected"
    severity = gixy.severity.MEDIUM
    description = (
        "HSTS (Strict-Transport-Security) helps protect users against protocol "
        "downgrade attacks and cookie hijacking by forcing browsers to use HTTPS "
        "for a host once it has been seen over HTTPS."
    )
    directives = []
    supports_full_config = True

    def audit(self, directive):
        return

    def post_audit(self, root):
        # Find http block
        http_block = None
        for child in root.children:
            if child.name == "http":
                http_block = child
                break

        if not http_block:
            return

        http_add_headers = list(http_block.find("add_header"))

        for server_block in http_block.find_all_contexts_of_type("server"):
            if not self._server_has_ssl(server_block):
                continue

            # Servers rejecting the TLS handshake cannot emit HTTP response headers.
            if self._server_rejects_handshake(server_block):
                continue

            server_add_headers = list(server_block.find("add_header"))

            # Best-effort inheritance: if server defines any add_header directives,
            # treat those as authoritative; otherwise fall back to http-level.
            effective_add_headers = (
                server_add_headers if server_add_headers else http_add_headers
            )

            self._check_hsts(server_block, http_block, effective_add_headers)

    def _server_has_ssl(self, server_block):
        for listen_dir in server_block.find("listen"):
            listen_args = " ".join(listen_dir.args)
            if "ssl" in listen_args or "443" in listen_args:
                return True
        return False

    def _server_rejects_handshake(self, server_block):
        ssl_reject = server_block.some("ssl_reject_handshake")
        return bool(ssl_reject and ssl_reject.args and ssl_reject.args[0] == "on")

    def _has_security_headers_module(self, server_block, http_block):
        """Check if security_headers directive is enabled in server or http block."""
        for block in (server_block, http_block):
            if block is None:
                continue
            directive = block.some("security_headers")
            if directive and directive.args and directive.args[0] == "on":
                return True
        return False

    def _has_more_set_headers_hsts(self, server_block, http_block):
        """Check if more_set_headers sets Strict-Transport-Security in server or http block."""
        for block in (server_block, http_block):
            if block is None:
                continue
            for directive in block.find("more_set_headers"):
                for header_name in directive.headers:
                    if header_name.lower() == "strict-transport-security":
                        return True
        return False

    def _check_hsts(self, server_block, http_block, add_headers):
        # Skip if security_headers module or more_set_headers provides HSTS
        if self._has_security_headers_module(server_block, http_block):
            return
        if self._has_more_set_headers_hsts(server_block, http_block):
            return

        hsts_directive = None
        for add_header in add_headers:
            if (
                add_header.args
                and add_header.args[0].lower() == "strict-transport-security"
            ):
                hsts_directive = add_header
                break

        if not hsts_directive:
            self.add_issue(
                severity=gixy.severity.MEDIUM,
                directive=[server_block],
                summary="Missing HSTS header",
                reason="No Strict-Transport-Security header found. "
                "HSTS protects against protocol downgrade attacks and cookie hijacking.",
                fixes=[
                    self.make_fix(
                        title="Add HSTS header",
                        search="server {",
                        replace=(
                            "server {\n    add_header Strict-Transport-Security "
                            '"max-age=31536000; includeSubDomains" always;'
                        ),
                        description="Add HSTS header with 1 year max-age",
                    ),
                ],
            )
            return

        if len(hsts_directive.args) < 2:
            return

        # Evaluate max-age quality (best-effort parsing)
        hsts_value = hsts_directive.args[1].lower()
        match = re.search(r"max-age=(\d+)", hsts_value)
        if not match:
            return

        try:
            max_age = int(match.group(1))
        except ValueError:
            return

        # Less than 6 months is considered weak
        if max_age < 15768000:
            self.add_issue(
                severity=gixy.severity.LOW,
                directive=[hsts_directive, server_block],
                summary="HSTS max-age too short",
                reason=f"HSTS max-age is {max_age} seconds ({max_age // 86400} days). "
                "Recommended minimum is 6 months (15768000 seconds).",
                fixes=[
                    self.make_fix(
                        title="Set HSTS max-age to 1 year",
                        search=f"max-age={max_age}",
                        replace="max-age=31536000",
                        description="Use 1 year (31536000 seconds) for HSTS max-age",
                    ),
                ],
            )
