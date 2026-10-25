"""
Plugin to detect weak SSL/TLS configurations in NGINX.

Checks for:
- Outdated protocols (SSLv2, SSLv3, TLSv1, TLSv1.1)
- Weak cipher suites
- Unnecessary ssl_prefer_server_ciphers on
"""

import re

import gixy
from gixy.plugins.plugin import Plugin

# Protocols considered insecure
INSECURE_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

# Weak ciphers that should be avoided
# Based on: https://wiki.mozilla.org/Security/Server_Side_TLS
WEAK_CIPHERS = {
    # Export ciphers (40-bit, 56-bit)
    "EXP",
    "EXPORT",
    "EXPORT40",
    "EXPORT56",
    # NULL ciphers (no encryption)
    "NULL",
    "eNULL",
    "aNULL",
    # DES and 3DES (weak)
    "DES",
    "3DES",
    "DES-CBC3",
    # RC4 (broken)
    "RC4",
    # MD5 (weak hash)
    "MD5",
    # Anonymous ciphers (no authentication)
    "ADH",
    "AECDH",
    # Low-grade ciphers
    "LOW",
    # Medium-grade ciphers (still weak by modern standards)
    "MEDIUM",
    # Camellia (less reviewed than AES)
    "CAMELLIA",
    # SEED (rarely used, less reviewed)
    "SEED",
    # IDEA (old)
    "IDEA",
    # Single DES
    "DES-CBC-SHA",
    # SSLv2 ciphers
    "SSLv2",
}

# Patterns that indicate weak cipher configuration
WEAK_CIPHER_PATTERNS = [
    # Allowing all ciphers
    "ALL",
    "DEFAULT",
    # Specific weak cipher suites
    "RC4-SHA",
    "RC4-MD5",
    "DES-CBC-SHA",
    "DES-CBC3-SHA",
    "DHE-RSA-DES-CBC3-SHA",
    "DHE-RSA-CAMELLIA128-SHA",
    "ECDHE-RSA-CAMELLIA128-SHA",
    "EXPORT",
    "EXP-",
    "NULL-",
    "ADH-",
    "AECDH-",
]

# Representative weak suites provide finite witnesses for selector algebra.
# They are names from the documented OpenSSL grammar, not a probe of the host
# build; a cipher absent from the host library must not make a scan pass.
_WEAK_REPRESENTATIVES = (
    "DES-CBC3-SHA",
    "DES-CBC-SHA",
    "ADH-AES128-SHA",
    "AECDH-AES128-SHA",
    "NULL-SHA",
    "CAMELLIA128-SHA",
    "CAMELLIA256-SHA",
    "RC4-SHA",
    "SEED-SHA",
    "IDEA-CBC-SHA",
    "EXP-RC4-MD5",
)

_WEAK_ALIASES = {
    "ALL",
    "DEFAULT",
    "EXP",
    "EXPORT",
    "EXPORT40",
    "EXPORT56",
    "NULL",
    "ENULL",
    "ANULL",
    "DES",
    "3DES",
    "DES-CBC3",
    "RC4",
    "MD5",
    "ADH",
    "AECDH",
    "LOW",
    "MEDIUM",
    "CAMELLIA",
    "SEED",
    "IDEA",
    "SSLV2",
    "CAMELLIA128",
    "CAMELLIA256",
}

_STRONG_CONCRETE = re.compile(
    r"^(?:(?:ECDHE|DHE)-(?:RSA|ECDSA)-)?"
    r"(?:(?:AES128|AES256)(?:-GCM)?-SHA(?:256|384)?|"
    r"CHACHA20-POLY1305)$"
)


def _known_empty_intersection(selectors):
    """Recognize intersections of mutually exclusive encryption families."""
    families = set()
    for selector in selectors:
        name = selector.upper()
        if name.startswith("AES"):
            families.add("AES")
        elif name.startswith("CAMELLIA"):
            families.add("CAMELLIA")
        elif name in ("3DES", "DES-CBC3"):
            families.add("3DES")
        elif name in ("ENULL", "NULL"):
            families.add("NULL")
        elif name in ("RC4", "SEED", "IDEA"):
            families.add(name)
    return len(families) > 1


def _concrete_suite(name):
    """Recognize concrete suites with known strong or weak memberships."""
    upper = name.upper()
    return bool(_STRONG_CONCRETE.fullmatch(upper)) or (
        "-" in upper and upper not in _WEAK_ALIASES and _weak_name(upper)
    )


def _unsupported_aes_digest_suite(name):
    """Reject concrete AES names with an undocumented numeric SHA suffix."""
    match = re.fullmatch(
        r"(?:(?:ECDHE|DHE)-(?:RSA|ECDSA)-)?AES(?:128|256)" r"(?:-GCM)?-SHA([0-9]+)",
        name.upper(),
    )
    return match is not None and match.group(1) not in ("256", "384", "512")


def _known_strong_intersection(selectors):
    """Prove authenticated ephemeral DH plus AES excludes modeled weak families."""
    names = {selector.upper() for selector in selectors}
    encryption = {"AES128", "AES256", "AESGCM"}
    authenticated = {"EDH", "DHE", "EECDH", "ECDHE"}
    return (
        bool(names & encryption)
        and bool(names & authenticated)
        and names <= (encryption | authenticated)
    )


def _selector_covers_positive(selector, positive):
    """Prove an exclusion covers a whole symbolic positive selector."""
    if selector == positive:
        return True
    if selector == "ALL":
        return positive in _WEAK_ALIASES - {"ENULL", "NULL"} or positive in (
            "AES",
            "AES128",
            "AES256",
        )
    supersets = {
        "ANULL": {"ADH", "AECDH"},
        "ENULL": {"NULL"},
        "NULL": {"ENULL"},
        "CAMELLIA": {"CAMELLIA128", "CAMELLIA256"},
        "AES": {"AES128", "AES256"},
        "3DES": {"DES-CBC3"},
    }
    return positive in supersets.get(selector, set())


def _weak_name(name):
    """Classify a documented weak selector or concrete suite name."""
    upper = name.upper()
    if upper in _WEAK_ALIASES:
        return True
    if upper in _WEAK_REPRESENTATIVES:
        return True
    return bool(
        re.search(
            r"(^|-)ADH-|(^|-)AECDH-|(^|-)NULL-|(^|-)RC4-|"
            r"(^|-)CAMELLIA[0-9]*-|(^|-)DES-CBC3-|(^|-)DES-CBC-|"
            r"(^|-)SEED-|(^|-)IDEA-|(^|-)EXP-|[-]MD5$",
            upper,
        )
    )


def _selector_matches(selector, suite):
    """Return True, False, or None for unsupported selector membership."""
    selector = selector.upper()
    suite = suite.upper()
    if suite.startswith("?"):
        positives = suite[1:].split("+")
        if any(_selector_covers_positive(selector, part) for part in positives):
            return True
        if selector == "ALL" and any(part in ("ENULL", "NULL") for part in positives):
            return False
        return None
    if selector == suite:
        return True
    if selector == "ALL":
        # ALL contains every suite except eNULL; DEFAULT is a subset of ALL.
        return suite not in ("ENULL", "NULL-SHA") and not suite.startswith("NULL-")
    if selector == "DEFAULT":
        return None  # Build defaults and unsupported families vary.
    if suite in ("ALL", "DEFAULT"):
        return None
    if selector in ("ANULL", "ADH", "AECDH"):
        families = {
            "ADH": suite.startswith("ADH-"),
            "AECDH": suite.startswith("AECDH-"),
        }
        return any(families.values()) if selector == "ANULL" else families[selector]
    if selector in ("ENULL", "NULL"):
        return suite.startswith("NULL-") or "-NULL-" in suite
    if selector in ("3DES", "DES-CBC3"):
        return "DES-CBC3-" in suite
    if selector == "DES":
        return "DES-CBC-" in suite
    if selector in ("CAMELLIA", "CAMELLIA128", "CAMELLIA256"):
        return selector in suite
    if selector in ("AES", "AES128", "AES256"):
        return selector in suite
    if selector == "AESGCM":
        return "-AES128-GCM-" in suite or "-AES256-GCM-" in suite
    if selector in ("KRSA", "RSA", "ARSA"):
        return suite.startswith(
            ("NULL-", "DES-CBC", "CAMELLIA", "RC4-", "SEED-", "IDEA-")
        )
    if selector in ("KDHE", "KEDH", "DH"):
        return suite.startswith(("ADH-", "DHE-"))
    if selector in ("KECDHE", "KEECDH", "ECDH"):
        return suite.startswith(("AECDH-", "ECDHE-"))
    if selector in ("EDH", "DHE"):
        return suite.startswith("DHE-")
    if selector in ("EECDH", "ECDHE"):
        return suite.startswith("ECDHE-")
    if selector in ("RC4", "SEED", "IDEA", "MD5"):
        return selector in suite
    if selector in ("EXP", "EXPORT", "EXPORT40", "EXPORT56"):
        return suite.startswith("EXP-")
    if selector in ("LOW", "MEDIUM", "SSLV2"):
        return None
    # Concrete suite selectors are exact; an unknown alias cannot prove
    # deletion or intersection of a weak suite.
    if "-" in selector:
        return selector == suite
    return None


def _expression_matches(selectors, suite):
    """Evaluate OpenSSL's interior ``+`` intersection conservatively."""
    matches = [_selector_matches(selector, suite) for selector in selectors]
    if False in matches:
        return False
    if None in matches:
        return None
    return True


def _weak_enabled(expression):
    """Track weak cipher witnesses through ordered OpenSSL list commands."""
    enabled = set()
    banned = []
    for command in re.split(r"[:,\s]+", expression):
        if not command or command.startswith("@"):
            continue
        operator = command[0] if command[0] in "!-+" else ""
        body = command[1:] if operator else command
        selectors = [part for part in body.split("+") if part]
        if not selectors:
            continue
        if operator in ("!", "-"):
            enabled = {
                suite
                for suite in enabled
                if _expression_matches(selectors, suite) is not True
            }
            if operator == "!":
                banned.append(selectors)
            continue
        if operator == "+":
            continue  # Reorder only; never enable a new cipher.
        if len(selectors) == 1 and _unsupported_aes_digest_suite(selectors[0]):
            continue

        concrete_expression = all(_concrete_suite(part) for part in selectors)
        if concrete_expression and len({part.upper() for part in selectors}) > 1:
            continue  # Distinct concrete suites cannot intersect.

        candidates = set(_WEAK_REPRESENTATIVES)
        candidates.update(
            part.upper()
            for part in selectors
            if _weak_name(part) and part.upper() not in _WEAK_ALIASES
        )
        # A representative list alone cannot prove a broad selector safe.
        # Keep an opaque weak possibility unless the positive expression is a
        # recognized strong concrete suite or an impossible intersection.
        if (
            not _known_empty_intersection(selectors)
            and not _known_strong_intersection(selectors)
            and not concrete_expression
        ):
            candidates.add("?" + "+".join(part.upper() for part in selectors))
        for suite in candidates:
            if _expression_matches(selectors, suite) is not True:
                continue
            if any(_expression_matches(ban, suite) is True for ban in banned):
                continue
            enabled.add(suite)
    return sorted(enabled)


class weak_ssl_tls(Plugin):
    """
    Detects weak SSL/TLS configurations that may compromise security.

    Checks ssl_protocols, ssl_ciphers, ssl_prefer_server_ciphers,
    and basic server-level TLS hardening.
    """

    summary = "Weak SSL/TLS configuration detected"
    severity = gixy.severity.HIGH
    description = (
        "Using outdated TLS protocols (TLSv1.0, TLSv1.1) or weak cipher suites "
        "exposes your server to attacks such as POODLE, BEAST, and SWEET32. "
        "Modern configurations should use TLSv1.2+ with strong AEAD ciphers."
    )
    directives = ["ssl_protocols", "ssl_ciphers", "ssl_prefer_server_ciphers"]
    supports_full_config = True

    # Protocols where ssl_ciphers has no effect (uses SSL_CTX_set_ciphersuites instead)
    TLS13_AND_ABOVE = {"TLSv1.3"}

    def audit(self, directive):
        """Audit individual SSL/TLS directives."""
        if directive.name == "ssl_protocols":
            self._check_protocols(directive)
        elif directive.name == "ssl_ciphers":
            self._check_ciphers(directive)
        elif directive.name == "ssl_prefer_server_ciphers":
            self._check_prefer_server_ciphers(directive)

    def _get_effective_protocols(self, block):
        """Get effective ssl_protocols from block or its parent.

        Returns:
            Set of protocol strings, or None if no ssl_protocols found.
        """
        protocols_dir = block.some("ssl_protocols")
        if protocols_dir:
            return set(protocols_dir.args)
        if block.parent:
            protocols_dir = block.parent.some("ssl_protocols")
            if protocols_dir:
                return set(protocols_dir.args)
        return None

    def _is_tls13_only(self, protocols):
        """Return True if only TLSv1.3 (or higher) is configured.

        Args:
            protocols: Set of protocol strings, or None.

        Returns:
            True if all configured protocols are TLSv1.3+.
        """
        if not protocols:
            return False
        return protocols.issubset(self.TLS13_AND_ABOVE)

    def _check_protocols(self, directive):
        """Check for insecure protocols in ssl_protocols directive."""
        protocols = set(directive.args)
        insecure_found = protocols & INSECURE_PROTOCOLS

        if insecure_found:
            # Build fix - remove insecure protocols
            current_protocols = " ".join(directive.args)
            secure_protocols = protocols - INSECURE_PROTOCOLS

            # If no secure protocols remain, suggest TLSv1.2 TLSv1.3
            if not secure_protocols:
                secure_protocols = {"TLSv1.2", "TLSv1.3"}  # noqa: F841

            self.add_issue(
                severity=gixy.severity.HIGH,
                directive=[directive, directive.parent],
                summary="Insecure TLS protocols enabled",
                reason=f"Insecure protocols enabled: {', '.join(sorted(insecure_found))}. "
                "TLSv1.0 and TLSv1.1 are vulnerable to POODLE, BEAST, and other attacks.",
                fixes=[
                    self.make_fix(
                        title="Use only TLSv1.2 and TLSv1.3",
                        search=f"ssl_protocols {current_protocols}",
                        replace="ssl_protocols TLSv1.2 TLSv1.3",
                        description="Remove insecure protocols and use only modern TLS",
                    ),
                ],
            )

    def _check_ciphers(self, directive):
        """Check for weak ciphers in ssl_ciphers directive."""
        # ssl_ciphers only affects TLSv1.2 and below (SSL_CTX_set_cipher_list).
        # TLSv1.3 ciphersuites are controlled via ssl_conf_command Ciphersuites.
        if self._is_tls13_only(self._get_effective_protocols(directive.parent)):
            return

        cipher_string = directive.args[0] if directive.args else ""

        weak_found = _weak_enabled(cipher_string)

        if weak_found:
            opaque = [value[1:] for value in weak_found if value.startswith("?")]
            concrete = [value for value in weak_found if not value.startswith("?")]
            # Mozilla Intermediate compatibility cipher suite
            modern_ciphers = (
                "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
                "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
                "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
                "DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384"
            )

            self.add_issue(
                severity=gixy.severity.HIGH,
                directive=[directive, directive.parent],
                summary=(
                    "Weak SSL/TLS ciphers enabled"
                    if concrete
                    else "Possibly weak SSL/TLS cipher selection"
                ),
                reason=(
                    "Weak cipher witnesses: " + ", ".join(concrete[:5]) + ". "
                    if concrete
                    else ""
                )
                + (
                    "Possible weak selection from unresolved selectors: "
                    + ", ".join(opaque[:5])
                    + ". "
                    if opaque
                    else ""
                )
                + "Review the resulting cipher list against the target OpenSSL build.",
                fixes=[
                    self.make_fix(
                        title="Use Mozilla Intermediate cipher suite",
                        search=f"ssl_ciphers {cipher_string}",
                        replace=f"ssl_ciphers {modern_ciphers}",
                        description="Use Mozilla's recommended intermediate cipher suite",
                    ),
                ],
            )

    def _has_prioritize_chacha(self, block):
        """Check if PrioritizeChaCha is configured via ssl_conf_command.

        Args:
            block: The directive's parent block to search in.

        Returns:
            True if ssl_conf_command Options PrioritizeChaCha is found.
        """
        for ctx in (block, block.parent) if block.parent else (block,):
            if ctx is None:
                continue
            for d in ctx.find("ssl_conf_command"):
                if (
                    len(d.args) >= 2
                    and d.args[0] == "Options"
                    and d.args[1] == "PrioritizeChaCha"
                ):
                    return True
        return False

    def _check_prefer_server_ciphers(self, directive):
        """Check if ssl_prefer_server_ciphers is unnecessarily enabled."""
        if directive.args and directive.args[0] == "on":
            # PrioritizeChaCha achieves the same goal — server controls order
            # but defers to ChaCha-preferring clients (SSL_OP_PRIORITIZE_CHACHA)
            if self._has_prioritize_chacha(directive.parent):
                return
            self.add_issue(
                severity=gixy.severity.LOW,
                directive=[directive, directive.parent],
                summary="Server cipher preference enabled unnecessarily",
                reason="ssl_prefer_server_ciphers is on, forcing server cipher order. "
                "With modern cipher lists (all strong AEAD ciphers), client cipher preference "
                "improves performance — mobile clients without AES-NI benefit from choosing "
                "ChaCha20-Poly1305 over AES-GCM. Mozilla and nginx maintainers recommend off. "
                "If you must keep server preference (policy, compliance), add "
                "`ssl_conf_command Options PrioritizeChaCha;` so the server order still "
                "defers to clients that put ChaCha20-Poly1305 first.",
                fixes=[
                    self.make_fix(
                        title="Disable server cipher preference",
                        search="ssl_prefer_server_ciphers on",
                        replace="ssl_prefer_server_ciphers off",
                        description="Let clients choose the most efficient cipher",
                    ),
                    self.make_fix(
                        title="Keep server preference but prioritise ChaCha20",
                        search="ssl_prefer_server_ciphers on;",
                        replace="ssl_prefer_server_ciphers on;\n    ssl_conf_command Options PrioritizeChaCha;",
                        description=(
                            "SSL_OP_PRIORITIZE_CHACHA lets AES-NI-less clients still "
                            "get ChaCha20-Poly1305 while the server keeps ordering "
                            "everything else (nginx 1.19.4+, OpenSSL 1.1.1+)"
                        ),
                    ),
                ],
            )

    def post_audit(self, root):
        """Check for missing SSL configurations in HTTPS servers."""
        # Find http block
        http_block = None
        for child in root.children:
            if child.name == "http":
                http_block = child
                break

        if not http_block:
            return

        # Check each server block that has SSL enabled
        for server_block in http_block.find_all_contexts_of_type("server"):
            # Check if this is an SSL server
            has_ssl = False
            for listen_dir in server_block.find("listen"):
                listen_args = " ".join(listen_dir.args)
                if "ssl" in listen_args or "443" in listen_args:
                    has_ssl = True
                    break

            if not has_ssl:
                continue

            # Check for missing ssl_protocols at server level
            # (only if not set at http level)
            http_protocols = http_block.some("ssl_protocols")
            server_protocols = server_block.some("ssl_protocols")

            if not http_protocols and not server_protocols:
                self.add_issue(
                    severity=gixy.severity.MEDIUM,
                    directive=[server_block],
                    summary="Missing ssl_protocols directive",
                    reason="No ssl_protocols directive found. Default may include insecure protocols.",
                    fixes=[
                        self.make_fix(
                            title="Add ssl_protocols TLSv1.2 TLSv1.3",
                            search="server {",
                            replace="server {\n    ssl_protocols TLSv1.2 TLSv1.3;",
                            description="Explicitly set secure TLS protocols",
                        ),
                    ],
                )

            # Check for missing ssl_ciphers
            # Skip if TLSv1.3-only — ssl_ciphers is irrelevant
            effective_protocols = self._get_effective_protocols(server_block)
            if effective_protocols is None and http_protocols:
                effective_protocols = set(http_protocols.args)
            if self._is_tls13_only(effective_protocols):
                continue

            http_ciphers = http_block.some("ssl_ciphers")
            server_ciphers = server_block.some("ssl_ciphers")

            if not http_ciphers and not server_ciphers:
                self.add_issue(
                    severity=gixy.severity.MEDIUM,
                    directive=[server_block],
                    summary="Missing ssl_ciphers directive",
                    reason="No ssl_ciphers directive found. Default cipher suite may include weak ciphers.",
                    fixes=[
                        self.make_fix(
                            title="Add modern ssl_ciphers",
                            search="server {",
                            replace=(
                                "server {\n    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:"
                                "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:"
                                "ECDHE-RSA-AES256-GCM-SHA384;"
                            ),
                            description="Add Mozilla Intermediate cipher suite",
                        ),
                    ],
                )

            # HSTS checks are handled by the dedicated `hsts_header` plugin.
