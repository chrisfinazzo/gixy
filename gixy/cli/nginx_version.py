"""Resolve an explicitly requested local NGINX identity at the CLI boundary."""

import logging
import subprocess  # nosec B404 - explicit local CLI opt-in only.

from gixy.core.nginx_flavors import parse_banner
from gixy.core.nginx_version import parse_oss


LOG = logging.getLogger(__name__)


def probe_nginx():
    """Run the local binary with bounded execution and disconnected stdin.

    Returns:
        subprocess.CompletedProcess: Captured text output and exit status.

    Raises:
        OSError: If the executable cannot be started.
        subprocess.TimeoutExpired: If it exceeds five seconds.
    """
    return subprocess.run(  # noqa: UP022  # nosec B603 B607 - opt-in nginx from PATH.
        ["nginx", "-V"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        timeout=5,
        check=False,
    )


def resolve_identity(version, flavor, definitions):
    """Resolve auto once while keeping failed auto distinct from absent input.

    Args:
        version (str or None): Shared version setting, including opt-in auto.
        flavor (str or None): Explicit flavor override.
        definitions (dict): Validated bundled flavor records.

    Returns:
        tuple: Version setting and resolved flavor; failed auto stays auto.
    """
    if version != "auto":
        if parse_oss(version) is not None:
            LOG.info(
                "Resolved NGINX version %s, flavor %s", version, flavor or "upstream"
            )
        return version, flavor
    try:
        result = probe_nginx()
    except (OSError, subprocess.TimeoutExpired, UnicodeError) as error:
        LOG.warning(
            "Cannot detect NGINX with nginx -V: %s; version remains unknown", error
        )
        return version, flavor
    if result.returncode != 0:
        LOG.warning(
            "Cannot detect NGINX: nginx -V exited with status %s; version remains unknown",
            result.returncode,
        )
        return version, flavor
    identity = parse_banner(result.stderr + "\n" + result.stdout, definitions)
    if identity is None:
        LOG.warning(
            "Cannot detect NGINX: nginx -V has no valid version banner; version remains unknown"
        )
        return version, flavor
    detected_version, detected_flavor = identity
    resolved_flavor = flavor if flavor is not None else detected_flavor
    LOG.info("Resolved NGINX version %s, flavor %s", detected_version, resolved_flavor)
    return detected_version, resolved_flavor
