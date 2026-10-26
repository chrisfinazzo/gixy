import logging

import gixy
from gixy.core.nginx_flavors import load_definitions
from gixy.core.nginx_version import parse_oss


LOG = logging.getLogger(__name__)


class Config:
    def __init__(
        self,
        plugins=None,
        skips=None,
        severity=gixy.severity.UNSPECIFIED,
        output_format=None,
        output_file=None,
        allow_includes=True,
        vars_dirs=None,
        load_default_vars=False,
        nginx_version=None,
        nginx_flavor=None,
    ):
        self.severity = severity
        self.output_format = output_format
        self.output_file = output_file
        self.plugins = plugins
        self.skips = skips
        self.allow_includes = allow_includes
        self.vars_dirs = vars_dirs
        self.load_default_vars = load_default_vars
        self.nginx_flavor = nginx_flavor
        self.resolved_nginx_flavor = (
            nginx_flavor if nginx_flavor is not None else "upstream"
        )
        self._nginx_flavors = load_definitions()
        if (
            not isinstance(self.resolved_nginx_flavor, str)
            or self.resolved_nginx_flavor not in self._nginx_flavors
        ):
            raise ValueError(f"Unknown NGINX flavor: {nginx_flavor!r}")
        self.nginx_version = nginx_version
        self.resolved_nginx_version = parse_oss(nginx_version)
        self.plugins_options = {}

    def set_for(self, name, options):
        self.plugins_options[name] = options
        if name == "nginx_cves" and self.nginx_version is None:
            self.resolved_nginx_version = parse_oss(options.get("version"))

    def get_for(self, name):
        if self.has_for(name):
            return self.plugins_options[name]
        return {}

    def has_for(self, name):
        return name in self.plugins_options

    def nginx_has_fix(self, key):
        """Check an exact check/CVE key against the selected flavor's fix.

        Args:
            key (str): Exact check name or CVE ID.

        Returns:
            bool: Whether a recorded fix covers the known advertised version.
        """
        fix = self._nginx_flavors[self.resolved_nginx_flavor]["fixed_in"].get(key)
        if fix is None or self.resolved_nginx_version is None:
            return False
        if self.resolved_nginx_version < parse_oss(fix["version"]):
            return False
        LOG.debug(
            "Applying NGINX flavor %s fix for %s at %s (sources: %s)",
            self.resolved_nginx_flavor,
            key,
            fix["version"],
            ", ".join(fix["sources"]),
        )
        return True
