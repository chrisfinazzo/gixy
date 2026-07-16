"""Module for low_keepalive_requests plugin."""

import gixy
from gixy.plugins.plugin import Plugin


class low_keepalive_requests(Plugin):
    """
    Insecure example:
        keepalive_requests 100;
    """

    summary = "The keepalive_requests directive should be at least 1000."
    severity = gixy.severity.LOW
    description = (
        "The keepalive_requests directive should be at least 1000. Any value "
        "lower than this may result in client disconnections."
    )
    directives = ["keepalive_requests"]

    def audit(self, directive):
        if not directive.args:
            return
        try:
            value = int(directive.args[0])
        except (ValueError, TypeError, IndexError):
            return
        if value < 1000:
            self.add_issue(
                severity=self.severity,
                directive=[directive],
                reason="The keepalive_requests directive should be at least 1000.",
                fixes=[
                    self.make_fix(
                        title="Set keepalive_requests to 1000",
                        search=f"keepalive_requests {value}",
                        replace="keepalive_requests 1000",
                        description="Set to minimum recommended value",
                    ),
                    self.make_fix(
                        title="Set keepalive_requests to 10000",
                        search=f"keepalive_requests {value}",
                        replace="keepalive_requests 10000",
                        description="Higher value for high-traffic sites",
                    ),
                ],
            )
