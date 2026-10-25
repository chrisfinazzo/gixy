import gixy
from gixy.core.variable import compile_script
from gixy.plugins.plugin import Plugin


class http_splitting(Plugin):
    r"""
    Insecure examples:
        rewrite ^ http://$host$uri;
        return 301 http://$host$uri;
        proxy_set_header "X-Original-Uri" $uri;
        proxy_pass http://upstream$document_uri;

        location ~ /proxy/(a|b)/(\W*)$ {
            set $path $2;
            proxy_pass http://storage/$path;
        }
    """

    summary = "Possible HTTP-Splitting vulnerability."
    severity = gixy.severity.HIGH
    description = (
        'Using variables that can contain "\\n" or "\\r" may lead to http injection.'
    )
    directives = ["rewrite", "return", "add_header", "proxy_set_header", "proxy_pass"]

    def audit(self, directive):
        value = _get_value(directive)
        if not value:
            if directive.name == "return" and len(directive.args) == 2:
                # Keep ordinary script resolution diagnostics for body values.
                compile_script(directive.args[1])
            return

        server_side = directive.name.startswith("proxy_")
        for var in compile_script(value):
            char = ""
            if var.can_contain("\n"):
                char = "\\n"
            elif not server_side and var.can_contain("\r"):
                char = "\\r"
            else:
                continue
            reason = f'At least variable "${var.name}" can contain "{char}"'
            self.add_issue(directive=[directive] + var.providers, reason=reason)


def _get_value(directive):
    if directive.name == "return":
        # ngx_http_rewrite_return accepts URL/$scheme shorthand as 302.
        # ngx_http_send_response sets Location only for these five statuses;
        # every other return value is response body data, not a header sink.
        if len(directive.args) == 1:
            value = directive.args[0]
            return (
                value if value.startswith(("http://", "https://", "$scheme")) else None
            )
        if len(directive.args) == 2 and directive.args[0].lstrip("0") in (
            "301",
            "302",
            "303",
            "307",
            "308",
        ):
            return directive.args[1]
        return None
    if directive.name == "proxy_pass" and len(directive.args) >= 1:
        return directive.args[0]
    elif len(directive.args) >= 2:
        return directive.args[1]
    return None
