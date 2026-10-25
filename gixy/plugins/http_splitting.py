import gixy
from gixy.core.context import get_context
from gixy.core.variable import EXTRACT_RE, compile_script
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
            if (
                directive.name == "proxy_pass"
                and var.name in ("uri", "document_uri")
                and _proxy_uri_safe(directive, "\n")
                and _proxy_uri_safe(directive, "\r")
            ):
                continue
            char = ""
            if var.can_contain("\n"):
                char = "\\n"
            elif not server_side and var.can_contain("\r"):
                char = "\\r"
            else:
                continue
            reason = f'At least variable "${var.name}" can contain "{char}"'
            self.add_issue(directive=[directive] + var.providers, reason=reason)


def _replacement_safe(replacement, char, current_safe):
    """Prove a rewrite replacement excludes one dangerous character."""
    for index, piece in enumerate(EXTRACT_RE.split(replacement)):
        if index % 2 == 0:
            if char in piece:
                return False
            continue
        name = piece.strip("{}\x20").lower()
        if name in ("uri", "document_uri"):
            if not current_safe:
                return False
        elif name == "request_uri":
            source = get_context().get_var(name)
            if source is None or source.can_contain(char):
                return False
        else:
            # Captures, unknown variables, and query arguments need a wider
            # interpreter; none can establish a safety proof here.
            return False
    return True


def _proxy_uri_safe(directive, char):
    """Prove every local rewrite path reaching this proxy has a safe URI."""
    location = directive.parent
    if location is None or location.name != "location":
        return False

    # (safe alphabet, rewrite phase stopped by break, pending implicit redirect)
    states = {(False, False, False)}
    for node in location.children:
        if node.name == "rewrite":
            next_states = set()
            for safe, stopped, pending in states:
                if stopped:
                    next_states.add((safe, stopped, pending))
                    continue
                # Only '^' is proven to match every URI. Other patterns have
                # both match and nonmatch paths without executing the regex.
                if node.pattern != "^":
                    next_states.add((safe, False, pending))
                replacement_safe = _replacement_safe(node.replace, char, safe)
                if node.flag in ("redirect", "permanent"):
                    continue
                if node.flag == "last":
                    next_states.add((False, True, True))
                elif node.flag == "break":
                    next_states.add((replacement_safe, True, False))
                elif node.flag is None:
                    next_states.add((replacement_safe, False, True))
                else:
                    next_states.add((False, False, True))
            states = next_states
        elif node.name == "return":
            states = {state for state in states if state[1]}
        elif (
            node.name in ("if", "try_files", "error_page")
            or node.name.startswith(("rewrite_by_", "access_by_"))
            or (node.name == "set" and node.variable in ("uri", "document_uri"))
        ):
            states = {(False, stopped, pending) for _, stopped, pending in states}

    return all(safe and not pending for safe, _, pending in states)


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
