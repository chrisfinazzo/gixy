#!/usr/bin/env python3
"""Kill bounded variable-policy mutations in isolated temporary source copies.

Run with the project's Python interpreter. This is focused acceptance coverage,
not a general mutation framework; it never edits the live checkout.
"""

import ast
import os
from pathlib import Path
import re
import shutil
import subprocess  # nosec B404 - invoke only this interpreter and pytest.
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
TESTS = [
    "tests/core/test_module_variables.py",
    "tests/plugins/test_http_splitting_return_sinks.py",
]
# Name, source path, exact original/replacement, selected existing regression.
MUTATIONS = [
    (
        "remove-registration",
        "gixy/core/manager.py",
        "for var in node.declared_variables:",
        "for var in []:",
        "test_reported_two_locations",
    ),
    (
        "opaque-becomes-trusted",
        "gixy/directives/block.py",
        "Variable(child.name[1:].lower(), Regexp(pattern), provider=child)",
        "Variable(child.name[1:].lower(), None, provider=child, have_script=False)",
        "test_geoip_alias_models",
    ),
    (
        "first-duplicate-wins",
        "gixy/core/manager.py",
        "selected = aliases[-1]",
        "selected = aliases[0]",
        "test_final_geoip_duplicate_visible_before_between_after",
    ),
    (
        "ignore-provider-collision",
        "gixy/core/manager.py",
        "if competitors:",
        "if False:",
        "test_cross_provider_collision_conservative",
    ),
    (
        "scope-leak",
        "gixy/core/manager.py",
        "if directive.self_context:\n                    pop_context()",
        "if False:\n                    pop_context()",
        "test_http_stream_sibling_and_local_override_isolation",
    ),
    (
        "audit-override-leak",
        "gixy/core/manager.py",
        "self._declaration_overrides = {}\n        purge_context()",
        "purge_context()",
        "test_repeated_audits_and_parse_failure_clear_declarations",
    ),
    (
        "expand-invalid-inner-include",
        "gixy/parser/nginx_parser.py",
        'if parent.name == "geoip2":',
        "if False:",
        "test_invalid_inner_include_never_resolves_file",
    ),
    (
        "suppress-dynamic-resolver",
        "gixy/plugins/missing_resolver.py",
        "if literal is None:\n                return host_str",
        "if literal is None:\n                return None",
        "test_dynamic_map_nested_resolver",
    ),
    (
        "return-body-is-header",
        "gixy/plugins/http_splitting.py",
        'if directive.name == "return":',
        "if False:",
        "test_only_redirect_return_values_are_splitting_sinks",
    ),
    (
        "lose-lua-block-header",
        "gixy/parser/raw_parser.py",
        '"args": args[:-1],',
        '"args": [],',
        "test_raw_lua_header_body_and_content_contract",
    ),
]


def run_tests(directory, selector=None):
    """Run observed assertions with a bounded, clean subprocess environment."""
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    command = [sys.executable, "-m", "pytest"] + TESTS + ["-q", "--tb=line"]
    if selector:
        command += ["-k", selector]
    return subprocess.run(  # noqa: UP022  # nosec B603 - fixed interpreter/test paths.
        command,
        cwd=str(directory),
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
        timeout=30,
    )


def main():
    """Require a green baseline and assertion failures for every explicit mutant."""
    with tempfile.TemporaryDirectory(prefix="gixy-module-mutations-") as temporary:
        work = Path(temporary)
        for name in ("gixy", "tests"):
            shutil.copytree(
                str(ROOT / name),
                str(work / name),
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
            )
        baseline = run_tests(work)
        if (
            baseline.returncode != 0
            or re.search(r"\b[1-9][0-9]* passed\b", baseline.stdout) is None
        ):
            print("ERROR baseline did not pass\n" + baseline.stdout)
            return 1
        print("BASELINE " + baseline.stdout.strip().splitlines()[-1])
        failed = False
        for name, filename, original, replacement, selector in MUTATIONS:
            path = work / filename
            source = path.read_text()
            if source.count(original) != 1:
                print("ERROR replacement anchor changed: " + name)
                return 1
            mutated = source.replace(original, replacement, 1)
            ast.parse(mutated, filename=filename)
            path.write_text(mutated)
            try:
                result = run_tests(work, selector)
            finally:
                path.write_text(source)
            assertion_failed = (
                "AssertionError" in result.stdout
                or re.search(r": assert ", result.stdout) is not None
            )
            harness_error = (
                result.returncode not in (0, 1)
                or "ERROR collecting" in result.stdout
                or re.search(r"\b[1-9][0-9]* errors?\b", result.stdout) is not None
            )
            if result.returncode == 1 and assertion_failed and not harness_error:
                print("KILLED " + name)
            else:
                failed = True
                print(("ERROR " if harness_error else "SURVIVED ") + name)
                print(result.stdout)
        return int(failed)


if __name__ == "__main__":
    sys.exit(main())
