#!/usr/bin/env python3
"""Kill bounded security-proof mutations in temporary source copies.

This checker reuses the project's existing mutation-harness pattern. It never
executes supplied nginx regexes or changes the live checkout.
"""

import ast
import os
from pathlib import Path
import re
import shutil
import subprocess  # nosec B404 - fixed interpreter and local pytest files.
import sys
import tempfile


ROOT = Path(__file__).resolve().parent.parent
TESTS = [
    "tests/plugins/test_redos_analyzer.py",
    "tests/plugins/test_cipher_commands.py",
    "tests/plugins/test_map_capture_provenance.py",
    "tests/plugins/test_proxy_uri_transfer.py",
    "tests/plugins/test_quic_bpf_version.py",
    "tests/core/test_nginx_flavors.py",
]

# Name, source file, exact source fragment, mutant, selected assertion.
MUTATIONS = [
    (
        "regex-not-literal-complement",
        "gixy/plugins/regex_redos.py",
        "if op == NOT_LITERAL:\n            return (False, {chr(av)}), False",
        "if op == NOT_LITERAL:\n            return None, False",
        "test_mandatory_disjoint_boundary",
    ),
    (
        "regex-negated-class-complement",
        "gixy/plugins/regex_redos.py",
        "if inner_op == NEGATE:\n                negated = True",
        "if False:\n                negated = True",
        "test_mandatory_disjoint_boundary",
    ),
    (
        "regex-nullable-successor",
        "gixy/plugins/regex_redos.py",
        "if nullable:\n            return self._set_union(after, inherited_tail)",
        "if False:\n            return self._set_union(after, inherited_tail)",
        "test_nullable_or_overlapping_boundary_remains_unsafe",
    ),
    (
        "regex-inline-case",
        "gixy/plugins/regex_redos.py",
        "self.case_insensitive = bool(parsed.pattern.flags & re.IGNORECASE)",
        "self.case_insensitive = False",
        "test_nullable_or_overlapping_boundary_remains_unsafe",
    ),
    (
        "regex-dotall",
        "gixy/plugins/regex_redos.py",
        "self.dot_matches_newline = bool(parsed.pattern.flags & re.DOTALL)",
        "self.dot_matches_newline = False",
        "test_nullable_or_overlapping_boundary_remains_unsafe",
    ),
    (
        "cipher-permanent-ban",
        "gixy/plugins/weak_ssl_tls.py",
        'if operator == "!":\n                banned.append(selectors)',
        "if False:\n                banned.append(selectors)",
        "test_permanent_and_reversible_exclusions_for_supported_families",
    ),
    (
        "cipher-reversible-removal",
        "gixy/plugins/weak_ssl_tls.py",
        'if operator in ("!", "-"):',
        'if operator == "!":',
        "test_permanent_and_reversible_exclusions_for_supported_families",
    ),
    (
        "cipher-intersection",
        "gixy/plugins/weak_ssl_tls.py",
        "if False in matches:\n        return False",
        "if False in matches:\n        return True",
        "test_weak_selection_removed_or_never_added",
    ),
    (
        "cipher-reorder-only",
        "gixy/plugins/weak_ssl_tls.py",
        'if operator == "+":\n            continue',
        "if False:\n            continue",
        "test_permanent_and_reversible_exclusions_for_supported_families",
    ),
    (
        "map-unknown-source",
        "gixy/core/variable.py",
        "if dependency is None or dependency._possible_char(char, seen):",
        "if dependency is not None and dependency._possible_char(char, seen):",
        "test_capture_inherits_whole_source_alphabet",
    ),
    (
        "map-capture-scope",
        "gixy/directives/directive.py",
        "ctx=self,\n                    capture_source=map_source,",
        "ctx=self.src_val,\n                    capture_source=map_source,",
        "test_identical_patterns_in_distinct_maps_keep_source_scope",
    ),
    (
        "proxy-unsafe-path",
        "gixy/plugins/http_splitting.py",
        "return all(safe and not pending for safe, _, pending in states)",
        "return bool(states)",
        "test_unproved_or_tainted_path_keeps_warning",
    ),
    (
        "parser-map-quoted-control",
        "gixy/parser/nginx_parser.py",
        "args = [to_native(v) for v in parsed_args[0]]",
        "args = [to_native(v).strip() for v in parsed_args[0]]",
        "test_capture_inherits_whole_source_alphabet",
    ),
    (
        "parser-rewrite-quoted-control",
        "gixy/parser/nginx_parser.py",
        "args = [to_native(v) for v in parsed_args]",
        "args = [to_native(v).strip() for v in parsed_args]",
        "test_unproved_or_tainted_path_keeps_warning",
    ),
    (
        "flavor-fix-ignores-exact-key",
        "gixy/core/config.py",
        ".get(key)",
        '.get("CVE-2026-93479")',
        "test_data_only_flavor_and_exact_cve_scope",
    ),
    (
        "flavor-fix-below-threshold",
        "gixy/core/config.py",
        'self.resolved_nginx_version < parse_oss(fix["version"])',
        "self.resolved_nginx_version < (0, 0, 0)",
        "test_flavor_specific_quic_fix",
    ),
    (
        "version-unknown-boundary",
        "gixy/plugins/quic_bpf_reuseport.py",
        "if version is not None and version >= (1, 31, 7):",
        "if version is None or version >= (1, 31, 7):",
        "test_explicit_upstream_version_boundary",
    ),
]


def run_tests(directory, selector=None):
    """Run selected real assertions with the current interpreter."""
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    command = [sys.executable, "-m", "pytest"] + TESTS + ["-q", "--tb=line"]
    if selector:
        command += ["-k", selector]
    return subprocess.run(  # noqa: UP022  # nosec B603 - Python 3.6 support.
        command,
        cwd=str(directory),
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
        timeout=30,
    )


def main():
    """Require every mutation to fail a named assertion without harness errors."""
    with tempfile.TemporaryDirectory(prefix="gixy-analyzer-mutations-") as temporary:
        work = Path(temporary)
        for name in ("gixy", "tests"):
            shutil.copytree(
                str(ROOT / name),
                str(work / name),
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
            )
        baseline = run_tests(work)
        if baseline.returncode != 0 or not re.search(
            r"\b[1-9][0-9]* passed\b", baseline.stdout
        ):
            print("ERROR baseline did not pass\n" + baseline.stdout)
            return 1
        print("BASELINE " + baseline.stdout.strip().splitlines()[-1])

        failed = False
        for name, filename, original, replacement, selector in MUTATIONS:
            path = work / filename
            source = path.read_text(encoding="utf-8")
            if source.count(original) != 1:
                print("ERROR replacement anchor changed: " + name)
                return 1
            mutated = source.replace(original, replacement, 1)
            ast.parse(mutated, filename=filename)
            with path.open("w", encoding="utf-8") as stream:
                stream.write(mutated)
            try:
                result = run_tests(work, selector)
            finally:
                with path.open("w", encoding="utf-8") as stream:
                    stream.write(source)
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
