#!/usr/bin/env python
"""Check for Python 3.7+ patterns that break Python 3.6 compatibility."""

import ast
import os
import re
import sys
from pathlib import Path

# Patterns that require Python 3.7+
# Format: (regex, message)
INCOMPATIBLE_PATTERNS = [
    # subprocess.run text=True requires 3.7+ (use universal_newlines=True)
    (
        r"subprocess\.run\([^)]*\btext\s*=\s*True",
        "Use universal_newlines=True instead of text=True (Python 3.7+)",
    ),
    # subprocess.Popen text=True requires 3.7+
    (
        r"subprocess\.Popen\([^)]*\btext\s*=\s*True",
        "Use universal_newlines=True instead of text=True (Python 3.7+)",
    ),
    # dataclasses module requires 3.7+ (if imported at module level)
    (r"^from dataclasses import", "dataclasses module requires Python 3.7+"),
    # positional-only params (/) require 3.8+
    (r"def \w+\([^)]*,\s*/", "Positional-only parameters (/) require Python 3.8+"),
]

# Files to skip (this script itself uses patterns as string literals)
SKIP_FILES = {"check_py36_compat.py"}
REPO_ROOT = Path(__file__).resolve().parent.parent


def resolve_repo_path(filepath: str) -> Path:
    """Resolve a path and require it to remain inside the repository."""
    candidate = Path(filepath).resolve()
    try:
        candidate.relative_to(REPO_ROOT)
    except ValueError:
        raise ValueError(f"Path is outside the repository: {filepath}")
    return candidate


def check_file(filepath: str) -> list:
    """Check a single file for Python 3.6 incompatibilities."""
    try:
        filepath = resolve_repo_path(filepath)
    except ValueError as exc:
        return [(filepath, 0, str(exc))]

    # Skip files that contain pattern definitions (like this script)
    if os.path.basename(str(filepath)) in SKIP_FILES:
        return []

    issues = []
    try:
        with filepath.open(encoding="utf-8") as f:
            source = f.read()
        try:
            tree = ast.parse(source, filename=str(filepath))
        except SyntaxError as exc:
            return [
                (
                    filepath,
                    exc.lineno or 1,
                    "Unable to parse source on this interpreter: " + exc.msg,
                )
            ]

        for node in ast.walk(tree):
            # NamedExpr is absent from older ast modules. Walking the parsed
            # tree also catches expressions inside f-strings, which tokenize
            # treats as a single string on Python versions before 3.12.
            if type(node).__name__ == "NamedExpr":
                issues.append(
                    (filepath, node.lineno, "Walrus operator := requires Python 3.8+")
                )

        lines = source.splitlines()

        for pattern, message in INCOMPATIBLE_PATTERNS:
            for i, line in enumerate(lines, 1):
                # Skip comments and string-only lines
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                if re.search(pattern, line):
                    issues.append((filepath, i, message))
    except (OSError, UnicodeDecodeError):
        pass
    return issues


def main() -> int:
    """Check all provided files."""
    if len(sys.argv) < 2:
        return 0

    all_issues = []
    for filepath in sys.argv[1:]:
        all_issues.extend(check_file(filepath))

    for filepath, line, message in all_issues:
        print(f"{filepath}:{line}: {message}")

    return 1 if all_issues else 0


if __name__ == "__main__":
    sys.exit(main())
