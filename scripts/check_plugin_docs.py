#!/usr/bin/env python3
"""
CI check: Ensure all plugins are documented.

Validates that:
1. All plugins are mentioned in README.md
2. All plugins have documentation files in docs/en/checks/

Run: python scripts/check_plugin_docs.py
"""

import sys
from pathlib import Path

# Plugins with external documentation (skip docs check)
EXTERNAL_DOCS_PLUGINS = {
    "try_files_is_evil_too",  # Links to external blog post
}


def plugin_name_to_slug(plugin_name):
    """Convert a plugin name to kebab-case slug."""
    return plugin_name.replace("_", "-")


def get_plugins():
    """Get all plugin names from gixy/plugins/."""
    plugins_dir = Path("gixy/plugins")
    skip = {"__init__.py", "plugin.py"}
    plugins = []
    for f in plugins_dir.glob("*.py"):
        # Underscore-prefixed files are internal data/helper modules, not
        # plugins (matches the PluginsManager.import_plugins convention).
        if f.name.startswith("_"):
            continue
        if f.name not in skip:
            plugins.append(f.stem)
    return sorted(plugins)


def check_readme(plugins):
    """Check if plugins are mentioned in README.md."""
    readme = Path("README.md").read_text().lower()
    missing = []
    for plugin in plugins:
        # Check for plugin name (with underscores, dashes, or without separators)
        variants = [
            plugin.lower(),
            plugin.replace("_", ""),
            plugin.replace("_", "-"),
        ]
        if not any(v in readme for v in variants):
            missing.append(plugin)
    return missing


def check_docs(plugins):
    """Check if plugins have doc files in docs/en/checks/."""
    docs_dir = Path("docs/en/checks")
    missing = []
    for plugin in plugins:
        # Skip plugins with external documentation
        if plugin in EXTERNAL_DOCS_PLUGINS:
            continue
        # Use kebab-case slug as per convention
        slug = plugin_name_to_slug(plugin)
        doc_file = docs_dir / f"{slug}.md"
        if not doc_file.exists():
            missing.append(plugin)
    return missing


def main():
    plugins = get_plugins()
    print(f"Found {len(plugins)} plugins: {', '.join(plugins)}\n")

    readme_missing = check_readme(plugins)
    docs_missing = check_docs(plugins)

    errors = []

    if readme_missing:
        print("Plugins missing from README.md:")
        for p in readme_missing:
            print(f"   - {p}")
        errors.append(f"{len(readme_missing)} plugins not in README")

    if docs_missing:
        print("\nPlugins missing documentation (docs/en/checks/):")
        for p in docs_missing:
            slug = plugin_name_to_slug(p)
            print(f"   - {p} -> docs/en/checks/{slug}.md")
        errors.append(f"{len(docs_missing)} plugins missing docs")

    if errors:
        print(f"\nFAILED: {', '.join(errors)}")
        sys.exit(1)
    else:
        print("\nAll plugins documented!")
        sys.exit(0)


if __name__ == "__main__":
    main()
