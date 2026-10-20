"""Checkstyle XML formatter for CI/CD integration.

The Checkstyle XML format is a widely-supported standard for static analysis
tools. It's natively consumed by:
- Jenkins (Warnings Next Generation plugin)
- GitLab CI (Code Quality reports)
- GitHub Actions (via reviewdog, super-linter)
- Bitbucket Pipelines (Code Insights)
- SonarQube (External issues import)
- Many IDEs (IntelliJ, Eclipse, etc.)

Example output:
    <?xml version="1.0" encoding="UTF-8"?>
    <checkstyle version="8.0">
      <file name="/etc/nginx/nginx.conf">
        <error line="10" column="1" severity="error"
               message="[ssrf] SSRF vulnerability: reason"
               source="gixy.ssrf"/>
      </file>
    </checkstyle>
"""

from xml.etree.ElementTree import (  # nosemgrep: use-defused-xml  # nosec B405
    Element,
    SubElement,
    tostring,
)  # We generate XML, not parse untrusted data

from gixy.formatters.base import BaseFormatter

# Map gixy severity to Checkstyle severity
# Checkstyle supports: error, warning, info, ignore
SEVERITY_MAP = {
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "info",
    "UNSPECIFIED": "info",
}


class CheckstyleFormatter(BaseFormatter):
    """Format gixy output as Checkstyle XML for CI/CD integration."""

    def format_reports(self, reports, stats):
        """Format all reports into Checkstyle XML.

        Args:
            reports: Dict mapping file paths to lists of issues.
            stats: Dict with issue counts by severity.

        Returns:
            str: Complete Checkstyle XML document.
        """
        root = Element("checkstyle", version="8.0")

        for path, issues in reports.items():
            if not issues:
                # Include empty file elements for completeness
                SubElement(root, "file", name=path)
                continue

            file_elem = SubElement(root, "file", name=path)

            for issue in issues:
                # Extract line number, defaulting to 1 if not available
                location = issue.get("location") or {}
                line = location.get("line", 1)
                # Use file from location if available, otherwise use path
                # This handles cases where the issue is in an included file
                issue_file = location.get("file") or path

                # Select the source file for every issue, including a return
                # to the main file after an issue from an included file.
                file_elem = self._get_or_create_file_element(root, issue_file)

                severity = SEVERITY_MAP.get(
                    issue.get("severity", "UNSPECIFIED"), "info"
                )

                # Build message: "[plugin] summary: reason"
                plugin = issue.get("plugin", "unknown")
                summary = issue.get("summary", "Issue detected")
                reason = issue.get("reason", "")

                if reason:
                    message = f"[{plugin}] {summary}: {reason}"
                else:
                    message = f"[{plugin}] {summary}"

                SubElement(
                    file_elem,
                    "error",
                    line=str(line),
                    column="1",
                    severity=severity,
                    message=message,
                    source=f"gixy.{plugin}",
                )

        # Generate XML with declaration
        xml_declaration = '<?xml version="1.0" encoding="UTF-8"?>\n'
        xml_body = tostring(root, encoding="unicode")

        return xml_declaration + xml_body

    def _get_or_create_file_element(self, root, filepath):
        """Get existing file element or create a new one.

        Args:
            root: The checkstyle root element.
            filepath: The file path to find or create.

        Returns:
            Element: The file element for the given path.
        """
        for file_elem in root.findall("file"):
            if file_elem.get("name") == filepath:
                return file_elem
        return SubElement(root, "file", name=filepath)
