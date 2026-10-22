"""Keep the version/help footer separate from the following shell prompt."""

import subprocess
import sys

import pytest


@pytest.mark.parametrize("flag", ["-v", "--version", "--help"])
def test_cli_footer_has_separate_url_and_trailing_line_breaks(flag):
    completed = subprocess.run(  # noqa: UP022 - capture_output requires Python 3.7+
        [sys.executable, "-m", "gixy.cli.main", flag],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )

    assert completed.returncode == 0
    assert completed.stderr == ""
    assert completed.stdout.endswith(
        "\n\nContinuous Gixy scans + NGINX monitoring: GetPageSpeed Amplify\n"
        "https://gixy.org/guides/nginx-monitoring-amplify\n\n"
    )
