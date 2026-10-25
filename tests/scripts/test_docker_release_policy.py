"""Keep Docker publication restricted to an explicit published release.

Actionlint validates YAML syntax separately; this focused policy regression uses
only the standard library, including on the minimum supported Python runtime.
"""

from pathlib import Path


RELEASE_ONLY = "github.event_name == 'release' && github.event.action == 'published'"


def test_docker_release_publication_keeps_push_build_and_smoke_tests():
    workflow = Path(".github/workflows/dockerpublish.yml").read_text()
    assert "  release:\n    types: [published]" in workflow
    assert "  push:\n    branches:\n      - master" in workflow
    steps = workflow.split("      - name: ")[1:]
    publishing = [
        step
        for step in steps
        if "uses: docker/login-action@" in step
        or "uses: docker/metadata-action@" in step
        or "          push: true\n" in step
    ]
    assert len(publishing) == 4
    assert all("        if: " + RELEASE_ONLY + "\n" in step for step in publishing)
    testing = [
        step
        for step in steps
        if "          load: true\n" in step or step.startswith("Test ")
    ]
    assert len(testing) == 3
    assert all("        if:" not in step for step in testing)
    assert "          tags: gixy:test\n" in testing[0]
