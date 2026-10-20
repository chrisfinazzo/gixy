"""Keep compatibility checks sensitive to Python syntax, not string contents."""

import ast

import pytest

from scripts import check_py36_compat


@pytest.fixture
def check_source(tmp_path, monkeypatch):
    monkeypatch.setattr(check_py36_compat, "REPO_ROOT", tmp_path)

    def run(source):
        path = tmp_path / "source.py"
        path.write_text(source, encoding="utf-8")
        return check_py36_compat.check_file(str(path))

    return run


@pytest.mark.parametrize(
    "source",
    [
        'pattern = r"[^:=;#]+"\n',
        'value = ":="\n',
        'value = f":="\n',
        'value = """first\n:=\nlast"""\n',
        "value = 1  # := is only a comment\n",
    ],
)
def test_walrus_text_in_literals_and_comments_is_compatible(check_source, source):
    assert check_source(source) == []


@pytest.mark.parametrize(
    "source",
    [
        "if (value := 1):\n    pass\n",
        'value = f"{(inner := 1)}"\n',
    ],
)
def test_real_walrus_is_rejected_including_fstring_expression(check_source, source):
    issues = check_source(source)
    assert len(issues) == 1
    assert issues[0][1] == 1
    try:
        ast.parse(source)
    except SyntaxError:
        assert "Unable to parse" in issues[0][2]
    else:
        assert "Walrus operator" in issues[0][2]


def test_unparseable_source_is_a_failure(check_source):
    issues = check_source("value = (\n")
    assert len(issues) == 1
    assert "Unable to parse" in issues[0][2]


@pytest.mark.parametrize(
    "source, expected",
    [
        ("subprocess.run(args, text" + "=True)\n", "universal_newlines"),
        ("subprocess.Popen(args, text" + "=True)\n", "universal_newlines"),
        ("from " + "dataclasses import dataclass\n", "dataclasses"),
        ("def function(a, " + "/):\n    pass\n", "Positional-only"),
    ],
)
def test_other_compatibility_rules_still_reject(check_source, source, expected):
    issues = check_source(source)
    assert issues
    try:
        ast.parse(source)
    except SyntaxError:
        assert any("Unable to parse" in issue[2] for issue in issues)
    else:
        assert any(expected in issue[2] for issue in issues)
