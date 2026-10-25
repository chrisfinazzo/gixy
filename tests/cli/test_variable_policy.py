"""Verify policy controls across configuration sources and server startup."""

import io
import json
import os
import subprocess
import sys

import pytest

from gixy.cli.main import _get_cli_parser


def parse(arguments=(), config="", environment=None):
    return _get_cli_parser().parse_args(
        list(arguments), config_file_contents=config, env_vars=environment or {}
    )


def test_unspecified_policy_is_tristate():
    assert parse().load_default_vars is None
    assert parse(["--server"]).load_default_vars is None


@pytest.mark.parametrize(
    "value, expected", [("true", True), ("false", False), ("yes", True), ("0", False)]
)
def test_boolean_config_and_environment(value, expected):
    assert parse(config="load-default-vars = " + value).load_default_vars is expected
    assert (
        parse(environment={"GIXY_LOAD_DEFAULT_VARS": value}).load_default_vars
        is expected
    )


@pytest.mark.parametrize(
    "cli, expected", [("--load-default-vars", True), ("--no-default-vars", False)]
)
@pytest.mark.parametrize("lower", ["true", "false"])
def test_cli_alias_overrides_both_lower_sources(cli, expected, lower):
    args = parse(
        [cli], "load-default-vars = " + lower, {"GIXY_LOAD_DEFAULT_VARS": lower}
    )
    assert args.load_default_vars is expected


@pytest.mark.parametrize("value, expected", [("true", True), ("false", False)])
def test_environment_overrides_opposite_config(value, expected):
    config = "load-default-vars = " + ("false" if expected else "true")
    assert (
        parse(
            config=config, environment={"GIXY_LOAD_DEFAULT_VARS": value}
        ).load_default_vars
        is expected
    )


@pytest.mark.parametrize(
    "arguments",
    [
        ("--load-default-vars", "--no-default-vars"),
        ("--no-default-vars", "--load-default-vars"),
    ],
)
def test_opposite_policy_flags_are_rejected(arguments):
    with pytest.raises(SystemExit) as error:
        parse(arguments)
    assert error.value.code == 2


@pytest.mark.parametrize(
    "config, env",
    [
        ("load-default-vars = maybe", {}),
        ("", {"GIXY_LOAD_DEFAULT_VARS": "maybe"}),
        ("no-default-vars = true", {}),
    ],
)
def test_invalid_or_negative_config_key_rejected(config, env):
    with pytest.raises(SystemExit) as error:
        parse(config=config, environment=env)
    assert error.value.code == 2


@pytest.mark.parametrize(
    "arguments, config, env, expected",
    [
        (["--no-default-vars"], "load-default-vars = true", {}, False),
        (["--load-default-vars"], "load-default-vars = false", {}, True),
        ([], "load-default-vars = false", {}, False),
        ([], "", {"GIXY_LOAD_DEFAULT_VARS": "false"}, False),
        ([], "", {"GIXY_LOAD_DEFAULT_VARS": "true"}, True),
    ],
)
def test_write_config_roundtrip(tmp_path, arguments, config, env, expected):
    output = tmp_path / "gixy.cfg"
    parser = _get_cli_parser()
    with pytest.raises(SystemExit) as error:
        parser.parse_args(
            arguments + ["--write-config", str(output)],
            config_file_contents=config,
            env_vars=env,
        )
    assert error.value.code == 0
    contents = output.read_text()
    assert contents.count("load-default-vars =") == 1
    assert "no-default-vars =" not in contents
    assert parse(config=contents).load_default_vars is expected


def test_documented_scalar_vars_dirs():
    from gixy.cli.argparser import GixyConfigParser

    example = "vars-dirs = /etc/gixy/vars, ~/.config/gixy/vars"
    assert (
        GixyConfigParser().parse(io.StringIO(example))["vars-dirs"]
        == "/etc/gixy/vars, ~/.config/gixy/vars"
    )
    assert parse(config=example).vars_dirs == "/etc/gixy/vars, ~/.config/gixy/vars"


def run_server(arguments, requests):
    environment = {
        key: value for key, value in os.environ.items() if not key.startswith("GIXY_")
    }
    environment["GIXY_DISABLE_INCLUDES"] = "true"
    result = subprocess.run(  # noqa: UP022 - retain Python 3.6 support.
        [sys.executable, "-m", "gixy.cli", "--server"] + arguments,
        input="".join(json.dumps(request) + "\n" for request in requests),
        stdout=subprocess.PIPE,  # Python 3.6 has no capture_output.
        stderr=subprocess.PIPE,
        universal_newlines=True,
        env=environment,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
    responses = [json.loads(line) for line in result.stdout.splitlines()]
    assert responses[0]["ready"] is True
    assert all(response.get("error") is None for response in responses[1:])
    return responses[1:], result.stderr


def test_server_startup_paths_and_request_policy_isolation(tmp_path):
    directory = tmp_path / "policy"
    directory.mkdir()
    (directory / "model.cfg").write_text("brotli_ratio r'[\\s\\S]*'\n")
    request = {
        "id": 1,
        "method": "analyze",
        "content": "http { server { server_tokens off; add_header X $brotli_ratio; } }",
    }
    injected = dict(request, id=2, vars_dirs=[str(directory)], load_default_vars=True)
    responses, _ = run_server([], [request, injected])
    assert responses[0]["issues"] == responses[1]["issues"] == []
    responses, _ = run_server(
        ["--no-default-vars", "--vars-dirs", str(directory)], [request]
    )
    assert any(
        issue["summary"] == "Possible HTTP-Splitting vulnerability."
        for issue in responses[0]["issues"]
    )


def test_server_recognizes_bundled_unknown_and_ignores_uploaded_policy(caplog):
    request = {
        "id": 1,
        "method": "analyze",
        "content": "http { server { server_tokens off; add_header X $brotli_ratio; add_header Y $brotli_unknown; } }",
    }
    responses, stderr = run_server([], [request])
    assert responses[0]["issues"] == []
    assert "Can't find variable 'brotli_unknown'" in stderr
    assert "Can't find variable 'brotli_ratio'" not in stderr


def test_container_proof_refuses_host_mutations():
    from pathlib import Path

    script = (
        Path(__file__).resolve().parents[2]
        / "scripts"
        / "verify_variable_layers_linux.py"
    )
    environment = dict(os.environ)
    environment.pop("GIXY_DISPOSABLE_CONTAINER", None)
    result = subprocess.run(  # noqa: UP022 - retain Python 3.6 support.
        [sys.executable, str(script)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        env=environment,
        timeout=10,
    )
    assert result.returncode != 0
    assert (
        "disposable Linux root container" in result.stderr
        or "GIXY_DISPOSABLE_CONTAINER=1" in result.stderr
    )
