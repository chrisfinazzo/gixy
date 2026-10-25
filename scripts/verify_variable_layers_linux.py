#!/usr/bin/env python3
"""Prove real no-argument CLI policy loading inside a disposable Linux container.

Run with the installed package's interpreter and GIXY_DISPOSABLE_CONTAINER=1.
The harness writes /etc/nginx/nginx.conf and temporary system policy drop-ins;
it never installs packages or starts NGINX. Package lifecycle verification can
call --assert-current before/after each transaction instead of adding probes.
"""

import argparse
import json
import os
import platform
import subprocess  # nosec B404 - execute only this interpreter and the installed CLI.
import sys
import tempfile
from pathlib import Path

VENDOR = Path("/usr/share/gixy/vars.d")
ADMIN = Path("/etc/gixy/vars.d")
CONFIG = Path("/etc/nginx/nginx.conf")
TAINTED = "brotli_ratio r'[\\s\\S]*'\n"
SAFE = "brotli_ratio r'[0-9.]*'\n"


def require(condition, evidence):
    """Fail proof checks even when Python is running with optimization."""
    if not condition:
        raise AssertionError(evidence)


def require_disposable_container():
    """Refuse filesystem changes outside an explicitly designated container."""
    container = Path("/.dockerenv").exists() or Path("/run/.containerenv").exists()
    if platform.system() != "Linux" or os.geteuid() != 0 or not container:
        raise SystemExit("This proof requires a disposable Linux root container.")
    if os.environ.get("GIXY_DISPOSABLE_CONTAINER") != "1":
        raise SystemExit(
            "Set GIXY_DISPOSABLE_CONTAINER=1 to authorize this container's fixtures."
        )
    if Path("/etc/gixy/gixy.cfg").exists():
        raise SystemExit("Use a clean container without /etc/gixy/gixy.cfg.")


def invoke(arguments=(), environment=None, content=None):
    """Invoke the installed CLI with a clean environment and observed output."""
    clean = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.getcwd(),
        "LANG": "C.UTF-8",
    }
    clean.update(environment or {})
    result = subprocess.run(  # noqa: UP022  # nosec B603 - fixed module command; Python 3.6.
        [sys.executable, "-m", "gixy.cli"] + list(arguments),
        input=content,
        stdout=subprocess.PIPE,  # Python 3.6 has no capture_output.
        stderr=subprocess.PIPE,
        universal_newlines=True,
        env=clean,
        timeout=20,
    )
    require(result.returncode in (0, 1), result.stderr)
    require("Can't find variable 'brotli_ratio'" not in result.stderr, result.stderr)
    require(
        "Can't find variable 'brotli_unknown_probe'" in result.stderr, result.stderr
    )
    return result


def check(label, tainted, arguments=(), environment=None, stdin=False):
    """Assert that a selected layer changes actual HTTP-splitting findings."""
    content = "http { server { server_tokens off; add_header X $brotli_ratio; add_header Y $brotli_unknown_probe; } }\n"
    CONFIG.parent.mkdir(parents=True, exist_ok=True)
    CONFIG.write_text(content)
    result = invoke(arguments, environment, content if stdin else None)
    splitting = "Possible HTTP-Splitting vulnerability." in result.stdout
    require(splitting == tainted, (label, result.stdout, result.stderr))
    require(result.returncode == (1 if tainted else 0), (label, result.stdout))
    print(
        json.dumps(
            {"case": label, "splitting": splitting, "returncode": result.returncode}
        )
    )


def check_server(label, tainted, arguments=()):
    """Prove ambient policy isolation and operator-controlled server startup."""
    request = {
        "id": 1,
        "method": "analyze",
        "content": "http { server { server_tokens off; add_header X $brotli_ratio; add_header Y $brotli_unknown_probe; } }",
        "vars_dirs": [str(VENDOR)],
        "load_default_vars": True,
    }
    result = invoke(["--server"] + list(arguments), content=json.dumps(request) + "\n")
    responses = [json.loads(line) for line in result.stdout.splitlines()]
    require(responses[0]["ready"] is True, responses)
    require(responses[1]["error"] is None, responses)
    splitting = any(
        issue["summary"] == "Possible HTTP-Splitting vulnerability."
        for issue in responses[1]["issues"]
    )
    require(splitting == tainted, (label, responses, result.stderr))
    print(json.dumps({"case": label, "splitting": splitting}))


def exercise_layers(work):
    """Prove vendor/admin/explicit precedence using distinguishable probe models."""
    vendor_file = VENDOR / "zz-gixy-layer-proof.cfg"
    admin_file = ADMIN / "zz-gixy-layer-proof.cfg"
    require(
        not vendor_file.exists() and not admin_file.exists(),
        "Probe files already exist",
    )
    VENDOR.mkdir(parents=True, exist_ok=True)
    ADMIN.mkdir(parents=True, exist_ok=True)
    for directory in (VENDOR, ADMIN, VENDOR.parent, ADMIN.parent):
        directory.chmod(0o755)
    explicit = work / "explicit"
    explicit.mkdir()
    (explicit / "model.cfg").write_text(TAINTED)
    try:
        check("initial-installed-policy", False)
        vendor_file.write_text(TAINTED)
        vendor_file.chmod(0o644)
        check("automatic-vendor", True)
        check_server("server-default-isolation-request-cannot-enable", False)
        check_server("server-operator-defaults-enabled", True, ["--load-default-vars"])
        check_server("server-explicit-policy", True, ["--vars-dirs", str(VENDOR)])
        check("opt-out-bundled-only", False, ["--no-default-vars"])
        check("stdin-vendor", True, ["-"], stdin=True)
        admin_file.write_text(SAFE)
        admin_file.chmod(0o644)
        check("automatic-admin", False)
        check("explicit-above-admin", True, ["--vars-dirs", str(explicit)])
        check(
            "opt-out-with-explicit",
            True,
            ["--no-default-vars", "--vars-dirs", str(explicit)],
        )
        check(
            "environment-opt-out",
            False,
            environment={"GIXY_LOAD_DEFAULT_VARS": "false"},
        )
        admin_file.unlink()
        check(
            "cli-false-beats-environment-true",
            False,
            ["--no-default-vars"],
            {"GIXY_LOAD_DEFAULT_VARS": "true"},
        )
        check(
            "cli-true-beats-environment-false",
            True,
            ["--load-default-vars"],
            {"GIXY_LOAD_DEFAULT_VARS": "false"},
        )
        vendor_file.chmod(0o666)
        check("unsafe-vendor-rejected", False)
        vendor_file.chmod(0o644)
        vendor_file.unlink()
        check("vendor-removal-fallback", False)
    finally:
        for path in (vendor_file, admin_file):
            if path.exists():
                path.unlink()


def exercise_modules(work):
    """Verify installed CLI, library and server module behavior without policy."""
    import io

    from gixy.core.config import Config
    from gixy.core.manager import Manager

    for tainted in (False, True):
        # Formatters aggregate identical reasons across locations. Distinct
        # aliases keep all three raw findings independently observable in JSON.
        sink = (
            "add_header Country $country;\n"
            "            proxy_set_header Script $script;\n"
            "            proxy_pass http://$backend;"
            if tainted
            else "add_header Epoch $epoch;"
        )
        content = (
            """http {
          geoip2 /nonexistent.mmdb {
            $country default=US country iso_code;
            $backend custom bytes;
            $epoch metadata build_epoch;
          }
          server { server_tokens off;
            set_by_lua_block $script { return ngx.var.uri }
            add_header Ratio $zstd_ratio;
            add_header Count $vts_request_counter;
            add_header Cache $srcache_fetch_status;
            add_header Unknown $brotli_unknown_probe;
            %s
          }
        }"""
            % sink
        )
        expected = (
            {"http_splitting": 3, "ssrf": 1, "missing_resolver": 1} if tainted else {}
        )

        def verify(label, issues, expected=expected, tainted=tainted):
            counts = {}
            for issue in issues:
                name = issue["plugin"]
                if name in ("http_splitting", "ssrf", "missing_resolver"):
                    counts[name] = counts.get(name, 0) + 1
            require(counts == expected, (label, counts, expected, issues))
            print(json.dumps({"case": label, "tainted": tainted, "counts": counts}))

        CONFIG.write_text(content)
        file_path = work / "modules.conf"
        file_path.write_text(content)
        for mode, arguments, stdin in (
            ("no-argument", [], None),
            ("file", [str(file_path)], None),
            ("stdin", ["-"], content),
        ):
            result = invoke(
                ["--no-default-vars", "-f", "json"] + arguments, content=stdin
            )
            for name in (
                "country",
                "backend",
                "epoch",
                "script",
                "zstd_ratio",
                "vts_request_counter",
                "srcache_fetch_status",
            ):
                require(
                    "Can't find variable '%s'" % name not in result.stderr,
                    result.stderr,
                )
            verify("modules-cli-" + mode, json.loads(result.stdout))
        with Manager(Config(load_default_vars=False)) as manager:
            manager.audit(str(file_path), io.StringIO(content), is_stdin=True)
            issues = [
                {"plugin": plugin.__class__.__name__}
                for plugin in manager.results
                for issue in plugin.issues
            ]
            verify("modules-library-disabled-policy", issues)
        request = {
            "id": 1,
            "method": "analyze",
            "content": content,
            "vars_dirs": [str(VENDOR)],
            "load_default_vars": True,
        }
        result = invoke(
            ["--server", "--no-default-vars"], content=json.dumps(request) + "\n"
        )
        responses = [json.loads(line) for line in result.stdout.splitlines()]
        require(
            responses[0]["ready"] is True and responses[1]["error"] is None, responses
        )
        verify("modules-server-disabled-policy", responses[1]["issues"])


def main():
    """Run independent installed-artifact checks or the complete layer proof."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assert-current", action="store_true")
    parser.add_argument("--expect-tainted", action="store_true")
    parser.add_argument("--expect-source", help="Expected exact catalog source path")
    args = parser.parse_args()
    require_disposable_container()
    with tempfile.TemporaryDirectory(prefix="gixy-policy-proof-") as directory:
        work = Path(directory)
        os.chdir(str(work))
        if args.assert_current:
            check("installed-policy", args.expect_tainted)
            if args.expect_source:
                from gixy.core.variable_catalog import load_variable_catalog

                definition = load_variable_catalog(load_default_vars=True).resolve(
                    "brotli_ratio"
                )
                require(definition.source == args.expect_source, definition)
                print(json.dumps(definition._asdict()))
        else:
            exercise_layers(work)
            exercise_modules(work)


if __name__ == "__main__":
    main()
