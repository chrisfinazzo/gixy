"""Exercise variable policy through real audits and variable resolution."""

import io

import pytest

from gixy.core import builtin_variables as builtins
from gixy.core.config import Config
from gixy.core.context import get_context, purge_context
from gixy.core.manager import Manager


@pytest.fixture(autouse=True)
def reset_context():
    purge_context()
    yield
    purge_context()


def audit(config=None, content="http { server { add_header X $brotli_ratio; } }"):
    manager = Manager(config)
    manager.audit("inline.conf", io.StringIO(content), is_stdin=True)
    return manager


def policy(tmp_path, text, name="policy"):
    directory = tmp_path / name
    directory.mkdir()
    (directory / "model.cfg").write_text(text)
    return str(directory)


def test_bundled_brotli_alphabet_and_exact_name():
    audit()
    variable = get_context().get_var("brotli_ratio")
    assert variable is not None
    assert variable.can_contain(".")
    assert variable.can_contain("9")
    for character in ("\r", "\n", "/", "a"):
        assert not variable.can_contain(character)
    assert get_context().get_var("brotli_arbitrary") is None
    assert not builtins.is_builtin(1)


def test_ordinary_quotes_preserve_literal_punctuation(tmp_path):
    directory = policy(tmp_path, 'literal "a.b[$http_host]"\n')
    audit(Config(vars_dirs=[directory]))
    variable = get_context().get_var("literal")
    assert variable.regexp is None
    assert variable.depends is None
    assert variable.value == "a.b[$http_host]"
    assert variable.must_contain(".")
    assert not variable.can_contain("\n")


@pytest.mark.parametrize("bad", ["host", "host =", "host r'['", "host 'unterminated"])
def test_malformed_override_retains_lower_definition(tmp_path, bad, caplog):
    lower = policy(tmp_path, "host r'[\\s\\S]*'\n", "lower")
    upper = policy(tmp_path, bad + "\n", "upper")
    audit(Config(vars_dirs=[lower, upper]))
    assert get_context().get_var("host").can_contain("\n")
    assert "model.cfg:1" in caplog.text


def test_same_layer_exact_and_longest_prefix_win(tmp_path):
    directory = policy(
        tmp_path, "layer_ none\nlayer_more_ none\nlayer_more_exact r'[\\s\\S]*'\n"
    )
    audit(Config(vars_dirs=[directory]))
    assert get_context().get_var("layer_more_exact").can_contain("\n")


def test_sequential_audits_do_not_leak_custom_models(tmp_path):
    directory = policy(tmp_path, "arg_ none\n")
    audit(Config(vars_dirs=[directory]))
    assert not get_context().get_var("arg_probe").can_contain(".")
    purge_context()
    audit()
    assert get_context().get_var("arg_probe").can_contain(".")


def test_brotli_retains_real_security_findings():
    content = """http { server { location / {
        add_header X-Ratio $brotli_ratio;
        add_header X-Request $uri;
        proxy_pass http://$brotli_ratio;
    } } }"""
    manager = audit(Config(plugins=["http_splitting", "ssrf"]), content)
    results = {plugin.__class__.__name__: plugin.issues for plugin in manager.results}
    assert len(results["http_splitting"]) == 1
    assert len(results["ssrf"]) == 1


def test_request_host_ssrf_remains():
    manager = audit(
        Config(plugins=["ssrf"]),
        "http { server { location / { proxy_pass http://$http_host; } } }",
    )
    assert len(list(manager.results)[0].issues) == 1


def test_context_defined_variable_overrides_catalog(tmp_path):
    directory = policy(tmp_path, "probe r'[\\s\\S]*'\n")
    manager = audit(
        Config(vars_dirs=[directory], plugins=["http_splitting"]),
        'http { server { set $probe "fixed"; add_header X $probe; } }',
    )
    assert list(manager.results) == []


def test_higher_prefix_overrides_lower_exact(tmp_path):
    lower = policy(tmp_path, "probe_exact r'[\\s\\S]*'\n", "lower")
    upper = policy(tmp_path, "probe_ none\n", "upper")
    audit(Config(vars_dirs=[lower, upper]))
    assert not get_context().get_var("probe_exact").can_contain("\n")


def test_longest_prefix_and_exact_ignore_insertion_order(tmp_path):
    import itertools

    from gixy.core.variable_catalog import load_variable_catalog

    lines = ("probe_ none", "probe_more_ r'[\\s\\S]*'", 'probe_more_exact "literal"')
    for index, order in enumerate(itertools.permutations(lines)):
        directory = policy(tmp_path, "\n".join(order), str(index))
        catalog = load_variable_catalog([directory])
        assert catalog.variable("probe_more_other").can_contain("\n")
        assert catalog.variable("probe_more_exact").value == "literal"
        assert not catalog.variable("probe_other").can_contain("\n")


def test_sorted_files_lines_suffixes_and_provenance(tmp_path):
    from gixy.core.variable_catalog import load_variable_catalog

    directory = policy(tmp_path, "probe none\n")
    path = tmp_path / "policy" / "z-last.conf"
    path.write_text("probe none\nprobe r'[\\s\\S]*'\nprobe r'['\n")
    (tmp_path / "policy" / "zz-ignored.txt").write_text("probe none\n")
    catalog = load_variable_catalog([directory])
    definition = catalog.resolve("probe")
    assert definition.source == str(path)
    assert definition.line == 2
    assert definition.layer == 1
    assert definition.kind == "regex"
    assert catalog.variable("probe").can_contain("\n")


@pytest.mark.parametrize(
    "bad",
    [
        "host :",
        "host r'[z-a]'",
        "host r'(unfinished'",
        'host "x" trailing',
        "host 'x\"",
        "bad-name none",
        "9host none",
        "höst none",
    ],
)
def test_invalid_entry_warns_without_losing_valid_neighbors(tmp_path, caplog, bad):
    from gixy.core.variable_catalog import load_variable_catalog

    directory = policy(tmp_path, "before none\n" + bad + "\nafter none\n")
    catalog = load_variable_catalog([directory])
    assert catalog.resolve("before") is not None
    assert catalog.resolve("after") is not None
    assert "model.cfg:2" in caplog.text
    assert "invalid variable definition" in caplog.text


@pytest.mark.parametrize("value", ["none", "NULL", "''", '""'])
def test_explicit_trusted_assertions(tmp_path, value):
    directory = policy(tmp_path, "probe = " + value + ",\n")
    audit(Config(vars_dirs=[directory]))
    assert not get_context().get_var("probe").can_contain("\n")


@pytest.mark.parametrize("value", ["r'[\\s\\S]*'", 'R"[\\s\\S]*"', "[\\s\\S]*"])
def test_raw_and_legacy_regexes(tmp_path, value):
    directory = policy(tmp_path, "probe: " + value + ",\n")
    audit(Config(vars_dirs=[directory]))
    assert get_context().get_var("probe").can_contain("\n")


def test_failed_load_and_repeated_same_manager_do_not_leak(tmp_path, caplog):
    directory = policy(tmp_path, "arg_ none\n")
    manager = audit(Config(vars_dirs=[directory]))
    first_catalog = get_context().catalog
    manager.config.vars_dirs = [str(tmp_path / "missing")]
    manager.audit("inline.conf", io.StringIO("http {}"), is_stdin=True)
    assert get_context().catalog is not first_catalog
    assert get_context().get_var("arg_probe").can_contain(".")
    assert "missing" in caplog.text
    assert not builtins.builtin_var("arg_probe").can_contain("\n")
    assert builtins.builtin_var("arg_probe").can_contain(".")


def test_context_children_share_only_their_audit_catalog(tmp_path):
    import copy

    directory = policy(tmp_path, "probe none\n")
    audit(Config(vars_dirs=[directory]))
    original = get_context()
    child = copy.deepcopy(original)
    assert child.catalog is original.catalog
    assert child.variables is not original.variables
    audit()
    assert get_context().catalog is not child.catalog
    assert get_context().get_var("probe") is None
    assert child.get_var("probe") is not None


def test_missing_resolver_reads_audit_catalog_and_preserves_context_values(tmp_path):
    directory = policy(tmp_path, 'probe "public.example.com"\n')
    manager = audit(
        Config(vars_dirs=[directory], plugins=["missing_resolver"]),
        "http { server { location / { proxy_pass http://$probe; } } }",
    )
    assert list(manager.results) == []
    manager = audit(
        Config(plugins=["missing_resolver"]),
        "http { server { set $probe public.example.com; location / { proxy_pass http://$probe; } } }",
    )
    assert len(list(manager.results)[0].issues) == 1


@pytest.mark.parametrize(
    "name, definition, directive",
    [
        ("probe", "probe none\n", "set $probe public.example.com;"),
        ("probe_suffix", "probe_ none\n", "set $probe_suffix public.example.com;"),
        ("host", None, "set $host public.example.com;"),
        ("document_root", None, "root public.example.com;"),
    ],
)
def test_missing_resolver_keeps_config_defined_values_over_catalog(
    tmp_path, name, definition, directive
):
    directories = [policy(tmp_path, definition)] if definition is not None else None
    content = "http { server { %s location / { proxy_pass http://$%s; } } }" % (
        directive,
        name,
    )
    manager = audit(
        Config(vars_dirs=directories, plugins=["missing_resolver"]), content
    )
    assert sum(len(plugin.issues) for plugin in manager.results) == 1


@pytest.mark.parametrize(
    "name, definition",
    [("probe", "probe none\n"), ("probe_suffix", "probe_ none\n"), ("host", None)],
)
def test_missing_resolver_catalog_only_models_remain_unresolvable(
    tmp_path, name, definition
):
    directories = [policy(tmp_path, definition)] if definition is not None else None
    content = "http { server { location / { proxy_pass http://$%s; } } }" % name
    manager = audit(
        Config(vars_dirs=directories, plugins=["missing_resolver"]), content
    )
    assert list(manager.results) == []
