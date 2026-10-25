"""Check filesystem trust at the policy loader's OS boundary."""

import os
import stat

import pytest

from gixy.core import variable_catalog as policy


def root_view(monkeypatch, exceptions=None):
    """Model safe root-owned ancestors without requiring host root privileges."""
    original = os.fstat
    exceptions = exceptions or {}

    def fstat(descriptor):
        info = original(descriptor)
        values = list(info)
        values[0] &= ~(stat.S_IWGRP | stat.S_IWOTH)
        values[4] = 0
        for index, value in exceptions.get(info.st_ino, {}).items():
            values[index] = value
        return os.stat_result(values)

    monkeypatch.setattr(policy.os, "fstat", fstat)


@pytest.fixture
def tree(tmp_path, monkeypatch):
    vendor = tmp_path / "vendor"
    admin = tmp_path / "admin"
    vendor.mkdir()
    admin.mkdir()
    (vendor / "model.cfg").write_text("brotli_ratio r'[\\s\\S]*'\n")
    monkeypatch.setattr(policy, "DEFAULT_VARIABLE_DIRS", (str(vendor), str(admin)))
    return vendor, admin


def test_defaults_are_opt_in_and_explicit_layers_are_above_them(
    tree, tmp_path, monkeypatch
):
    vendor, admin = tree
    root_view(monkeypatch)
    assert not policy.load_variable_catalog().variable("brotli_ratio").can_contain("\n")
    assert (
        policy.load_variable_catalog(load_default_vars=True)
        .variable("brotli_ratio")
        .can_contain("\n")
    )
    (admin / "model.conf").write_text("brotli_ none\n")
    catalog = policy.load_variable_catalog(load_default_vars=True)
    assert not catalog.variable("brotli_ratio").can_contain("\n")
    assert catalog.resolve("brotli_ratio").source == str(admin / "model.conf")
    explicit = tmp_path / "explicit"
    explicit.mkdir()
    (explicit / "model.cfg").write_text("brotli_ratio r'[\\s\\S]*'\n")
    catalog = policy.load_variable_catalog([str(explicit)], True)
    assert catalog.variable("brotli_ratio").can_contain("\n")
    assert catalog.resolve("brotli_ratio").layer == 3


@pytest.mark.parametrize("target", ["file", "directory", "ancestor"])
@pytest.mark.parametrize("defect", ["owner", "group_writable", "world_writable"])
def test_unsafe_metadata_is_rejected(tree, monkeypatch, caplog, target, defect):
    vendor, _ = tree
    selected = {
        "file": vendor / "model.cfg",
        "directory": vendor,
        "ancestor": vendor.parent,
    }[target]
    info = selected.stat()
    changes = (
        {4: 501}
        if defect == "owner"
        else {
            0: info.st_mode
            | (stat.S_IWGRP if defect == "group_writable" else stat.S_IWOTH)
        }
    )
    root_view(monkeypatch, {info.st_ino: changes})
    catalog = policy.load_variable_catalog(load_default_vars=True)
    assert not catalog.variable("brotli_ratio").can_contain("\n")
    assert str(selected) in caplog.text
    assert "root-owned" in caplog.text


@pytest.mark.parametrize("target", ["file", "directory", "ancestor"])
def test_symlinks_are_rejected(tree, tmp_path, monkeypatch, caplog, target):
    vendor, admin = tree
    root_view(monkeypatch)
    if target == "file":
        source = vendor / "model.cfg"
        source.rename(vendor / "real.txt")
        source.symlink_to(vendor / "real.txt")
    elif target == "directory":
        renamed = tmp_path / "real-vendor"
        vendor.rename(renamed)
        vendor.symlink_to(renamed, target_is_directory=True)
    else:
        alias = tmp_path / "alias"
        alias.symlink_to(vendor.parent, target_is_directory=True)
        monkeypatch.setattr(
            policy, "DEFAULT_VARIABLE_DIRS", (str(alias / "vendor"), str(admin))
        )
    catalog = policy.load_variable_catalog(load_default_vars=True)
    assert not catalog.variable("brotli_ratio").can_contain("\n")
    assert "Cannot load variable policy" in caplog.text


def test_non_regular_policy_files_do_not_block_or_load(tree, monkeypatch, caplog):
    vendor, _ = tree
    root_view(monkeypatch)
    (vendor / "model.cfg").unlink()
    os.mkfifo(str(vendor / "fifo.cfg"))
    (vendor / "directory.cfg").mkdir()
    assert (
        not policy.load_variable_catalog(load_default_vars=True)
        .variable("brotli_ratio")
        .can_contain("\n")
    )
    assert "regular file" in caplog.text


def test_missing_defaults_are_quiet_and_never_created(tmp_path, monkeypatch, caplog):
    missing = tmp_path / "missing"
    root_view(monkeypatch)
    monkeypatch.setattr(policy, "DEFAULT_VARIABLE_DIRS", (str(missing),))
    policy.load_variable_catalog(load_default_vars=True)
    assert not missing.exists()
    assert not caplog.records
    policy.load_variable_catalog([str(missing)])
    assert str(missing) in caplog.text


def test_explicit_nonroot_writable_directory_and_tilde_work(tmp_path, monkeypatch):
    directory = tmp_path / "user-policy"
    directory.mkdir(mode=0o777)
    (directory / "model.cfg").write_text("brotli_ratio r'[\\s\\S]*'\n")
    monkeypatch.setenv("HOME", str(tmp_path))
    assert (
        policy.load_variable_catalog(["~/user-policy"])
        .variable("brotli_ratio")
        .can_contain("\n")
    )


def test_unreadable_and_non_utf8_files_warn_and_preserve_lower(
    tree, tmp_path, monkeypatch, caplog
):
    vendor, _ = tree
    root_view(monkeypatch)
    explicit = tmp_path / "explicit"
    explicit.mkdir()
    (explicit / "broken.cfg").write_bytes(b"brotli_ratio \xff")
    catalog = policy.load_variable_catalog([str(explicit)], True)
    assert catalog.variable("brotli_ratio").can_contain("\n")
    assert "broken.cfg" in caplog.text
    original = policy.os.listdir

    def denied(path):
        if path == str(explicit):
            raise PermissionError("denied")
        return original(path)

    monkeypatch.setattr(policy.os, "listdir", denied)
    assert (
        policy.load_variable_catalog([str(explicit)], True)
        .variable("brotli_ratio")
        .can_contain("\n")
    )
    assert "denied" in caplog.text


def test_file_swap_to_symlink_between_listing_and_open_is_rejected(
    tree, monkeypatch, caplog
):
    vendor, _ = tree
    root_view(monkeypatch)
    original = policy.os.open
    source = vendor / "model.cfg"

    def replaced(path, flags, *args, **kwargs):
        if path == "model.cfg":
            source.rename(vendor / "held.txt")
            source.symlink_to(vendor / "held.txt")
        return original(path, flags, *args, **kwargs)

    # supports_dir_fd contains the original function, so preserve this capability
    # declaration when instrumenting the syscall boundary.
    monkeypatch.setattr(
        policy.os, "supports_dir_fd", policy.os.supports_dir_fd | {replaced}
    )
    monkeypatch.setattr(policy.os, "open", replaced)
    assert (
        not policy.load_variable_catalog(load_default_vars=True)
        .variable("brotli_ratio")
        .can_contain("\n")
    )
    assert "model.cfg" in caplog.text


def test_directory_swap_after_listing_still_reads_held_directory(
    tree, tmp_path, monkeypatch
):
    vendor, _ = tree
    root_view(monkeypatch)
    original = policy.os.listdir
    moved = tmp_path / "held-directory"
    attacker = tmp_path / "attacker"
    attacker.mkdir()
    (attacker / "model.cfg").write_text("brotli_ratio none\n")
    swapped = []

    def replaced(descriptor):
        entries = original(descriptor)
        if not swapped:
            vendor.rename(moved)
            vendor.symlink_to(attacker, target_is_directory=True)
            swapped.append(True)
        return entries

    monkeypatch.setattr(policy.os, "listdir", replaced)
    assert (
        policy.load_variable_catalog(load_default_vars=True)
        .variable("brotli_ratio")
        .can_contain("\n")
    )


def test_library_audits_ignore_ambient_policy_until_enabled(tree, monkeypatch):
    import io

    from gixy.core.config import Config
    from gixy.core.manager import Manager

    root_view(monkeypatch)
    content = "http { server { add_header X $brotli_ratio; } }"
    for enabled, issue_count in ((False, 0), (True, 1), (False, 0)):
        config = Config(plugins=["http_splitting"], load_default_vars=enabled)
        with Manager(config) as manager:
            manager.audit("inline.conf", io.StringIO(content), is_stdin=True)
            assert sum(len(plugin.issues) for plugin in manager.results) == issue_count


def test_system_open_capability_failure_warns_and_retains_bundled(
    tree, monkeypatch, caplog
):
    monkeypatch.setattr(policy.os, "supports_dir_fd", set())
    catalog = policy.load_variable_catalog(load_default_vars=True)
    assert not catalog.variable("brotli_ratio").can_contain("\n")
    assert "safe no-follow directory loading is unavailable" in caplog.text


def test_missing_optional_directory_below_symlink_is_quiet_but_existing_is_rejected(
    tmp_path, monkeypatch, caplog
):
    real = tmp_path / "real"
    real.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    selected = alias / "optional"
    monkeypatch.setattr(policy, "DEFAULT_VARIABLE_DIRS", (str(selected),))
    root_view(monkeypatch)
    assert (
        not policy.load_variable_catalog(load_default_vars=True)
        .variable("brotli_ratio")
        .can_contain("\n")
    )
    assert not caplog.records
    (real / "optional").mkdir()
    (real / "optional" / "model.cfg").write_text("brotli_ratio r'[\\s\\S]*'\n")
    assert (
        not policy.load_variable_catalog(load_default_vars=True)
        .variable("brotli_ratio")
        .can_contain("\n")
    )
    assert "Cannot load variable policy directory" in caplog.text


def test_system_lstat_read_error_warns(tree, monkeypatch, caplog):
    vendor, _ = tree
    original = policy.os.lstat

    def denied(path, *args, **kwargs):
        if path == str(vendor):
            raise PermissionError("lstat denied")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(policy.os, "lstat", denied)
    catalog = policy.load_variable_catalog(load_default_vars=True)
    assert not catalog.variable("brotli_ratio").can_contain("\n")
    assert "lstat denied" in caplog.text
    assert str(vendor) in caplog.text


def test_system_directory_swap_after_lstat_is_rejected(
    tree, tmp_path, monkeypatch, caplog
):
    vendor, _ = tree
    root_view(monkeypatch)
    original = policy.os.lstat
    moved = tmp_path / "held-directory"
    swapped = []

    def replaced(path, *args, **kwargs):
        info = original(path, *args, **kwargs)
        if path == str(vendor) and not swapped:
            vendor.rename(moved)
            vendor.symlink_to(moved, target_is_directory=True)
            swapped.append(True)
        return info

    monkeypatch.setattr(policy.os, "lstat", replaced)
    catalog = policy.load_variable_catalog(load_default_vars=True)
    assert not catalog.variable("brotli_ratio").can_contain("\n")
    assert "Cannot load variable policy directory" in caplog.text
