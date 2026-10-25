import logging
import os

import gixy
from gixy.core import builtin_variables as builtins
from gixy.core.config import Config
from gixy.core.context import get_context, pop_context, purge_context, push_context
from gixy.core.plugins_manager import PluginsManager
from gixy.core.regexp import Regexp
from gixy.core.variable import Variable
from gixy.core.variable_catalog import load_variable_catalog
from gixy.directives.block import GeoBlock, Geoip2Block, MapBlock, SetByLuaBlock
from gixy.directives.directive import (
    AuthRequestSetDirective,
    MapDirective,
    JsSetDirective,
    JsVarDirective,
    PerlSetDirective,
    RootDirective,
    SetByLuaDirective,
    SetByLuaFileDirective,
    SetDirective,
)
from gixy.parser.nginx_parser import NginxParser

SCOPE_STATIC_SET_DIRECTIVES = (
    SetDirective,
    AuthRequestSetDirective,
    PerlSetDirective,
    SetByLuaDirective,
    SetByLuaFileDirective,
    SetByLuaBlock,
    JsSetDirective,
    JsVarDirective,
)

LOG = logging.getLogger(__name__)


class Manager:
    def __init__(self, config=None):
        self.root = None
        self.config = config or Config()
        self.auditor = PluginsManager(config=self.config)
        self._declaration_overrides = {}

    def audit(self, file_path, file_data, is_stdin=False):
        LOG.debug(f"Audit config file: {file_path}")
        self._declaration_overrides = {}
        purge_context()
        catalog = load_variable_catalog(
            self.config.vars_dirs, self.config.load_default_vars
        )
        parser = NginxParser(
            cwd=os.path.dirname(file_path) if not is_stdin else "",
            allow_includes=self.config.allow_includes,
        )
        if is_stdin:
            # Route stdin through parse_string for consistent path-based parsing via tempfile
            self.root = parser.parse_string(
                content=file_data.read(), path_info=file_path
            )
        else:
            # Prefer path-based parsing to avoid temporary files
            self.root = parser.parse_file(file_path)

        purge_context()
        push_context(self.root, catalog=catalog)
        self._audit_recursive(self.root.children)
        # Call post_audit hooks after all directives have been processed
        self.auditor.post_audit(self.root)

    @property
    def results(self):
        for plugin in self.auditor.plugins:
            if plugin.issues:
                yield plugin

    @property
    def stats(self):
        stats = dict.fromkeys(gixy.severity.ALL, 0)
        for plugin in self.auditor.plugins:
            base_severity = plugin.severity
            for issue in plugin.issues:
                # TODO(buglloc): encapsulate into Issue class?
                severity = issue.severity if issue.severity else base_severity
                stats[severity] += 1
        return stats

    def _audit_recursive(self, tree):
        # Pre-populate scope-wide variables so nested blocks see `set`-like
        # directives that appear later in source order. Matches nginx's
        # parse-time variable registration (see issue #100).
        self._prepare_scope_declarations(tree)
        self._prepopulate_scope_var_names(tree)
        self._prepopulate_scope_var_values(tree)
        for directive in tree:
            self._update_variables(directive)
            self.auditor.audit(directive)
            if directive.is_block:
                if directive.self_context:
                    push_context(directive)
                self._audit_recursive(directive.children)
                if directive.self_context:
                    pop_context()

    def _prepare_scope_declarations(self, tree):
        """Finalize GeoIP2 aliases before any sibling compiles a value.

        Args:
            tree (list): Expanded sibling nodes in the current context.
        """
        context = get_context()
        main = context.block
        if (
            main.name not in ("http", "stream")
            or main.parent is None
            or main.parent.name is not None
        ):
            return
        declarations = {}
        for node in tree:
            if isinstance(node, Geoip2Block):
                for var in node.declared_variables:
                    declarations.setdefault(var.name, []).append(var)
        for name, aliases in declarations.items():
            competitors = []
            for node in tree:
                if (
                    isinstance(
                        node,
                        (
                            MapBlock,
                            GeoBlock,
                            PerlSetDirective,
                            JsSetDirective,
                            JsVarDirective,
                        ),
                    )
                    and node.provide_variables
                    and node.variable.lower() == name
                ):
                    competitors.append(node)
            selected = aliases[-1]
            if competitors:
                selected = Variable(
                    name, Regexp(r"[\s\S]*"), provider=selected.provider
                )
                selected.depends = aliases[:-1] + [
                    Variable(name, Regexp(r"[\s\S]*"), provider=node)
                    for node in competitors
                ]
                LOG.warning(
                    "Variable $%s provider collision at %s; rename overlapping "
                    "GeoIP2/map/geo/script destinations to establish precedence",
                    name,
                    ", ".join(
                        "%s:%s" % (node.file, node.line) for node in selected.providers
                    ),
                )
                for node in competitors:
                    self._declaration_overrides[(node, name)] = selected
            context.add_var(name, selected)

    def _selected_variable(self, directive, var):
        """Apply only audit-owned, unscoped destination collision overrides."""
        if var.ctx is None and isinstance(var.name, str):
            return self._declaration_overrides.get((directive, var.name.lower()), var)
        return var

    def _prepopulate_scope_var_names(self, tree):
        """Register placeholder names for every set-like var in this scope.

        Walks `tree` and any nested non-self_context blocks, adding a
        ``builtins.fake_var(name)`` for each set-like directive's variable
        name not yet present in the current context. Done before value
        compilation (step B) so forward references within the same scope
        resolve and do not log spurious "Can't find variable" INFO records.

        Args:
            tree: Iterable of sibling directives in the current scope.
        """
        context = get_context()
        for directive in tree:
            if (
                isinstance(directive, SCOPE_STATIC_SET_DIRECTIVES)
                and directive.provide_variables
            ):
                name = directive.variable
                if name.lower() not in context.variables["name"]:
                    context.add_var(name, builtins.fake_var(name))
            elif isinstance(directive, RootDirective):
                if "document_root" not in context.variables["name"]:
                    context.add_var("document_root", builtins.fake_var("document_root"))
            elif directive.is_block and not directive.self_context:
                self._prepopulate_scope_var_names(directive.children)

    def _prepopulate_scope_var_values(self, tree):
        """Replace placeholder names with real Variable objects.

        Walks the same scope as :meth:`_prepopulate_scope_var_names` and
        instantiates each set-like directive's full ``Variable`` (with value,
        provider, and depends), overwriting the placeholder. Nested blocks
        pushed during the main pass deepcopy these real Variables.

        Args:
            tree: Iterable of sibling directives in the current scope.
        """
        context = get_context()
        for directive in tree:
            if (
                isinstance(directive, SCOPE_STATIC_SET_DIRECTIVES + (RootDirective,))
                and directive.provide_variables
            ):
                for var in directive.variables:
                    context.add_var(var.name, self._selected_variable(directive, var))
            elif directive.is_block and not directive.self_context:
                # Register vars the block itself provides (e.g. IfBlock regex
                # capture groups) before recursing, so nested set-like
                # directives can resolve them during prepopulate instead of
                # logging a spurious "Can't find variable" warning. Mirrors
                # _update_variables; safe to re-run there because add_var
                # overwrites with the same Variable.
                if directive.provide_variables:
                    for var in directive.variables:
                        if var.name == 0:
                            context.clear_index_vars()
                        context.add_var(
                            var.name, self._selected_variable(directive, var)
                        )
                self._prepopulate_scope_var_values(directive.children)

    def _update_variables(self, directive):
        # TODO(buglloc): finish him!
        if not directive.provide_variables:
            return

        context = get_context()
        for var in directive.variables:
            if var.name == 0 and not isinstance(directive, MapDirective):
                # All regexps must clean indexed variables
                context.clear_index_vars()
            context.add_var(var.name, self._selected_variable(directive, var))

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        purge_context()
