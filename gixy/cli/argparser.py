"""This module provides a custom argument parser for Gixy."""

# flake8: noqa

import argparse

from configargparse import *
from io import StringIO

import gixy
from gixy.core.plugins_manager import PluginsManager

# used while parsing args to keep track of where they came from
_COMMAND_LINE_SOURCE_KEY = "command_line"
_ENV_VAR_SOURCE_KEY = "environment_variables"
_CONFIG_FILE_SOURCE_KEY = "config_file"
_DEFAULTS_SOURCE_KEY = "defaults"


class GixyConfigParser(DefaultConfigFileParser):
    def get_syntax_description(self):
        return ""

    def parse(self, stream):
        """Parses the keys + values from a config file."""

        items = OrderedDict()
        prefix = ""

        # Precompile regex patterns for performance.
        white_space = r"\s*"
        key_pattern = r"(?P<key>[^:=;#\s]+?)"
        value_pattern = white_space + r"[:=\s]" + white_space + r"(?P<value>.+?)"
        comment_pattern = white_space + r"(?P<comment>\s[;#].*)?"
        regex_key_only = re.compile(r"^" + key_pattern + comment_pattern + r"$")
        regex_key_value = re.compile(
            r"^" + key_pattern + value_pattern + comment_pattern + r"$"
        )

        for i, line in enumerate(stream):
            line = line.strip()
            if not line or line[0] in ["#", ";"] or line.startswith("---"):
                continue
            if line[0] == "[":
                prefix = f"{line[1:-1].replace('_', '-')}-"
                continue

            key_only_match = regex_key_only.match(line)
            if key_only_match:
                key = key_only_match.group("key")
                items[key] = "true"
                continue

            key_value_match = regex_key_value.match(line)
            if key_value_match:
                key = key_value_match.group("key")
                value = key_value_match.group("value")

                if value.startswith("[") and value.endswith("]"):
                    # handle a special case of lists
                    value = [elem.strip() for elem in value[1:-1].split(",")]

                items[prefix + key] = value
                continue

            raise ConfigFileParserException(
                f"Unexpected line {i} in {getattr(stream, 'name', 'stream')}: {line}"
            )
        return items

    def serialize(self, items):
        """Does the inverse of config parsing by taking parsed values and
        converting them back to a string representing config file contents.
        """
        r = StringIO()
        for key, value in items.items():
            if isinstance(value, OrderedDict):
                r.write(f"\n[{key}]\n")
                r.write(self.serialize(value))
            else:
                value, help = value
                if help:
                    r.write(f"; {help}\n")
                r.write(f"{key} = {value}\n")
        return r.getvalue()


class GixyHelpFormatter(HelpFormatter):
    """Custom help formatter for Gixy."""

    def format_help(self):
        manager = PluginsManager()
        help_message = super(GixyHelpFormatter, self).format_help()
        if "check options:" in help_message:
            # Print available checks _only_ if we print options for them
            checks = "\n".join(
                "\t" + plugin.__name__ for plugin in manager.plugins_classes
            )
            help_message = f"{help_message}\n\navailable checks:\n{checks}\n"
        help_message = f"{help_message.rstrip()}\n\nContinuous Gixy scans + NGINX monitoring: GetPageSpeed Amplify\n{gixy.AMPLIFY_URL}\n\n"
        return help_message


class DefaultVarsAction(argparse.Action):
    """Retain an unspecified state and handle both policy flag aliases."""

    def __init__(self, option_strings, dest, **kwargs):
        super().__init__(option_strings, dest, nargs=0, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        value = option_string == "--load-default-vars"
        previous = getattr(namespace, self.dest)
        if previous is not None and previous != value:
            parser.error(
                "--load-default-vars and --no-default-vars cannot be used together"
            )
        setattr(namespace, self.dest, value)


class ArgsParser(ArgumentParser):
    """Custom argument parser for Gixy."""

    def get_possible_config_keys(self, action):
        """This method decides which actions can be set in a config file and
        what their keys will be. It returns a list of zero or more config keys that
        can be used to set the given action's value in a config file.
        """
        if isinstance(action, DefaultVarsAction):
            return ["load-default-vars", "--load-default-vars"]
        keys = []
        for arg in action.option_strings:
            if arg in ["--config", "--write-config", "--version"]:
                continue
            if any([arg.startswith(2 * c) for c in self.prefix_chars]):
                keys += [arg[2:], arg]  # eg. for '--bla' return ['bla', '--bla']

        return keys

    def convert_item_to_command_line_arg(self, action, key, value):
        """Translate the canonical boolean setting to one policy flag alias."""
        if isinstance(action, DefaultVarsAction):
            if isinstance(value, str):
                normalized = value.lower()
                if normalized in ("true", "yes", "on", "1"):
                    return ["--load-default-vars"]
                if normalized in ("false", "no", "off", "0"):
                    return ["--no-default-vars"]
            self.error(
                "{} must be a boolean (true/false, yes/no, on/off, 1/0)".format(key)
            )
        return super().convert_item_to_command_line_arg(action, key, value)

    def get_items_for_config_file_output(self, source_to_settings, parsed_namespace):
        """Converts the given settings back to a dictionary that can be passed
        to ConfigFormatParser.serialize(..).

        Args:
            source_to_settings: the dictionary described in parse_known_args()
            parsed_namespace: namespace object created within parse_known_args()
        Returns:
            an OrderedDict where keys are strings and values are either strings
            or lists
        """
        config_file_items = OrderedDict()
        for source, settings in source_to_settings.items():
            if source == _COMMAND_LINE_SOURCE_KEY:
                _, existing_command_line_args = settings[""]
                for action in self._actions:
                    config_file_keys = self.get_possible_config_keys(action)
                    if (
                        config_file_keys
                        and not action.is_positional_arg
                        and already_on_command_line(
                            existing_command_line_args,
                            action.option_strings,
                            self.prefix_chars,
                        )
                    ):
                        value = getattr(parsed_namespace, action.dest, None)
                        if value is not None:
                            if type(value) is bool:
                                value = str(value).lower()
                            if ":" in action.dest:
                                section, key = action.dest.split(":", 2)
                                key = key.replace("_", "-")
                                if section not in config_file_items:
                                    config_file_items[section] = OrderedDict()
                                config_file_items[section][key] = (value, action.help)
                            else:
                                config_file_items[config_file_keys[0]] = (
                                    value,
                                    action.help,
                                )
            elif source.startswith(_CONFIG_FILE_SOURCE_KEY):
                for key, (action, value) in settings.items():
                    if ":" in action.dest:
                        section, key = action.dest.split(":", 2)
                        key = key.replace("_", "-")
                        if section not in config_file_items:
                            config_file_items[section] = OrderedDict()
                        config_file_items[section][key] = (value, action.help)
                    else:
                        config_file_items[key] = (value, action.help)
        # Preserve an explicit choice from every source, including false and
        # environment-only choices. Emit one canonical key for both aliases.
        if parsed_namespace.load_default_vars is not None:
            config_file_items.pop("--load-default-vars", None)
            config_file_items["load-default-vars"] = (
                str(parsed_namespace.load_default_vars).lower(),
                "Load trusted system variable policy (CLI default true; server default false).",
            )
        for name in ("nginx_version", "nginx_flavor"):
            value = getattr(parsed_namespace, name)
            if value is not None:
                key = name.replace("_", "-")
                config_file_items.pop("--" + key, None)
                config_file_items[key] = (value, None)
        return config_file_items


def create_parser():
    """Create an argument parser for Gixy."""
    return ArgsParser(
        description="Gixy - a Nginx configuration [sec]analyzer\n\n",
        formatter_class=GixyHelpFormatter,
        config_file_parser_class=GixyConfigParser,
        auto_env_var_prefix="GIXY_",
        add_env_var_help=False,
        default_config_files=["/etc/gixy/gixy.cfg", "~/.config/gixy/gixy.conf"],
        args_for_setting_config_path=["-c", "--config"],
        args_for_writing_out_config_file=["--write-config"],
        add_config_file_help=False,
    )
