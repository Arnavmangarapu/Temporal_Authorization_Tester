"""Load YAML without resolving credentials, contacting targets or executing tags."""

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode

from temporal_auth.config.models import TargetConfig
from temporal_auth.config.lifecycle import LifecycleConfig


class ConfigLoadError(ValueError):
    """A configuration cannot be loaded or violates the policy contract."""


class UniqueKeyLoader(yaml.SafeLoader):
    """Reject duplicate keys instead of silently overwriting policy values."""

    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[Any, Any]:
        self.flatten_mapping(node)
        mapping: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in mapping
            except TypeError as exc:
                raise ConstructorError(None, None, "unhashable mapping key", key_node.start_mark) from exc
            if duplicate:
                raise ConstructorError(None, None, "duplicate mapping key", key_node.start_mark)
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def load_config(path: str | Path) -> TargetConfig | LifecycleConfig:
    """Return validated configuration; error messages omit supplied field values."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ConfigLoadError("Cannot read configuration as UTF-8.") from exc
    return parse_config(text)


def parse_config(text: str) -> TargetConfig | LifecycleConfig:
    """Validate configuration text using the same contract as the file loader."""
    try:
        data = yaml.load(text, Loader=UniqueKeyLoader)
    except yaml.YAMLError as exc:
        # YAML exception messages can contain source lines with credentials.
        raise ConfigLoadError("Invalid YAML: check syntax, supported tags and duplicate keys.") from exc
    if not isinstance(data, dict):
        raise ConfigLoadError("Configuration must be a YAML mapping.")
    try:
        model = LifecycleConfig if data.get("schema_version") == "2" else TargetConfig
        return model.model_validate(data)
    except ValidationError as exc:
        issues = []
        for issue in exc.errors(include_input=False, include_url=False):
            location = ".".join(str(part) for part in issue["loc"]) or "configuration"
            issues.append(f"{location}: {issue['msg']}")
        raise ConfigLoadError("Invalid configuration:\n" + "\n".join(issues)) from exc
