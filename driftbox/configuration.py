"""Persistent, schema-validated Driftbox configuration."""

from __future__ import annotations

import json
import os
import platform
import tempfile
from copy import deepcopy
from pathlib import Path

CONFIG_SCHEMA_VERSION = 1
DEFAULT_SETTINGS = {
    "history_retention_days": 30,
    "default_baseline": "latest",
    "integrity_targets": [],
    "scan_output": "human",
}


def configuration_directory() -> Path:
    """Return the platform-appropriate per-user configuration directory."""
    override = os.environ.get("DRIFTBOX_CONFIG_DIR")
    if override:
        return Path(override).expanduser()
    operating_system = platform.system()
    if operating_system == "Windows":
        local_app_data = os.environ.get("LOCALAPPDATA")
        if not local_app_data:
            raise ValueError("LOCALAPPDATA is not set")
        return Path(local_app_data) / "Driftbox"
    if operating_system == "Darwin":
        return Path.home() / "Library" / "Application Support" / "Driftbox"
    config_home = os.environ.get("XDG_CONFIG_HOME")
    if config_home:
        return Path(config_home).expanduser() / "driftbox"
    return Path.home() / ".config" / "driftbox"


def configuration_path() -> Path:
    """Return the active configuration file path."""
    return configuration_directory() / "config.json"


def default_configuration() -> dict[str, object]:
    """Return an independent copy of the default configuration."""
    return {
        "schema_version": CONFIG_SCHEMA_VERSION,
        "settings": deepcopy(DEFAULT_SETTINGS),
    }


def _validate_integrity_targets(value: object) -> list[dict[str, str]]:
    if not isinstance(value, list):
        raise ValueError("integrity_targets must be a JSON array")
    targets = []
    for index, target in enumerate(value):
        if not isinstance(target, dict) or set(target) != {"path", "manifest"}:
            raise ValueError(
                f"integrity target {index} must contain only path and manifest"
            )
        path = target["path"]
        manifest = target["manifest"]
        if not isinstance(path, str) or not path:
            raise ValueError(f"integrity target {index} has an invalid path")
        if not isinstance(manifest, str) or not manifest:
            raise ValueError(f"integrity target {index} has an invalid manifest")
        targets.append({"path": path, "manifest": manifest})
    return targets


def validate_setting(key: str, value: object) -> object:
    """Validate and normalize one supported configuration setting."""
    if key not in DEFAULT_SETTINGS:
        raise ValueError(f"unknown configuration key: {key}")
    if key == "history_retention_days":
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError("history_retention_days must be a positive integer")
        return value
    if key == "default_baseline":
        if value != "latest":
            raise ValueError("default_baseline must currently be 'latest'")
        return value
    if key == "integrity_targets":
        return _validate_integrity_targets(value)
    if value not in ("human", "json"):
        raise ValueError("scan_output must be 'human' or 'json'")
    return value


def validate_configuration(configuration: object) -> dict[str, object]:
    """Validate a complete configuration document."""
    if not isinstance(configuration, dict):
        raise ValueError("configuration must be a JSON object")
    version = configuration.get("schema_version")
    if type(version) is not int or version != CONFIG_SCHEMA_VERSION:
        raise ValueError("unsupported configuration schema version")
    settings = configuration.get("settings")
    if not isinstance(settings, dict):
        raise ValueError("configuration settings must be a JSON object")
    if set(settings) != set(DEFAULT_SETTINGS):
        unknown = sorted(set(settings) - set(DEFAULT_SETTINGS))
        if unknown:
            raise ValueError(f"unknown configuration key: {unknown[0]}")
        raise ValueError("configuration is missing required settings")
    return {
        "schema_version": CONFIG_SCHEMA_VERSION,
        "settings": {
            key: validate_setting(key, settings[key])
            for key in DEFAULT_SETTINGS
        },
    }


def write_configuration(configuration: object) -> dict[str, object]:
    """Validate and atomically write the configuration."""
    validated = validate_configuration(configuration)
    path = configuration_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            prefix=".config-",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)
            json.dump(validated, temporary_file, indent=2, sort_keys=True)
            temporary_file.write("\n")
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
    return validated


def load_configuration() -> dict[str, object]:
    """Load configuration, creating defaults when none exists."""
    path = configuration_path()
    if not path.exists():
        return write_configuration(default_configuration())
    with path.open(encoding="utf-8-sig") as config_file:
        return validate_configuration(json.load(config_file))


def parse_setting_value(key: str, text: str) -> object:
    """Parse a CLI value according to its setting type."""
    if key not in DEFAULT_SETTINGS:
        raise ValueError(f"unknown configuration key: {key}")
    if key in ("history_retention_days", "integrity_targets"):
        try:
            value = json.loads(text)
        except json.JSONDecodeError as error:
            raise ValueError(f"invalid JSON value for {key}: {error}") from error
    else:
        value = text
    return validate_setting(key, value)


def set_configuration_value(key: str, text: str) -> dict[str, object]:
    """Update one setting while preserving all other valid settings."""
    configuration = load_configuration()
    settings = configuration["settings"]
    if not isinstance(settings, dict):
        raise ValueError("configuration settings must be a JSON object")
    settings[key] = parse_setting_value(key, text)
    return write_configuration(configuration)


def reset_configuration() -> dict[str, object]:
    """Replace configuration with validated defaults."""
    return write_configuration(default_configuration())
