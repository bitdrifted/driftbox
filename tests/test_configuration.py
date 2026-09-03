"""Tests for persistent Driftbox configuration."""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from driftbox.cli import (
    reset_configuration_command,
    set_configuration,
    show_configuration,
)
from driftbox.configuration import (
    configuration_directory,
    configuration_path,
    default_configuration,
    load_configuration,
    reset_configuration,
    set_configuration_value,
)


class ConfigurationStorageTests(unittest.TestCase):
    """Verify configuration location, validation, and atomic storage."""

    def test_override_creates_schema_versioned_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict("os.environ", {"DRIFTBOX_CONFIG_DIR": directory}):
                configuration = load_configuration()
                stored = json.loads(configuration_path().read_text(encoding="utf-8"))

        self.assertEqual(configuration, default_configuration())
        self.assertEqual(stored["schema_version"], 1)
        self.assertEqual(stored["settings"]["default_baseline"], "latest")
        self.assertEqual(stored["settings"]["integrity_targets"], [])

    def test_platform_specific_default_paths(self) -> None:
        with patch.dict(
            "os.environ",
            {"LOCALAPPDATA": "C:/Users/Test/AppData/Local"},
            clear=True,
        ):
            with patch(
                "driftbox.configuration.platform.system", return_value="Windows"
            ):
                self.assertEqual(
                    configuration_directory(),
                    Path("C:/Users/Test/AppData/Local/Driftbox"),
                )
        with patch.dict("os.environ", {}, clear=True):
            with (
                patch("driftbox.configuration.platform.system", return_value="Darwin"),
                patch(
                    "driftbox.configuration.Path.home",
                    return_value=Path("/Users/test"),
                ),
            ):
                self.assertEqual(
                    configuration_directory(),
                    Path("/Users/test/Library/Application Support/Driftbox"),
                )
        with patch.dict("os.environ", {"XDG_CONFIG_HOME": "/config"}, clear=True):
            with patch("driftbox.configuration.platform.system", return_value="Linux"):
                self.assertEqual(configuration_directory(), Path("/config/driftbox"))
        with patch.dict("os.environ", {}, clear=True):
            with (
                patch("driftbox.configuration.platform.system", return_value="Linux"),
                patch(
                    "driftbox.configuration.Path.home",
                    return_value=Path("/home/test"),
                ),
            ):
                self.assertEqual(
                    configuration_directory(), Path("/home/test/.config/driftbox")
                )

    def test_update_preserves_other_settings_and_reset_restores_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict("os.environ", {"DRIFTBOX_CONFIG_DIR": directory}):
                set_configuration_value("history_retention_days", "14")
                updated = set_configuration_value("scan_output", "json")
                reset = reset_configuration()

        self.assertEqual(updated["settings"]["history_retention_days"], 14)
        self.assertEqual(updated["settings"]["scan_output"], "json")
        self.assertEqual(updated["settings"]["default_baseline"], "latest")
        self.assertEqual(reset, default_configuration())

    def test_integrity_targets_are_validated_as_json(self) -> None:
        value = '[{"path":"files","manifest":"manifest.json"}]'
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict("os.environ", {"DRIFTBOX_CONFIG_DIR": directory}):
                configuration = set_configuration_value("integrity_targets", value)

        self.assertEqual(
            configuration["settings"]["integrity_targets"],
            [{"path": "files", "manifest": "manifest.json"}],
        )

    def test_unknown_and_invalid_values_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict("os.environ", {"DRIFTBOX_CONFIG_DIR": directory}):
                with self.assertRaisesRegex(ValueError, "unknown configuration key"):
                    set_configuration_value("secret", "value")
                with self.assertRaisesRegex(ValueError, "positive integer"):
                    set_configuration_value("history_retention_days", "0")
                with self.assertRaisesRegex(ValueError, "human.*json"):
                    set_configuration_value("scan_output", "xml")

    def test_write_is_atomic_and_leaves_no_temporary_file(self) -> None:
        real_replace = os.replace
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch.dict("os.environ", {"DRIFTBOX_CONFIG_DIR": directory}),
                patch(
                    "driftbox.configuration.os.replace", wraps=real_replace
                ) as replace,
            ):
                load_configuration()
                set_configuration_value("scan_output", "json")
                temporary_files = list(Path(directory).glob("*.tmp"))

        self.assertEqual(replace.call_count, 2)
        self.assertEqual(temporary_files, [])

    def test_corrupt_configuration_is_not_silently_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text("{invalid", encoding="utf-8")
            with patch.dict("os.environ", {"DRIFTBOX_CONFIG_DIR": directory}):
                with self.assertRaises(json.JSONDecodeError):
                    load_configuration()
            self.assertEqual(path.read_text(encoding="utf-8"), "{invalid")


class ConfigurationCommandTests(unittest.TestCase):
    """Verify configuration command output and exit codes."""

    def test_show_json_set_and_reset(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = io.StringIO()
            with (
                patch.dict("os.environ", {"DRIFTBOX_CONFIG_DIR": directory}),
                redirect_stdout(output),
            ):
                self.assertEqual(show_configuration(json_output=True), 0)
                shown = json.loads(output.getvalue())
                output.seek(0)
                output.truncate(0)
                self.assertEqual(set_configuration("scan_output", "json"), 0)
                self.assertEqual(reset_configuration_command(), 0)

        self.assertEqual(shown["schema_version"], 1)

    def test_corrupt_and_unknown_configuration_return_two(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "config.json").write_text("[]", encoding="utf-8")
            errors = io.StringIO()
            with (
                patch.dict("os.environ", {"DRIFTBOX_CONFIG_DIR": directory}),
                redirect_stderr(errors),
            ):
                show_exit = show_configuration()
                set_exit = set_configuration("unknown", "value")

        self.assertEqual(show_exit, 2)
        self.assertEqual(set_exit, 2)
        self.assertIn("config show failed", errors.getvalue())
        self.assertIn("config set failed", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
