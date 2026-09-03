"""Tests for persistent local report history."""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from driftbox.cli import (
    capture_history,
    diff_history_snapshot,
    show_history_list,
    show_history_snapshot,
)
from driftbox.history import (
    capture_snapshot,
    history_directory,
    list_snapshots,
    read_snapshot,
)


def report(
    generated_at: str = "2026-09-03T12:00:00+00:00",
    port: int = 8080,
) -> dict[str, object]:
    """Build a complete representative Driftbox report."""
    return {
        "schema_version": 1,
        "driftbox_version": "0.1.0",
        "generated_at": generated_at,
        "system": {"hostname": "test-host"},
        "network": {"ipv4_addresses": ["192.168.1.10"]},
        "firewall": {"status": "enabled"},
        "exposure": {
            "listening_ports": [
                {
                    "protocol": "TCP",
                    "address": "127.0.0.1",
                    "port": port,
                    "pid": 100,
                    "process": "test-server",
                    "scope": "local only",
                }
            ]
        },
    }


class HistoryStorageTests(unittest.TestCase):
    """Verify storage paths, capture, listing, and retrieval."""

    def test_environment_override_is_history_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(
                "os.environ",
                {"DRIFTBOX_STATE_DIR": directory},
                clear=True,
            ):
                self.assertEqual(history_directory(), Path(directory))

    def test_platform_specific_default_paths(self) -> None:
        with patch.dict("os.environ", {"LOCALAPPDATA": "C:/State"}, clear=True):
            with patch("driftbox.history.platform.system", return_value="Windows"):
                self.assertEqual(
                    history_directory(),
                    Path("C:/State") / "Driftbox" / "history",
                )

        with patch.dict("os.environ", {}, clear=True):
            with (
                patch("driftbox.history.platform.system", return_value="Darwin"),
                patch("driftbox.history.Path.home", return_value=Path("/Users/test")),
            ):
                self.assertEqual(
                    history_directory(),
                    Path("/Users/test/Library/Application Support/Driftbox/history"),
                )

        with patch.dict("os.environ", {"XDG_STATE_HOME": "/state"}, clear=True):
            with patch("driftbox.history.platform.system", return_value="Linux"):
                self.assertEqual(
                    history_directory(),
                    Path("/state/driftbox/history"),
                )

        with patch.dict("os.environ", {}, clear=True):
            with (
                patch("driftbox.history.platform.system", return_value="Linux"),
                patch("driftbox.history.Path.home", return_value=Path("/home/test")),
            ):
                self.assertEqual(
                    history_directory(),
                    Path("/home/test/.local/state/driftbox/history"),
                )

    def test_capture_uses_unique_timestamp_identifiers(self) -> None:
        fixed_time = datetime(2026, 9, 3, 12, 30, 45, 123456, timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict("os.environ", {"DRIFTBOX_STATE_DIR": directory}):
                first = capture_snapshot(report(), now=fixed_time)
                second = capture_snapshot(report(), now=fixed_time)

            files = sorted(path.name for path in Path(directory).glob("*.json"))

        self.assertEqual(first.identifier, "20260903T123045.123456Z")
        self.assertEqual(second.identifier, "20260903T123045.123456Z-01")
        self.assertEqual(
            files,
            [
                "20260903T123045.123456Z-01.json",
                "20260903T123045.123456Z.json",
            ],
        )

    def test_capture_publishes_atomically_without_temp_files(self) -> None:
        fixed_time = datetime(2026, 9, 3, tzinfo=timezone.utc)
        real_link = os.link
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch.dict("os.environ", {"DRIFTBOX_STATE_DIR": directory}),
                patch("driftbox.history.os.link", wraps=real_link) as link,
            ):
                snapshot = capture_snapshot(report(), now=fixed_time)

            self.assertTrue((Path(directory) / f"{snapshot.identifier}.json").is_file())
            self.assertEqual(list(Path(directory).glob("*.tmp")), [])
            link.assert_called_once()

    def test_list_is_newest_first_and_deterministic(self) -> None:
        older = datetime(2026, 9, 3, 10, tzinfo=timezone.utc)
        newer = datetime(2026, 9, 3, 11, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict("os.environ", {"DRIFTBOX_STATE_DIR": directory}):
                old_snapshot = capture_snapshot(report(), now=older)
                new_snapshot = capture_snapshot(report(), now=newer)
                snapshots = list_snapshots()

        self.assertEqual(
            [item.identifier for item in snapshots],
            [new_snapshot.identifier, old_snapshot.identifier],
        )

    def test_latest_returns_newest_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict("os.environ", {"DRIFTBOX_STATE_DIR": directory}):
                capture_snapshot(
                    report("2026-09-03T10:00:00+00:00"),
                    now=datetime(2026, 9, 3, 10, tzinfo=timezone.utc),
                )
                newest = capture_snapshot(
                    report("2026-09-03T11:00:00+00:00"),
                    now=datetime(2026, 9, 3, 11, tzinfo=timezone.utc),
                )
                _, stored_report = read_snapshot("latest")

        self.assertEqual(stored_report["generated_at"], newest.created_at)


class HistoryCommandTests(unittest.TestCase):
    """Verify history command output and exit codes."""

    def test_capture_and_json_listing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = io.StringIO()
            with (
                patch.dict("os.environ", {"DRIFTBOX_STATE_DIR": directory}),
                patch("driftbox.cli.build_report", return_value=report()),
                redirect_stdout(output),
            ):
                capture_exit = capture_history()
                output.seek(0)
                output.truncate(0)
                list_exit = show_history_list(json_output=True)
                listing = json.loads(output.getvalue())

        self.assertEqual(capture_exit, 0)
        self.assertEqual(list_exit, 0)
        self.assertEqual(listing["schema_version"], 1)
        self.assertEqual(len(listing["snapshots"]), 1)
        self.assertGreater(listing["snapshots"][0]["size"], 0)

    def test_show_outputs_snapshot_without_reformatting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict("os.environ", {"DRIFTBOX_STATE_DIR": directory}):
                captured = capture_snapshot(report())
                stored_text, _ = read_snapshot(captured.identifier)
                output = io.StringIO()
                with redirect_stdout(output):
                    exit_code = show_history_snapshot(captured.identifier)

        self.assertEqual(exit_code, 0)
        self.assertEqual(output.getvalue(), stored_text)

    def test_intact_history_diff_returns_zero(self) -> None:
        current_report = report()
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict("os.environ", {"DRIFTBOX_STATE_DIR": directory}):
                captured = capture_snapshot(current_report)
                output = io.StringIO()
                with (
                    patch("driftbox.cli.build_report", return_value=current_report),
                    redirect_stdout(output),
                ):
                    exit_code = diff_history_snapshot(captured.identifier)

        self.assertEqual(exit_code, 0)
        self.assertIn("No drift detected.", output.getvalue())

    def test_detected_history_diff_returns_one(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict("os.environ", {"DRIFTBOX_STATE_DIR": directory}):
                captured = capture_snapshot(report(port=8080))
                output = io.StringIO()
                with (
                    patch("driftbox.cli.build_report", return_value=report(port=9090)),
                    redirect_stdout(output),
                ):
                    exit_code = diff_history_snapshot(captured.identifier)

        self.assertEqual(exit_code, 1)
        self.assertIn("Drift detected.", output.getvalue())

    def test_missing_snapshot_returns_two(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            errors = io.StringIO()
            with (
                patch.dict("os.environ", {"DRIFTBOX_STATE_DIR": directory}),
                redirect_stderr(errors),
            ):
                exit_code = show_history_snapshot("20260903T120000.000000Z")

        self.assertEqual(exit_code, 2)
        self.assertIn("snapshot not found", errors.getvalue())

    def test_corrupt_snapshot_is_not_silently_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            corrupt = Path(directory) / "20260903T120000.000000Z.json"
            corrupt.write_text("{invalid", encoding="utf-8")
            errors = io.StringIO()
            with (
                patch.dict("os.environ", {"DRIFTBOX_STATE_DIR": directory}),
                redirect_stderr(errors),
            ):
                list_exit = show_history_list()
                diff_exit = diff_history_snapshot("latest")

        self.assertEqual(list_exit, 2)
        self.assertEqual(diff_exit, 2)
        self.assertIn("history list failed", errors.getvalue())
        self.assertIn("history diff failed", errors.getvalue())

    @patch("builtins.print", side_effect=OSError("output failed"))
    @patch("driftbox.cli.list_snapshots", return_value=())
    def test_output_error_returns_two(self, _: object, __: object) -> None:
        self.assertEqual(show_history_list(), 2)


if __name__ == "__main__":
    unittest.main()
