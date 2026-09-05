"""Tests for reusable configured scan orchestration."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, call, patch

from driftbox.cli import main, run_configured_scan
from driftbox.configuration import set_configuration_value
from driftbox.history import SnapshotInfo, list_snapshots
from driftbox.integrity import create_manifest
from driftbox.scan_runner import run_scan


def report(
    generated_at: str = "2026-09-03T12:00:00+00:00",
    port: int = 8080,
    address: str = "127.0.0.1",
    scope: str = "local only",
) -> dict[str, object]:
    """Return a complete deterministic report for scan tests."""
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
                    "address": address,
                    "port": port,
                    "pid": 100,
                    "process": "test-server",
                    "scope": scope,
                }
            ]
        },
    }


def configuration(
    integrity_targets: list[dict[str, str]] | None = None,
) -> dict[str, object]:
    """Return a validated configuration-shaped test value."""
    return {
        "schema_version": 1,
        "settings": {
            "history_retention_days": 30,
            "default_baseline": "latest",
            "integrity_targets": integrity_targets or [],
            "scan_output": "human",
        },
    }


class ScanRunnerTests(unittest.TestCase):
    """Verify baseline sequencing, aggregation, and safe failure behavior."""

    def test_first_scan_initializes_then_second_unchanged_exits_zero(self) -> None:
        current = report()
        with (
            tempfile.TemporaryDirectory() as config_directory,
            tempfile.TemporaryDirectory() as state_directory,
        ):
            environment = {
                "DRIFTBOX_CONFIG_DIR": config_directory,
                "DRIFTBOX_STATE_DIR": state_directory,
            }
            output = io.StringIO()
            with (
                patch.dict("os.environ", environment),
                patch("driftbox.cli.build_report", return_value=current),
                redirect_stdout(output),
            ):
                first_exit = run_configured_scan()
                first_output = output.getvalue()
                output.seek(0)
                output.truncate(0)
                second_exit = run_configured_scan(json_output=True)
                second_output = json.loads(output.getvalue())
                snapshots = list_snapshots()

        self.assertEqual(first_exit, 0)
        self.assertIn("baseline initialized", first_output)
        self.assertEqual(second_exit, 0)
        self.assertEqual(second_output["schema_version"], 1)
        self.assertNotEqual(
            second_output["previous_snapshot"], second_output["captured_snapshot"]
        )
        self.assertEqual(len(snapshots), 2)

    def test_cli_parser_end_to_end_uses_isolated_storage(self) -> None:
        """Exercise parsing through capture twice without using real user state."""
        current = report()
        with (
            tempfile.TemporaryDirectory() as config_directory,
            tempfile.TemporaryDirectory() as state_directory,
        ):
            environment = {
                "DRIFTBOX_CONFIG_DIR": config_directory,
                "DRIFTBOX_STATE_DIR": state_directory,
            }
            output = io.StringIO()
            with (
                patch.dict("os.environ", environment),
                patch("driftbox.cli.build_report", return_value=current),
                patch("sys.argv", ["driftbox", "scan", "--json"]),
                redirect_stdout(output),
            ):
                first_exit = main()
                output.seek(0)
                output.truncate(0)
                second_exit = main()
                second = json.loads(output.getvalue())

            files = list(Path(state_directory).glob("*.json"))
            config_exists = (Path(config_directory) / "config.json").is_file()

        self.assertEqual(first_exit, 0)
        self.assertEqual(second_exit, 0)
        self.assertEqual(second["schema_version"], 1)
        self.assertNotEqual(second["previous_snapshot"], second["captured_snapshot"])
        self.assertEqual(len(files), 2)
        self.assertTrue(config_exists)

    def test_later_scan_aggregates_drift_posture_and_integrity(self) -> None:
        with (
            tempfile.TemporaryDirectory() as root,
            tempfile.TemporaryDirectory() as config_directory,
            tempfile.TemporaryDirectory() as state_directory,
        ):
            monitored = Path(root) / "important.txt"
            manifest = Path(root) / "manifest.json"
            monitored.write_text("trusted", encoding="utf-8")
            create_manifest(str(monitored), str(manifest))
            targets = json.dumps(
                [{"path": str(monitored), "manifest": str(manifest)}]
            )
            environment = {
                "DRIFTBOX_CONFIG_DIR": config_directory,
                "DRIFTBOX_STATE_DIR": state_directory,
            }
            with patch.dict("os.environ", environment):
                set_configuration_value("integrity_targets", targets)
                first = run_scan(report)
                monitored.write_text("changed", encoding="utf-8")
                second = run_scan(
                    lambda: report(
                        port=9090,
                        address="0.0.0.0",
                        scope="all interfaces",
                    )
                )

        finding_ids = [finding.id for finding in second.findings.findings]
        self.assertFalse(first.findings.actionable)
        self.assertTrue(second.findings.actionable)
        self.assertIn("integrity-file-modified", finding_ids)
        self.assertIn("listener-newly-detected", finding_ids)
        self.assertIn("posture-no-actionable-findings", finding_ids)
        self.assertEqual(finding_ids, sorted(finding_ids))

    def test_previous_snapshot_is_read_before_current_is_captured(self) -> None:
        events = Mock()
        old_info = SnapshotInfo("20260903T100000.000000Z", "old", 100)
        new_info = SnapshotInfo("20260903T110000.000000Z", "new", 100)
        collect = Mock(
            side_effect=lambda: (events.collect(), report())[1]
        )
        read = Mock(
            side_effect=lambda *_: (events.read(), ("{}", report()))[1]
        )
        capture = Mock(
            side_effect=lambda *_: (events.capture(), new_info)[1]
        )
        with (
            patch(
                "driftbox.scan_runner.load_configuration",
                return_value=configuration(),
            ),
            patch(
                "driftbox.scan_runner.list_snapshots",
                side_effect=lambda: (events.list(), (old_info,))[1],
            ),
            patch("driftbox.scan_runner.read_snapshot", read),
            patch("driftbox.scan_runner.capture_snapshot", capture),
        ):
            run_scan(collect)

        self.assertEqual(
            events.mock_calls,
            [call.list(), call.collect(), call.read(), call.capture()],
        )

    def test_partial_integrity_failure_does_not_capture_previous(self) -> None:
        old_info = SnapshotInfo("20260903T100000.000000Z", "old", 100)
        configured = configuration(
            [{"path": "missing", "manifest": "bad"}]
        )
        with (
            patch(
                "driftbox.scan_runner.load_configuration",
                return_value=configured,
            ),
            patch("driftbox.scan_runner.list_snapshots", return_value=(old_info,)),
            patch("driftbox.scan_runner.load_manifest", side_effect=OSError("denied")),
            patch("driftbox.scan_runner.capture_snapshot") as capture,
        ):
            with self.assertRaisesRegex(OSError, "denied"):
                run_scan(report)
        capture.assert_not_called()

    def test_operational_error_returns_two_without_capture(self) -> None:
        errors = io.StringIO()
        with (
            patch("driftbox.cli.load_configuration", side_effect=OSError("denied")),
            patch("driftbox.scan_runner.capture_snapshot") as capture,
            redirect_stderr(errors),
        ):
            exit_code = run_configured_scan()
        self.assertEqual(exit_code, 2)
        self.assertIn("scan failed", errors.getvalue())
        capture.assert_not_called()

    def test_actionable_scan_returns_one(self) -> None:
        current = report(port=445, address="0.0.0.0", scope="all interfaces")
        with (
            tempfile.TemporaryDirectory() as config_directory,
            tempfile.TemporaryDirectory() as state_directory,
        ):
            environment = {
                "DRIFTBOX_CONFIG_DIR": config_directory,
                "DRIFTBOX_STATE_DIR": state_directory,
            }
            with (
                patch.dict("os.environ", environment),
                patch("driftbox.cli.build_report", return_value=current),
                redirect_stdout(io.StringIO()),
            ):
                exit_code = run_configured_scan()

        self.assertEqual(exit_code, 1)

    def test_saved_json_output_preference_is_used(self) -> None:
        with (
            tempfile.TemporaryDirectory() as config_directory,
            tempfile.TemporaryDirectory() as state_directory,
        ):
            environment = {
                "DRIFTBOX_CONFIG_DIR": config_directory,
                "DRIFTBOX_STATE_DIR": state_directory,
            }
            output = io.StringIO()
            with (
                patch.dict("os.environ", environment),
                patch("driftbox.cli.build_report", return_value=report()),
                redirect_stdout(output),
            ):
                set_configuration_value("scan_output", "json")
                exit_code = run_configured_scan()
                result = json.loads(output.getvalue())

        self.assertEqual(exit_code, 0)
        self.assertEqual(result["schema_version"], 1)


if __name__ == "__main__":
    unittest.main()
