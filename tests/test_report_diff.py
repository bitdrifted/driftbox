"""Tests for Driftbox report drift detection."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from driftbox.cli import show_report_diff


def report(
    listeners: list[dict[str, object]] | None = None,
    firewall_status: str = "enabled",
    generated_at: str = "2026-01-01T00:00:00+00:00",
) -> dict[str, object]:
    """Build the report fields used by drift comparisons."""
    return {
        "generated_at": generated_at,
        "firewall": {"status": firewall_status},
        "exposure": {"listening_ports": listeners or []},
    }


def listener(
    port: int,
    process: str = "server",
    pid: int = 100,
) -> dict[str, object]:
    """Build a representative listening-port report entry."""
    return {
        "protocol": "TCP",
        "address": "0.0.0.0",
        "port": port,
        "pid": pid,
        "process": process,
        "scope": "all interfaces",
    }


class ReportDiffTests(unittest.TestCase):
    """Verify drift output and command exit codes."""

    def run_diff(
        self,
        baseline: object,
        current: dict[str, object],
    ) -> tuple[int, str, str]:
        """Write a baseline and invoke the command implementation."""
        baseline_bytes = json.dumps(baseline).encode("utf-8")
        return self.run_diff_bytes(baseline_bytes, current)

    def run_diff_bytes(
        self,
        baseline_bytes: bytes,
        current: dict[str, object],
    ) -> tuple[int, str, str]:
        """Write baseline bytes and invoke the command implementation."""
        with tempfile.TemporaryDirectory() as directory:
            baseline_path = Path(directory) / "baseline.json"
            baseline_path.write_bytes(baseline_bytes)
            output = io.StringIO()
            errors = io.StringIO()

            with (
                patch("driftbox.cli.build_report", return_value=current),
                redirect_stdout(output),
                redirect_stderr(errors),
            ):
                exit_code = show_report_diff(str(baseline_path))

        return exit_code, output.getvalue(), errors.getvalue()

    def test_normal_utf8_baseline_ignores_timestamp_and_pid(self) -> None:
        baseline = report([listener(8080, pid=100)])
        current = report(
            [listener(8080, pid=999)],
            generated_at="2026-02-01T00:00:00+00:00",
        )

        exit_code, output, errors = self.run_diff(baseline, current)

        self.assertEqual(exit_code, 0)
        self.assertIn("No drift detected.", output)
        self.assertEqual(errors, "")

    def test_utf8_bom_baseline(self) -> None:
        baseline = report([listener(8080)])
        baseline_bytes = json.dumps(baseline).encode("utf-8-sig")

        exit_code, output, errors = self.run_diff_bytes(
            baseline_bytes,
            baseline,
        )

        self.assertEqual(exit_code, 0)
        self.assertIn("No drift detected.", output)
        self.assertEqual(errors, "")

    def test_utf16_little_endian_bom_baseline(self) -> None:
        baseline = report([listener(8080)])
        baseline_bytes = json.dumps(baseline).encode("utf-16")

        exit_code, output, errors = self.run_diff_bytes(
            baseline_bytes,
            baseline,
        )

        self.assertEqual(exit_code, 0)
        self.assertIn("No drift detected.", output)
        self.assertEqual(errors, "")

    def test_utf16_big_endian_bom_baseline(self) -> None:
        baseline = report([listener(8080)])
        baseline_bytes = b"\xfe\xff" + json.dumps(baseline).encode("utf-16-be")

        exit_code, output, errors = self.run_diff_bytes(
            baseline_bytes,
            baseline,
        )

        self.assertEqual(exit_code, 0)
        self.assertIn("No drift detected.", output)
        self.assertEqual(errors, "")

    def test_reports_added_listener(self) -> None:
        exit_code, output, _ = self.run_diff(
            report(),
            report([listener(8080)]),
        )

        self.assertEqual(exit_code, 1)
        self.assertIn("Added listening services/endpoints:", output)
        self.assertIn("+ TCP 0.0.0.0:8080", output)

    def test_reports_removed_listener(self) -> None:
        exit_code, output, _ = self.run_diff(
            report([listener(8080)]),
            report(),
        )

        self.assertEqual(exit_code, 1)
        self.assertIn("Removed listening services/endpoints:", output)
        self.assertIn("- TCP 0.0.0.0:8080", output)

    def test_reports_firewall_status_change(self) -> None:
        exit_code, output, _ = self.run_diff(
            report(firewall_status="enabled"),
            report(firewall_status="disabled"),
        )

        self.assertEqual(exit_code, 1)
        self.assertIn("Firewall status changed: enabled -> disabled", output)

    def test_invalid_baseline_returns_exit_code_two(self) -> None:
        exit_code, output, errors = self.run_diff({}, report())

        self.assertEqual(exit_code, 2)
        self.assertEqual(output, "")
        self.assertIn("invalid baseline", errors)

    def test_malformed_json_returns_exit_code_two(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            baseline_path = Path(directory) / "baseline.json"
            baseline_path.write_text("{invalid", encoding="utf-8")
            output = io.StringIO()
            errors = io.StringIO()

            with redirect_stdout(output), redirect_stderr(errors):
                exit_code = show_report_diff(str(baseline_path))

        self.assertEqual(exit_code, 2)
        self.assertEqual(output.getvalue(), "")
        self.assertIn("invalid baseline", errors.getvalue())

    def test_invalid_encoding_returns_exit_code_two(self) -> None:
        exit_code, output, errors = self.run_diff_bytes(b"\x80\x81", report())

        self.assertEqual(exit_code, 2)
        self.assertEqual(output, "")
        self.assertIn("invalid baseline", errors)

    def test_unreadable_baseline_returns_exit_code_two(self) -> None:
        output = io.StringIO()
        errors = io.StringIO()

        with redirect_stdout(output), redirect_stderr(errors):
            exit_code = show_report_diff("missing-baseline.json")

        self.assertEqual(exit_code, 2)
        self.assertEqual(output.getvalue(), "")
        self.assertIn("invalid baseline", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
