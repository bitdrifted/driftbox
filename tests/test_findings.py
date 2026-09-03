"""Tests for the unified severity findings engine."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from driftbox.cli import analyze_history_snapshot, build_parser
from driftbox.findings import (
    CLASSIFICATIONS,
    Finding,
    combine_findings,
    drift_findings,
    integrity_findings,
    posture_findings,
)
from driftbox.history import capture_snapshot
from driftbox.integrity import IntegrityChanges
from driftbox.report_diff import ReportDrift
from driftbox.security_checks import analyze_security_posture


def listener(port: int = 8080, scope: str = "local only") -> dict[str, object]:
    """Build representative listener data."""
    address = "127.0.0.1" if scope == "local only" else "0.0.0.0"
    return {
        "protocol": "TCP",
        "address": address,
        "port": port,
        "pid": 100,
        "process": "test-server",
        "scope": scope,
    }


def report(
    firewall_status: str = "enabled",
    listeners: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    """Build a complete stored report for analyze tests."""
    return {
        "schema_version": 1,
        "driftbox_version": "0.1.0",
        "generated_at": "2026-09-03T12:00:00+00:00",
        "system": {"hostname": "test-host"},
        "network": {"ipv4_addresses": []},
        "firewall": {
            "platform": "TestOS",
            "provider": "Test Firewall",
            "status": firewall_status,
            "profiles": [],
        },
        "exposure": {"listening_ports": listeners or []},
    }


class FindingsEngineTests(unittest.TestCase):
    """Verify shared classification rules and finding structure."""

    def test_only_exact_classifications_are_allowed(self) -> None:
        self.assertEqual(CLASSIFICATIONS, ("normal", "suspicious", "critical"))
        with self.assertRaises(ValueError):
            Finding("bad", "warning", "Bad", "Bad", {}, "Do nothing")

    def test_every_finding_has_required_fields(self) -> None:
        posture = analyze_security_posture(
            report("unknown")["firewall"],
            [listener(scope="all interfaces")],
        )
        data = posture_findings(posture).as_dict()

        for finding in data["findings"]:
            self.assertEqual(
                set(finding),
                {
                    "id",
                    "classification",
                    "title",
                    "explanation",
                    "evidence",
                    "recommended_action",
                },
            )

    def test_firewall_regression_is_critical(self) -> None:
        result = drift_findings(
            ReportDrift((), (), ("enabled", "disabled"))
        )
        finding = result.findings[0]
        self.assertEqual(finding.id, "firewall-regressed-to-disabled")
        self.assertEqual(finding.classification, "critical")

    def test_firewall_improvement_and_removed_listener_are_normal(self) -> None:
        removed = ("TCP", "127.0.0.1", 8080, "server", "local only")
        result = drift_findings(
            ReportDrift((), (removed,), ("disabled", "enabled"))
        )

        self.assertEqual(
            {finding.classification for finding in result.findings},
            {"normal"},
        )
        actions = " ".join(item.recommended_action for item in result.findings)
        self.assertIn("expected", actions)

    def test_new_listener_is_suspicious_and_non_alarmist(self) -> None:
        added = ("TCP", "0.0.0.0", 8080, "server", "all interfaces")
        finding = drift_findings(ReportDrift((added,), (), None)).findings[0]

        self.assertEqual(finding.classification, "suspicious")
        self.assertIn("does not prove internet accessibility", finding.explanation)
        self.assertIn("firewall policy, routing, and NAT", finding.explanation)

    def test_integrity_changes_and_intact_results(self) -> None:
        changed = integrity_findings(
            IntegrityChanges(("new",), ("gone",), ("changed",), 2)
        )
        intact = integrity_findings(IntegrityChanges((), (), (), 3))

        self.assertTrue(changed.actionable)
        self.assertEqual(
            {finding.classification for finding in changed.findings},
            {"suspicious"},
        )
        self.assertFalse(intact.actionable)
        self.assertEqual(intact.findings[0].classification, "normal")

    def test_combined_results_are_deterministic(self) -> None:
        first = drift_findings(
            ReportDrift(
                (("TCP", "0.0.0.0", 9000, "z", "all interfaces"),),
                (),
                None,
            )
        )
        second = integrity_findings(IntegrityChanges(("a",), (), (), 0))

        forward = combine_findings(first, second).as_dict()
        reverse = combine_findings(second, first).as_dict()
        self.assertEqual(forward, reverse)


class AnalyzeCommandTests(unittest.TestCase):
    """Verify history-backed unified analysis behavior."""

    def test_snapshot_defaults_to_latest(self) -> None:
        args = build_parser().parse_args(["analyze"])
        self.assertEqual(args.snapshot, "latest")

    def test_json_analysis_and_actionable_exit_code(self) -> None:
        baseline = report("enabled")
        current = report("disabled", [listener(scope="all interfaces")])
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict("os.environ", {"DRIFTBOX_STATE_DIR": directory}):
                capture_snapshot(baseline)
                output = io.StringIO()
                with (
                    patch("driftbox.cli.build_report", return_value=current),
                    redirect_stdout(output),
                ):
                    exit_code = analyze_history_snapshot("latest", True)

        data = json.loads(output.getvalue())
        self.assertEqual(exit_code, 1)
        self.assertEqual(data["schema_version"], 1)
        self.assertGreaterEqual(data["summary"]["critical"], 1)
        ids = [finding["id"] for finding in data["findings"]]
        self.assertIn("firewall-regressed-to-disabled", ids)
        self.assertIn("firewall-currently-disabled", ids)

    def test_only_normal_findings_exit_zero(self) -> None:
        unchanged = report()
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict("os.environ", {"DRIFTBOX_STATE_DIR": directory}):
                capture_snapshot(unchanged)
                output = io.StringIO()
                with (
                    patch("driftbox.cli.build_report", return_value=unchanged),
                    redirect_stdout(output),
                ):
                    exit_code = analyze_history_snapshot("latest")

        self.assertEqual(exit_code, 0)
        self.assertIn("[NORMAL]", output.getvalue())
        self.assertIn("Recommended action:", output.getvalue())

    def test_missing_snapshot_exits_two(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            errors = io.StringIO()
            with (
                patch.dict("os.environ", {"DRIFTBOX_STATE_DIR": directory}),
                redirect_stderr(errors),
            ):
                exit_code = analyze_history_snapshot("latest")

        self.assertEqual(exit_code, 2)
        self.assertIn("analysis failed", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
