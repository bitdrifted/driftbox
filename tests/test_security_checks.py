"""Tests for Driftbox security posture checks."""

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from driftbox.cli import show_security_checks
from driftbox.security_checks import analyze_security_posture


def firewall(status: str) -> dict[str, object]:
    """Build representative firewall inspection data."""
    return {
        "platform": "TestOS",
        "provider": "Test Firewall",
        "status": status,
        "profiles": [],
    }


def listener(
    scope: str,
    address: str = "127.0.0.1",
    port: int = 8080,
) -> dict[str, object]:
    """Build representative listening-port inspection data."""
    return {
        "protocol": "TCP",
        "address": address,
        "port": port,
        "pid": 123,
        "process": "test-server",
        "scope": scope,
    }


class SecurityAnalysisTests(unittest.TestCase):
    """Verify finding rules and deterministic evidence."""

    def test_enabled_firewall_has_no_firewall_finding(self) -> None:
        result = analyze_security_posture(firewall("enabled"), [])
        self.assertEqual(result.observations, ())

    def test_disabled_firewall_is_high_severity(self) -> None:
        result = analyze_security_posture(firewall("disabled"), [])

        self.assertEqual(len(result.observations), 1)
        self.assertEqual(result.observations[0].id, "firewall-disabled")
        self.assertEqual(result.observations[0].severity, "high")
        self.assertIn("confirmed disabled", result.observations[0].message)

    def test_unknown_firewall_is_not_treated_as_secure(self) -> None:
        result = analyze_security_posture(firewall("unknown"), [])

        self.assertEqual(len(result.observations), 1)
        self.assertEqual(result.observations[0].id, "firewall-unknown")
        self.assertEqual(result.observations[0].severity, "warning")
        self.assertIn("do not assume", result.observations[0].message)

    def test_every_address_scope(self) -> None:
        cases = {
            "all interfaces": "listener-all-interfaces",
            "public address": "listener-public-address",
            "local only": None,
            "link local": None,
            "private network": None,
            "unknown": None,
        }

        for scope, expected_id in cases.items():
            with self.subTest(scope=scope):
                result = analyze_security_posture(
                    firewall("enabled"),
                    [listener(scope)],
                )
                ids = [item.id for item in result.observations]
                self.assertEqual(ids, [] if expected_id is None else [expected_id])

    def test_listener_wording_does_not_claim_internet_accessibility(self) -> None:
        result = analyze_security_posture(
            firewall("enabled"),
            [
                listener("all interfaces", "0.0.0.0"),
                listener("public address", "203.0.113.10"),
            ],
        )

        messages = " ".join(item.message for item in result.observations)
        self.assertIn("firewall policy, routing, and NAT", messages)
        self.assertIn("does not prove internet accessibility", messages)
        self.assertNotIn("is internet-accessible", messages)

    def test_findings_have_deterministic_order_and_ignore_pid(self) -> None:
        first_listener = listener("all interfaces", "::", 9000)
        second_listener = listener("all interfaces", "0.0.0.0", 8000)
        forward = analyze_security_posture(
            firewall("unknown"),
            [first_listener, second_listener],
        )
        first_listener["pid"] = 999
        second_listener["pid"] = 888
        reverse = analyze_security_posture(
            firewall("unknown"),
            [second_listener, first_listener],
        )

        self.assertEqual(forward.as_dict(), reverse.as_dict())
        self.assertEqual(
            [item.id for item in forward.observations],
            [
                "firewall-unknown",
                "listener-all-interfaces",
                "listener-all-interfaces",
            ],
        )
        self.assertNotIn("pid", forward.observations[1].evidence)


class SecurityCommandTests(unittest.TestCase):
    """Verify terminal, JSON, and exit-code behavior."""

    def run_check(
        self,
        firewall_status: str,
        listeners: list[dict[str, object]] | None = None,
        json_output: bool = False,
    ) -> tuple[int, str, str]:
        """Run checks with deterministic inspection data."""
        output = io.StringIO()
        errors = io.StringIO()
        with (
            patch(
                "driftbox.cli.collect_firewall_info",
                return_value=firewall(firewall_status),
            ),
            patch(
                "driftbox.cli.collect_listening_ports",
                return_value=listeners or [],
            ),
            redirect_stdout(output),
            redirect_stderr(errors),
        ):
            exit_code = show_security_checks(json_output)
        return exit_code, output.getvalue(), errors.getvalue()

    def test_exit_zero_and_terminal_summary_without_findings(self) -> None:
        exit_code, output, errors = self.run_check("enabled")

        self.assertEqual(exit_code, 0)
        self.assertIn("Summary: 1 normal, 0 suspicious, 0 critical", output)
        self.assertIn("[NORMAL] posture-no-actionable-findings", output)
        self.assertEqual(errors, "")

    def test_exit_one_with_findings(self) -> None:
        exit_code, output, _ = self.run_check("disabled")

        self.assertEqual(exit_code, 1)
        self.assertIn("[CRITICAL] firewall-currently-disabled", output)
        self.assertIn("Summary: 0 normal, 0 suspicious, 1 critical", output)

    def test_json_output_is_versioned_and_machine_readable(self) -> None:
        exit_code, output, errors = self.run_check(
            "enabled",
            [listener("public address", "203.0.113.10")],
            json_output=True,
        )
        data = json.loads(output)

        self.assertEqual(exit_code, 1)
        self.assertEqual(data["schema_version"], 1)
        self.assertEqual(data["summary"]["suspicious"], 1)
        self.assertEqual(data["findings"][0]["id"], "listener-public-address")
        self.assertEqual(data["findings"][0]["classification"], "suspicious")
        self.assertEqual(errors, "")

    @patch(
        "driftbox.cli.collect_firewall_info",
        side_effect=RuntimeError("inspection failed"),
    )
    def test_unexpected_inspection_error_returns_exit_two(self, _: object) -> None:
        output = io.StringIO()
        errors = io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            exit_code = show_security_checks()

        self.assertEqual(exit_code, 2)
        self.assertEqual(output.getvalue(), "")
        self.assertIn("security check failed", errors.getvalue())

    @patch("builtins.print", side_effect=OSError("output failed"))
    @patch(
        "driftbox.cli.collect_listening_ports",
        return_value=[],
    )
    @patch(
        "driftbox.cli.collect_firewall_info",
        return_value=firewall("enabled"),
    )
    def test_unexpected_output_error_returns_exit_two(
        self,
        _: object,
        __: object,
        ___: object,
    ) -> None:
        self.assertEqual(show_security_checks(), 2)


if __name__ == "__main__":
    unittest.main()
