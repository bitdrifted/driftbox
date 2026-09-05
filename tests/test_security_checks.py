"""Tests for the dedicated Driftbox posture-triage engine."""

import io
import json
import shlex
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from driftbox.cli import build_parser, show_security_checks
from driftbox.findings import posture_findings
from driftbox.security_checks import (
    CHECK_SCHEMA_VERSION,
    TERMINAL_GROUP_LIMIT,
    analyze_security_posture,
    format_check_result,
)

FIXTURES = Path(__file__).parent / "fixtures"


def firewall(status: str, platform: str = "Windows") -> dict[str, object]:
    return {
        "platform": platform,
        "provider": "Synthetic Firewall",
        "status": status,
        "profiles": [
            {
                "name": "SyntheticPrivate",
                "enabled": status == "enabled",
                "default_inbound": "Block",
                "default_outbound": "Allow",
            }
        ],
    }


def listener(
    scope: str = "all interfaces",
    address: str | None = None,
    port: int = 8080,
    process: str = "test-observer",
    protocol: str = "TCP",
    pid: int | None = 123,
) -> dict[str, object]:
    if address is None:
        address = {
            "all interfaces": "0.0.0.0",
            "local only": "127.0.0.1",
            "link local": "169.254.18.20",
            "private network": "192.0.2.20",
            "public address": "198.51.100.20",
            "unknown": "192.0.2.30",
        }[scope]
    return {
        "protocol": protocol,
        "address": address,
        "port": port,
        "pid": pid,
        "process": process,
        "scope": scope,
    }


def regression_fixture() -> dict[str, object]:
    with (FIXTURES / "posture_windows_enabled_49.json").open(
        encoding="utf-8"
    ) as handle:
        return json.load(handle)


class PostureTriagePolicyTests(unittest.TestCase):
    """Verify evidence preservation, policy, and cautious language."""

    def test_firewall_levels_map_without_multiplying_listener_findings(self) -> None:
        expected = {
            "enabled": ("informational", "normal", False),
            "unknown": ("review", "suspicious", True),
            "mixed": ("review", "suspicious", True),
            "disabled": ("urgent", "critical", True),
        }
        for status, (level, unified, actionable) in expected.items():
            with self.subTest(status=status):
                result = analyze_security_posture(
                    firewall(status), [listener(port=9107)]
                )
                item = result.triage_items[0]
                self.assertEqual((item.triage_level, item.unified_classification), (level, unified))
                self.assertEqual(result.actionable, actionable)
                self.assertEqual(len(result.presentation_groups), 1)

    def test_enabled_firewall_generic_wildcard_is_informational_not_safe(self) -> None:
        result = analyze_security_posture(
            firewall("enabled"), [listener(port=9107, process="unavailable")]
        )
        group = result.presentation_groups[0]
        self.assertEqual(group["triage_level"], "informational")
        self.assertEqual(group["unified_classification"], "normal")
        wording = f"{group['explanation']} {group['uncertainty']}"
        self.assertIn("does not prove", wording)
        self.assertIn("safe", wording)
        self.assertFalse(result.actionable)

    def test_sensitive_wildcard_and_public_address_remain_review_worthy(self) -> None:
        result = analyze_security_posture(
            firewall("enabled"),
            [
                listener(port=445, process="file-observer"),
                listener(
                    scope="public address",
                    address="198.51.100.20",
                    port=9107,
                    process="public-observer",
                ),
            ],
        )
        self.assertEqual(
            [group["triage_level"] for group in result.presentation_groups],
            ["review", "review"],
        )
        wording = json.dumps(result.as_dict())
        self.assertIn("does not prove internet reachability", wording)
        self.assertNotIn("is internet reachable", wording)

    def test_contextual_service_families_do_not_claim_identity(self) -> None:
        ports = [123, 135, 137, 138, 139, 445, 500, 4500, 5353, 5355, 7680]
        listeners = [
            listener(
                port=port,
                protocol="UDP" if port in {123, 137, 138, 500, 4500, 5353, 5355} else "TCP",
                process=f"observer-{port}",
            )
            for port in ports
        ]
        result = analyze_security_posture(firewall("enabled"), listeners)
        contexts = " ".join(
            str(group["service_context"]) for group in result.presentation_groups
        )
        for phrase in (
            "time synchronization",
            "Windows RPC",
            "NetBIOS/SMB",
            "IPsec/IKE",
            "multicast DNS",
            "LLMNR",
            "Windows Delivery Optimization",
        ):
            self.assertIn(phrase, contexts)
        limitations = " ".join(result.limitations)
        self.assertIn("do not prove service identity", limitations)

    def test_49_endpoint_regression_is_honestly_consolidated(self) -> None:
        evidence = regression_fixture()
        result = analyze_security_posture(
            evidence["firewall"], evidence["listening_ports"]
        )
        data = result.as_dict()
        summary = data["summary"]
        self.assertEqual(summary["raw_endpoint_count"], 49)
        self.assertEqual(summary["presentation_group_count"], 14)
        self.assertEqual(summary["endpoints_consolidated_for_presentation"], 35)
        self.assertEqual(summary["triage"], {"informational": 9, "review": 6, "urgent": 0})
        self.assertEqual(len(data["raw_endpoints"]), 49)
        self.assertEqual(
            sum(group["raw_endpoint_count"] for group in data["presentation_groups"]),
            49,
        )
        self.assertLess(summary["triage"]["review"], 10)

    def test_deterministic_order_retains_pid_but_excludes_it_from_group_id(self) -> None:
        first = [listener(address="::", pid=701), listener(pid=700)]
        forward = analyze_security_posture(firewall("enabled"), first)
        changed = [dict(first[1], pid=900), dict(first[0], pid=901)]
        reverse = analyze_security_posture(firewall("enabled"), changed)
        self.assertEqual(
            forward.presentation_groups[0]["id"], reverse.presentation_groups[0]["id"]
        )
        self.assertEqual(
            [member["pid"] for member in forward.raw_endpoints], [700, 701]
        )
        self.assertEqual(
            [member["pid"] for member in reverse.raw_endpoints], [900, 901]
        )

    def test_malformed_firewall_and_listener_evidence_is_rejected(self) -> None:
        bad_values = [
            ({"status": "enabled", "unexpected": True}, []),
            ({"status": "definitely-safe"}, []),
            (dict(firewall("enabled"), profiles=[{"name": "Synthetic", "enabled": False}]), []),
            (firewall("enabled"), [{"protocol": "TCP"}]),
            (firewall("enabled"), [dict(listener(), command="whoami")]),
        ]
        for bad_firewall, bad_listeners in bad_values:
            with self.subTest(value=(bad_firewall, bad_listeners)):
                with self.assertRaises(ValueError):
                    analyze_security_posture(bad_firewall, bad_listeners)

    def test_existing_minimal_unified_report_firewall_shape_remains_supported(self) -> None:
        result = analyze_security_posture({"status": "enabled"}, [])
        self.assertEqual(result.firewall["platform"], "unknown")
        self.assertEqual(result.firewall["provider"], "unknown")
        self.assertEqual(posture_findings(result).findings[0].classification, "normal")


class PostureTriageOutputTests(unittest.TestCase):
    """Verify bounded human output, complete JSON, commands, and exits."""

    def run_check(
        self,
        status: str,
        listeners: list[dict[str, object]] | None = None,
        json_output: bool = False,
    ) -> tuple[int, str, str]:
        output = io.StringIO()
        errors = io.StringIO()
        with (
            patch("driftbox.cli.collect_firewall_info", return_value=firewall(status)),
            patch("driftbox.cli.collect_listening_ports", return_value=listeners or []),
            redirect_stdout(output),
            redirect_stderr(errors),
        ):
            exit_code = show_security_checks(json_output)
        return exit_code, output.getvalue(), errors.getvalue()

    def test_human_sections_bottom_line_and_exit_codes(self) -> None:
        exit_zero, normal_output, _ = self.run_check("enabled", [listener(port=9107)])
        exit_review, review_output, _ = self.run_check("unknown")
        exit_urgent, urgent_output, _ = self.run_check("disabled")
        self.assertEqual((exit_zero, exit_review, exit_urgent), (0, 1, 1))
        for heading in (
            "POSTURE SUMMARY",
            "BOTTOM LINE",
            "PRIORITY REVIEW",
            "SERVICE GROUPS",
            "RECOMMENDED NEXT STEPS",
            "SOURCES AND LIMITATIONS",
        ):
            self.assertIn(heading, normal_output)
        self.assertIn("[REVIEW]", review_output)
        self.assertIn("[URGENT]", urgent_output)

    def test_terminal_preview_is_bounded_and_json_is_complete(self) -> None:
        evidence = regression_fixture()
        result = analyze_security_posture(
            evidence["firewall"], evidence["listening_ports"]
        )
        human = format_check_result(result)
        data = result.as_dict()
        service_section = human.split("SERVICE GROUPS\n", 1)[1].split(
            "\n\nRECOMMENDED NEXT STEPS", 1
        )[0]
        self.assertEqual(service_section.count("raw endpoint(s);"), TERMINAL_GROUP_LIMIT)
        self.assertIn("and 4 more service group(s)", service_section)
        self.assertTrue(data["terminal_preview"]["bounded"])
        self.assertEqual(len(data["raw_endpoints"]), 49)
        self.assertEqual(len(data["presentation_groups"]), 14)
        self.assertLess(human.count("[REVIEW]"), 10)

    def test_json_schema_two_preserves_profiles_groups_and_mappings(self) -> None:
        exit_code, output, errors = self.run_check(
            "enabled", [listener(port=445)], json_output=True
        )
        data = json.loads(output)
        self.assertEqual(exit_code, 1)
        self.assertEqual(data["schema_version"], CHECK_SCHEMA_VERSION)
        self.assertEqual(data["firewall"]["profiles"][0]["default_inbound"], "Block")
        self.assertEqual(data["presentation_groups"][0]["triage_level"], "review")
        self.assertEqual(data["presentation_groups"][0]["unified_classification"], "suspicious")
        self.assertEqual(errors, "")

    def test_every_recommended_command_parses_and_is_not_dispatched(self) -> None:
        with (
            patch("subprocess.run", side_effect=AssertionError("must not execute")),
            patch("socket.socket", side_effect=AssertionError("must not access network")),
            patch(
                "driftbox.cli.collect_firewall_info",
                side_effect=AssertionError("must not recollect firewall"),
            ),
            patch(
                "driftbox.cli.collect_listening_ports",
                side_effect=AssertionError("must not recollect listeners"),
            ),
        ):
            result = analyze_security_posture(firewall("enabled"), [])
            for recommendation in result.recommendations:
                args = shlex.split(str(recommendation["command"]), posix=True)
                parsed = build_parser().parse_args(args[1:])
                self.assertIsNotNone(parsed.command)
        self.assertEqual(result.provenance["commands_executed_by_triage"], 0)
        self.assertEqual(result.provenance["network_requests"], 0)

    @patch("driftbox.cli.collect_firewall_info", side_effect=RuntimeError("inspection failed"))
    def test_malformed_or_operational_input_exits_two(self, _: object) -> None:
        output = io.StringIO()
        errors = io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            exit_code = show_security_checks()
        self.assertEqual(exit_code, 2)
        self.assertEqual(output.getvalue(), "")
        self.assertIn("security check failed", errors.getvalue())

    @patch("builtins.print", side_effect=OSError("output failed"))
    @patch("driftbox.cli.collect_listening_ports", return_value=[])
    @patch("driftbox.cli.collect_firewall_info", return_value=firewall("enabled"))
    def test_output_failure_exits_two(self, _: object, __: object, ___: object) -> None:
        self.assertEqual(show_security_checks(), 2)


if __name__ == "__main__":
    unittest.main()
