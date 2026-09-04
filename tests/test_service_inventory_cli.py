"""Hermetic operator-experience tests for the Nmap service inventory."""

from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import Mock, patch

from driftbox.cli import build_parser, format_service_inventory, main, run_service_inventory
from driftbox.service_inventory import (
    NmapExecutionError,
    NmapExecutionTimeoutError,
    NmapInstallation,
    NmapScanResult,
    NmapUnavailableError,
    NmapXMLParseError,
    ParsedNmapEvidence,
)
from driftbox.service_inventory_interpretation import (
    build_service_inventory_interpretation,
    validate_service_recommendation_commands,
)


def sample_result(
    *,
    incomplete: bool = False,
    services: tuple[dict[str, object], ...] | None = None,
    top_ports: int = 100,
    target: str = "192.168.1.20",
) -> NmapScanResult:
    if services is None:
        services = ({
            "protocol": "tcp", "port": 443, "state": "open", "reason": "syn-ack",
            "service": {
                "name": "https", "product": "Example Server", "version": "1.2",
                "extrainfo": "TLS", "tunnel": "ssl", "cpe": ["cpe:/a:example:server:1.2"],
                "method": "probed", "confidence": "10",
            },
            "raw": {"name": "https", "product": "Example Server"},
        },)
    return NmapScanResult(
        installation=NmapInstallation(executable="C:/Program Files/Nmap/nmap.exe", version="7.99"),
        command=("C:/Program Files/Nmap/nmap.exe", "-n", "-Pn", "--disable-arp-ping", "--unprivileged", "-sT", "--top-ports", str(top_ports), "-sV", "--version-light", "--reason", "--open", "--host-timeout", "60s", "-oX", "-", target),
        started_at="2026-09-03T12:00:00Z",
        completed_at="2026-09-03T12:00:03Z",
        exit_code=0,
        parsed=ParsedNmapEvidence(
            host={"state": "up", "reason": "user-set"}, services=services,
            evidence_incomplete=incomplete,
            incomplete_reasons=("host-timeout",) if incomplete else (),
            nmap_xml_version="1.05",
        ),
    )


def privacy_safe_windows_services() -> tuple[dict[str, object], ...]:
    """Model common Windows service-label relationships without live inventory."""
    records: list[dict[str, object]] = []
    relationships = ((135, "msrpc"), (139, "netbios-ssn"), (445, "microsoft-ds"))
    for port, name in relationships:
        records.append(
            {
                "protocol": "tcp",
                "port": port,
                "state": "open",
                "reason": "syn-ack",
                "service": {
                    "name": name,
                    "product": None,
                    "version": None,
                    "extrainfo": None,
                    "tunnel": None,
                    "cpe": [],
                    "method": "table",
                    "confidence": 3,
                },
                "raw": {"name": name},
            }
        )
    return tuple(records)


class ServiceInventoryParserTests(unittest.TestCase):
    def test_parser_has_explicit_authorization_json_and_bounded_scope(self) -> None:
        parsed = build_parser().parse_args([
            "services", "192.168.1.20", "--confirm-authorization", "--json", "--top-ports", "1000",
        ])
        self.assertEqual(parsed.command, "services")
        self.assertTrue(parsed.authorization_confirmed)
        self.assertTrue(parsed.json_output)
        self.assertEqual(parsed.top_ports, "1000")

    @patch("driftbox.cli.run_service_inventory", return_value=0)
    def test_main_dispatches_service_arguments_without_scanning(self, run: Mock) -> None:
        with patch("sys.argv", ["driftbox", "services", "10.1.2.3", "--confirm-authorization", "--top-ports", "1000"]):
            self.assertEqual(main(), 0)
        run.assert_called_once_with(
            "10.1.2.3",
            authorization_confirmed=True,
            json_output=False,
            top_ports="1000",
        )

    def test_noninteger_scope_uses_stable_json_error_without_scanning(self) -> None:
        with patch("driftbox.cli.NmapAdapter") as adapter, patch(
            "sys.argv",
            [
                "driftbox",
                "services",
                "10.1.2.3",
                "--confirm-authorization",
                "--top-ports",
                "1.5",
                "--json",
            ],
        ):
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(main(), 2)
        self.assertEqual(json.loads(output.getvalue())["status"], "invalid_request")
        adapter.return_value.scan.assert_not_called()


class ServiceInventoryCommandTests(unittest.TestCase):
    def test_missing_authorization_refuses_before_target_validation_or_adapter(self) -> None:
        adapter = Mock()
        with patch("driftbox.cli.NmapAdapter", return_value=adapter):
            output = io.StringIO()
            with redirect_stdout(output):
                code = run_service_inventory("not a target", authorization_confirmed=False, json_output=True)
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())["status"], "authorization_required")
        adapter.scan.assert_not_called()

    def test_unsafe_and_injection_like_targets_never_construct_adapter(self) -> None:
        for target in ("8.8.8.8", "192.168.1.20;whoami", "192.168.1.0/24", "example.test", "[::1]"):
            with self.subTest(target=target), patch("driftbox.cli.NmapAdapter") as adapter:
                with redirect_stderr(io.StringIO()):
                    code = run_service_inventory(target, authorization_confirmed=True)
                self.assertEqual(code, 2)
                adapter.return_value.scan.assert_not_called()

    def test_port_scope_boundaries_are_enforced_before_adapter(self) -> None:
        for ports, expected in ((1, 0), (1000, 0), (0, 2), (1001, 2)):
            with self.subTest(ports=ports), patch("driftbox.cli.NmapAdapter") as adapter:
                if expected == 0:
                    adapter.return_value.scan.return_value = sample_result(
                        top_ports=ports,
                        target="10.1.2.3",
                    )
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    code = run_service_inventory("10.1.2.3", authorization_confirmed=True, top_ports=ports)
                self.assertEqual(code, expected)
                if expected:
                    adapter.return_value.scan.assert_not_called()

    @patch("driftbox.cli.NmapAdapter")
    def test_json_is_deterministic_complete_and_never_invokes_real_nmap(self, adapter: Mock) -> None:
        adapter.return_value.scan.return_value = sample_result()
        first, second = io.StringIO(), io.StringIO()
        with redirect_stdout(first):
            self.assertEqual(run_service_inventory("192.168.1.20", authorization_confirmed=True, json_output=True), 0)
        with redirect_stdout(second):
            self.assertEqual(run_service_inventory("192.168.1.20", authorization_confirmed=True, json_output=True), 0)
        self.assertEqual(first.getvalue(), second.getvalue())
        payload = json.loads(first.getvalue())
        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(payload["target"]["address"], "192.168.1.20")
        self.assertTrue(payload["authorization"]["confirmed"])
        self.assertEqual(payload["scan_profile"]["top_ports"], 100)
        self.assertEqual(payload["nmap"]["xml_version"], "1.05")
        self.assertEqual(payload["scan_profile"]["privilege_mode"], "unprivileged")
        self.assertEqual(payload["scan_profile"]["scripts"], "disabled")
        self.assertNotIn("Program Files", first.getvalue())
        self.assertEqual(payload["services"][0]["port"], 443)
        self.assertEqual(payload["interpretation"]["schema_version"], 1)
        self.assertEqual(
            payload["interpretation"]["service_summary"]["vulnerability_correlation"]["status"],
            "not_performed",
        )
        self.assertEqual(adapter.return_value.scan.call_count, 2)

    @patch("driftbox.cli.NmapAdapter")
    def test_no_open_ports_and_partial_evidence_are_successful_and_explicit(self, adapter: Mock) -> None:
        adapter.return_value.scan.return_value = sample_result(incomplete=True, services=())
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(run_service_inventory("192.168.1.20", authorization_confirmed=True), 0)
        self.assertIn("Open ports: 0", output.getvalue())
        self.assertIn("Evidence incomplete: yes", output.getvalue())
        self.assertIn("No reported open ports", output.getvalue())
        self.assertIn("not automatically vulnerable", output.getvalue())

    def test_stable_error_mapping_and_scan_started_state(self) -> None:
        cases = (
            (NmapUnavailableError("missing"), "nmap_unavailable", False),
            (NmapExecutionTimeoutError("late"), "nmap_timeout", True),
            (NmapExecutionError(2), "nmap_failed", True),
            (NmapXMLParseError("broken"), "invalid_evidence", True),
        )
        for error, status, started in cases:
            with self.subTest(status=status), patch("driftbox.cli.NmapAdapter") as adapter:
                adapter.return_value.scan.side_effect = error
                output = io.StringIO()
                with redirect_stdout(output):
                    code = run_service_inventory("192.168.1.20", authorization_confirmed=True, json_output=True)
                payload = json.loads(output.getvalue())
                self.assertEqual(code, 4)
                self.assertEqual(payload["status"], status)
                self.assertEqual(payload["scan_started"], started)

    @patch("driftbox.cli.NmapAdapter")
    def test_post_scan_contract_failure_is_marked_started(self, adapter: Mock) -> None:
        malformed = sample_result()
        adapter.return_value.scan.return_value = NmapScanResult(
            installation=malformed.installation,
            command=("nmap", "--script", "vuln"),
            started_at=malformed.started_at,
            completed_at=malformed.completed_at,
            exit_code=malformed.exit_code,
            parsed=malformed.parsed,
        )
        output = io.StringIO()
        with redirect_stdout(output):
            code = run_service_inventory(
                "192.168.1.20",
                authorization_confirmed=True,
                json_output=True,
            )
        self.assertEqual(code, 4)
        self.assertTrue(json.loads(output.getvalue())["scan_started"])

    @patch("driftbox.cli.NmapAdapter")
    def test_output_failure_returns_stable_exit_four(self, adapter: Mock) -> None:
        adapter.return_value.scan.return_value = sample_result()
        with patch("builtins.print", side_effect=OSError("closed output")):
            self.assertEqual(
                run_service_inventory(
                    "192.168.1.20",
                    authorization_confirmed=True,
                ),
                4,
            )


class ServiceInventoryFormattingTests(unittest.TestCase):
    def test_terminal_output_keeps_unknown_explicit_and_strips_terminal_controls(self) -> None:
        report = {
            "schema_version": 1, "target": {"address": "192.168.1.20"},
            "nmap": {"version": "7.99\x1b[2J"},
            "scan_profile": {"top_ports": 100}, "execution": {"status": "completed"},
            "host": {"state": "up"}, "evidence": {"incomplete": False, "incomplete_reasons": []},
            "services": [{"protocol": "tcp", "port": 80, "state": "open", "reason": "syn-ack", "service": {"name": "http", "product": None, "version": None, "extrainfo": None, "tunnel": None, "cpe": None, "method": None, "confidence": None}}],
            "limitations": [],
        }
        text = format_service_inventory(report)
        self.assertNotIn("\x1b", text)
        self.assertIn("Product: unavailable", text)
        self.assertIn("Tunnel/TLS: unavailable", text)
        self.assertIn("Vulnerability correlation", text)

    @patch("driftbox.cli.NmapAdapter")
    def test_privacy_safe_windows_relationships_have_context_and_bottom_line(
        self, adapter: Mock
    ) -> None:
        target = "10.55.0.20"
        adapter.return_value.scan.return_value = sample_result(
            services=privacy_safe_windows_services(), target=target
        )
        output = io.StringIO()
        with patch("driftbox.cli.show_listening_ports") as ports, patch(
            "driftbox.cli.show_firewall_info"
        ) as firewall, patch("driftbox.cli.show_security_checks") as check, redirect_stdout(
            output
        ):
            self.assertEqual(
                run_service_inventory(
                    target,
                    authorization_confirmed=True,
                ),
                0,
            )
        ports.assert_not_called()
        firewall.assert_not_called()
        check.assert_not_called()
        adapter.return_value.scan.assert_called_once_with(target, top_ports=100)
        text = output.getvalue()
        self.assertIn(
            "Common association: Commonly associated with Microsoft Windows RPC.",
            text,
        )
        self.assertIn(
            "Common association: Commonly associated with legacy Windows "
            "file/printer networking.",
            text,
        )
        self.assertIn(
            "Common association: Commonly associated with SMB and Windows file sharing.",
            text,
        )
        self.assertIn("BOTTOM LINE", text)
        self.assertIn("commonly seen on Windows systems", text)
        self.assertIn("Nothing in this evidence proves a vulnerability", text)
        self.assertIn("SMB/NetBIOS service exposure is intentional", text)
        self.assertIn("restricted by firewall rules", text)
        self.assertIn(
            "does not establish internet reachability or reachability from another device",
            text,
        )
        self.assertEqual(text.count("not guaranteed identity"), 1)
        self.assertEqual(
            text.count("Only the selected common TCP ports were examined."), 1
        )
        self.assertIn(
            "Recommendations are suggestions only; Driftbox never executes them "
            "automatically.",
            text,
        )
        self.assertIn("1. [LOCAL READ-ONLY] driftbox ports", text)
        self.assertIn("2. [LOCAL READ-ONLY] driftbox firewall", text)
        self.assertIn("3. [LOCAL READ-ONLY] driftbox check", text)
        self.assertIn(
            "4. [ACTIVE AUTHORIZED SCAN] driftbox services 10.55.0.20 ", text
        )


class ServiceInventoryRecommendationTests(unittest.TestCase):
    def test_recommendations_are_ranked_parser_valid_and_non_alarmist(self) -> None:
        result = sample_result()
        with patch("driftbox.cli.NmapAdapter") as adapter:
            adapter.return_value.scan.return_value = result
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(
                    run_service_inventory(
                        "192.168.1.20",
                        authorization_confirmed=True,
                        json_output=True,
                    ),
                    0,
                )
        report = json.loads(output.getvalue())
        interpretation = build_service_inventory_interpretation(report)
        recommendations = interpretation["recommendations"]
        self.assertEqual([item["rank"] for item in recommendations], [1, 2, 3, 4])
        self.assertEqual(
            [item["command"] for item in recommendations],
            [
                "driftbox ports",
                "driftbox firewall",
                "driftbox check",
                "driftbox services 192.168.1.20 --confirm-authorization "
                "--top-ports 100 --json",
            ],
        )
        self.assertEqual(
            [item["activity_level"] for item in recommendations],
            [
                "LOCAL READ-ONLY",
                "LOCAL READ-ONLY",
                "LOCAL READ-ONLY",
                "ACTIVE AUTHORIZED SCAN",
            ],
        )
        validate_service_recommendation_commands(recommendations, build_parser().parse_args)
        rendered = json.dumps(recommendations)
        self.assertNotIn("--script", rendered)
        self.assertNotIn("metasploit", rendered.lower())

    @patch("driftbox.cli.NmapAdapter")
    def test_interpretation_structures_common_windows_relationships(
        self, adapter: Mock
    ) -> None:
        target = "10.55.0.20"
        adapter.return_value.scan.return_value = sample_result(
            services=privacy_safe_windows_services(), target=target
        )
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(
                run_service_inventory(
                    target,
                    authorization_confirmed=True,
                    json_output=True,
                ),
                0,
            )
        interpretation = json.loads(output.getvalue())["interpretation"]
        recognized = interpretation["recognized_common_services"]
        self.assertEqual([item["port"] for item in recognized], [135, 139, 445])
        self.assertEqual(
            [item["observed_name"] for item in recognized],
            ["msrpc", "netbios-ssn", "microsoft-ds"],
        )
        self.assertTrue(
            all("Commonly associated" in item["explanation"] for item in recognized)
        )
        self.assertIn("commonly seen on Windows systems", interpretation["bottom_line"])

    def test_unexpected_external_recommendation_is_rejected(self) -> None:
        unsafe_commands = (
            "curl https://example.test",
            "driftbox report",
            "driftbox ports",
            "driftbox services 8.8.8.8 --confirm-authorization --json",
            "driftbox services 10.0.0.2 --confirm-authorization --json",
            "driftbox services 10.0.0.1 --json",
            "driftbox services 10.0.0.1 --confirm-authorization",
        )
        for command in unsafe_commands:
            with self.subTest(command=command), self.assertRaises(ValueError):
                validate_service_recommendation_commands(
                    [{"command": command, "target": "10.0.0.1"}],
                    build_parser().parse_args,
                )


if __name__ == "__main__":
    unittest.main()
