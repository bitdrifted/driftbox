"""Hermetic CLI tests for authorized private-network discovery."""

from __future__ import annotations

import io
import ipaddress
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import Mock, patch

from driftbox.cli import (
    build_parser,
    format_network_discovery,
    main,
    run_network_discovery,
)
from driftbox.discovery_interpretation import with_discovery_interpretation
from driftbox.network_discovery import (
    CandidateSelectionRequired,
    DiscoveryOperationalError,
    NetworkCandidate,
    NoSuitableNetworkError,
    TargetValidationError,
)


def sample_candidate(cidr: str, interface: str, address: str) -> NetworkCandidate:
    return NetworkCandidate(
        ipaddress.IPv4Network(cidr),
        (interface,),
        (ipaddress.IPv4Address(address),),
    )


def sample_report(collection_status: str = "completed") -> dict[str, object]:
    return {
        "schema_version": 1,
        "generated_at": "2026-09-03T12:00:00+00:00",
        "collection_status": collection_status,
        "target": {
            "cidr": "192.168.1.0/30",
            "address_count": 4,
            "host_address_count": 2,
            "probe_address_count": 1,
        },
        "settings": {
            "timeout_seconds": 0.5,
            "workers": 4,
            "maximum_target_addresses": 256,
        },
        "authorization": {
            "scope": "explicitly authorized private IPv4 only",
            "allowed_ranges": [],
        },
        "summary": {
            "local_machine": 1,
            "confirmed_responsive": 1,
            "known_neighbor": 0,
            "addresses_probed": 1,
            "responses_received": 1,
            "no_response_observed": 0,
            "probe_timeouts": 0,
            "probe_unavailable": 0,
            "probe_errors": 0,
        },
        "neighbor_cache": {"status": "available", "detail": None},
        "sources": {
            "reachability": {"status": "available"},
            "neighbor_cache": {"status": "available", "detail": None},
        },
        "hosts": [
            {
                "address": "192.168.1.1",
                "status": "local_machine",
                "evidence": [{
                    "kind": "local_interface_address",
                    "source": "psutil_interface_data",
                }],
                "metadata": {"hostname": {
                    "value": None,
                    "status": "not_collected",
                    "reason": "Reverse DNS is intentionally disabled.",
                }},
            },
            {
                "address": "192.168.1.2",
                "status": "confirmed_responsive",
                "evidence": [
                    {"kind": "icmp_echo_reply", "source": "system_ping"},
                    {
                        "kind": "neighbor_cache",
                        "source": "arp_cache",
                        "mac_address": "aa:bb:cc:dd:ee:02",
                        "state": "dynamic",
                    },
                ],
                "metadata": {"hostname": {
                    "value": None,
                    "status": "not_collected",
                    "reason": "Reverse DNS is intentionally disabled.",
                }},
            },
        ],
        "limitations": [
            "A silent address may still have a host; no absence claim is made.",
        ],
    }


class DiscoverParserTests(unittest.TestCase):
    """The learner-facing syntax maps cleanly to bounded settings."""

    def test_optional_cidr_and_json_timeout_workers_are_parsed(self) -> None:
        parser = build_parser()
        defaults = parser.parse_args(["discover"])
        explicit = parser.parse_args([
            "discover",
            "192.168.1.0/24",
            "--json",
            "--timeout",
            "0.4",
            "--workers",
            "8",
        ])
        self.assertEqual(defaults.command, "discover")
        self.assertIsNone(defaults.cidr)
        self.assertFalse(defaults.json_output)
        self.assertEqual(explicit.cidr, "192.168.1.0/24")
        self.assertTrue(explicit.json_output)
        self.assertEqual(explicit.timeout, 0.4)
        self.assertEqual(explicit.workers, 8)

    @patch("driftbox.cli.run_network_discovery", return_value=3)
    def test_main_dispatches_all_discovery_arguments(self, run: Mock) -> None:
        with patch(
            "sys.argv",
            ["driftbox", "discover", "10.0.0.0/24", "--json", "--timeout", "0.2", "--workers", "3"],
        ):
            self.assertEqual(main(), 3)
        run.assert_called_once_with(
            "10.0.0.0/24",
            json_output=True,
            timeout_seconds=0.2,
            workers=3,
        )


class DiscoverCommandTests(unittest.TestCase):
    """Exit codes and output remain stable without touching a live network."""

    @patch("driftbox.cli.discover_network")
    @patch("driftbox.cli.resolve_target")
    @patch("driftbox.cli.detect_local_network_candidates")
    def test_explicit_target_skips_interface_detection_and_emits_schema_json(
        self,
        detect: Mock,
        resolve: Mock,
        discover: Mock,
    ) -> None:
        target = ipaddress.IPv4Network("192.168.1.0/30")
        resolve.return_value = target
        discover.return_value = sample_report()
        output = io.StringIO()

        with redirect_stdout(output):
            code = run_network_discovery(
                "192.168.1.0/30",
                json_output=True,
                timeout_seconds=0.5,
                workers=4,
            )

        self.assertEqual(code, 0)
        self.assertEqual(
            json.loads(output.getvalue()),
            with_discovery_interpretation(sample_report()),
        )
        self.assertEqual(
            output.getvalue(),
            json.dumps(
                with_discovery_interpretation(sample_report()),
                indent=2,
                sort_keys=True,
            ) + "\n",
        )
        detect.assert_not_called()
        resolve.assert_called_once_with("192.168.1.0/30", candidates=None)
        discover.assert_called_once_with(
            target,
            timeout_seconds=0.5,
            workers=4,
        )

    @patch("driftbox.cli.discover_network", return_value=sample_report())
    @patch("driftbox.cli.resolve_target")
    @patch("driftbox.cli.detect_local_network_candidates")
    def test_one_local_candidate_is_selected_without_guessing_beyond_it(
        self,
        detect: Mock,
        resolve: Mock,
        discover: Mock,
    ) -> None:
        only = sample_candidate("10.0.0.0/24", "eth0", "10.0.0.4")
        detect.return_value = [only]
        resolve.return_value = only.network
        with redirect_stdout(io.StringIO()):
            self.assertEqual(run_network_discovery(), 0)
        resolve.assert_called_once_with(None, candidates=[only])
        discover.assert_called_once()

    @patch("driftbox.cli.discover_network")
    @patch("driftbox.cli.resolve_target")
    @patch("driftbox.cli.detect_local_network_candidates")
    def test_multiple_candidates_are_listed_with_exit_3_and_no_probe(
        self,
        detect: Mock,
        resolve: Mock,
        discover: Mock,
    ) -> None:
        choices = [
            sample_candidate("10.0.0.0/24", "eth0", "10.0.0.4"),
            sample_candidate("192.168.1.0/24", "wlan0", "192.168.1.4"),
        ]
        detect.return_value = choices
        resolve.side_effect = CandidateSelectionRequired(choices)
        output = io.StringIO()

        with redirect_stdout(output):
            code = run_network_discovery(json_output=True)

        payload = json.loads(output.getvalue())
        self.assertEqual(code, 3)
        self.assertEqual(payload["schema_version"], 2)
        self.assertEqual(payload["status"], "selection_required")
        self.assertIs(payload["probes_started"], False)
        self.assertEqual([item["cidr"] for item in payload["candidates"]], [
            "10.0.0.0/24", "192.168.1.0/24",
        ])
        discover.assert_not_called()

    @patch("driftbox.cli.discover_network")
    @patch("driftbox.cli.resolve_target", side_effect=NoSuitableNetworkError("none"))
    @patch("driftbox.cli.detect_local_network_candidates", return_value=[])
    def test_no_candidate_returns_exit_4_without_probe(
        self,
        detect: Mock,
        resolve: Mock,
        discover: Mock,
    ) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            code = run_network_discovery(json_output=True)
        self.assertEqual(code, 4)
        self.assertEqual(json.loads(output.getvalue())["status"], "unavailable")
        discover.assert_not_called()

    @patch("driftbox.cli.discover_network")
    @patch(
        "driftbox.cli.detect_local_network_candidates",
        side_effect=DiscoveryOperationalError("interfaces unavailable"),
    )
    def test_interface_inspection_failure_returns_exit_4_without_probe(
        self,
        detect: Mock,
        discover: Mock,
    ) -> None:
        error = io.StringIO()
        with redirect_stderr(error):
            code = run_network_discovery()
        self.assertEqual(code, 4)
        self.assertIn("interfaces unavailable", error.getvalue())
        discover.assert_not_called()

    @patch("driftbox.cli.discover_network")
    @patch("driftbox.cli.resolve_target")
    def test_invalid_or_unsafe_target_and_parameters_return_exit_2(
        self,
        resolve: Mock,
        discover: Mock,
    ) -> None:
        for origin in ("target", "parameters"):
            with self.subTest(origin=origin):
                resolve.reset_mock(side_effect=True)
                discover.reset_mock(side_effect=True)
                if origin == "target":
                    resolve.side_effect = TargetValidationError("public target refused")
                    discover.side_effect = None
                else:
                    resolve.side_effect = None
                    resolve.return_value = ipaddress.IPv4Network("10.0.0.0/30")
                    discover.side_effect = TargetValidationError("timeout must be finite")
                output = io.StringIO()
                with redirect_stdout(output):
                    code = run_network_discovery(
                        "8.8.8.0/24" if origin == "target" else "10.0.0.0/30",
                        json_output=True,
                    )
                payload = json.loads(output.getvalue())
                self.assertEqual(code, 2)
                self.assertEqual(payload["status"], "invalid_request")
                self.assertIs(payload["probes_started"], False)

    @patch("driftbox.cli.discover_network", return_value=sample_report("unavailable"))
    @patch(
        "driftbox.cli.resolve_target",
        return_value=ipaddress.IPv4Network("192.168.1.0/30"),
    )
    def test_fully_unavailable_collection_is_rendered_and_returns_exit_4(
        self,
        resolve: Mock,
        discover: Mock,
    ) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            code = run_network_discovery("192.168.1.0/30", json_output=True)
        self.assertEqual(code, 4)
        self.assertEqual(json.loads(output.getvalue())["collection_status"], "unavailable")

    @patch("driftbox.cli.discover_network", return_value=sample_report("partial"))
    @patch(
        "driftbox.cli.resolve_target",
        return_value=ipaddress.IPv4Network("192.168.1.0/30"),
    )
    def test_partial_collection_is_useful_and_returns_exit_0(
        self,
        resolve: Mock,
        discover: Mock,
    ) -> None:
        with redirect_stdout(io.StringIO()):
            code = run_network_discovery("192.168.1.0/30")
        self.assertEqual(code, 0)

    @patch("driftbox.cli.discover_network", side_effect=RuntimeError("adapter defect"))
    @patch(
        "driftbox.cli.resolve_target",
        return_value=ipaddress.IPv4Network("192.168.1.0/30"),
    )
    def test_unexpected_operational_failure_returns_exit_4(
        self,
        resolve: Mock,
        discover: Mock,
    ) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            code = run_network_discovery(
                "192.168.1.0/30", json_output=True
            )
        payload = json.loads(output.getvalue())
        self.assertEqual(code, 4)
        self.assertEqual(payload["status"], "unavailable")
        self.assertNotIn("traceback", output.getvalue().lower())

    @patch("driftbox.cli.format_network_discovery", side_effect=ValueError("bad report"))
    @patch("driftbox.cli.discover_network", return_value=sample_report())
    @patch(
        "driftbox.cli.resolve_target",
        return_value=ipaddress.IPv4Network("192.168.1.0/30"),
    )
    def test_text_rendering_failure_returns_stable_exit_4(
        self,
        resolve: Mock,
        discover: Mock,
        formatter: Mock,
    ) -> None:
        error = io.StringIO()
        with redirect_stderr(error):
            code = run_network_discovery("192.168.1.0/30")
        self.assertEqual(code, 4)
        self.assertIn("output", error.getvalue().lower())

    @patch("driftbox.cli.discover_network", return_value=sample_report())
    @patch(
        "driftbox.cli.resolve_target",
        return_value=ipaddress.IPv4Network("192.168.1.0/30"),
    )
    def test_stdout_failure_returns_stable_exit_4(
        self,
        resolve: Mock,
        discover: Mock,
    ) -> None:
        with patch("builtins.print", side_effect=OSError("closed stream")):
            code = run_network_discovery("192.168.1.0/30", json_output=True)
        self.assertEqual(code, 4)


class DiscoverFormattingTests(unittest.TestCase):
    """Text output teaches evidence boundaries without overclaiming."""

    def test_text_output_explains_authorization_evidence_privacy_and_next_step(self) -> None:
        text = format_network_discovery(sample_report())
        self.assertIn("Authorization: scan only networks you own", text)
        self.assertRegex(text, r"(?m)^192\.168\.1\.1\s+local machine\s+")
        self.assertRegex(text, r"(?m)^192\.168\.1\.2\s+confirmed responsive\s+")
        self.assertIn("ICMP echo reply", text)
        self.assertIn("MAC: aa:bb:cc:dd:ee:02", text)
        self.assertIn("Hostnames: not collected", text)
        self.assertIn("Silence is inconclusive", text)
        self.assertIn("Privacy:", text)
        self.assertIn("Next safe step:", text)

    def test_no_positive_evidence_is_not_described_as_no_hosts(self) -> None:
        report = sample_report()
        report["hosts"] = []
        summary = report["summary"]
        assert isinstance(summary, dict)
        summary["local_machine"] = 0
        summary["confirmed_responsive"] = 0
        text = format_network_discovery(report)
        self.assertIn("No positive host evidence was collected.", text)
        self.assertNotIn("No hosts exist", text)


if __name__ == "__main__":
    unittest.main()
