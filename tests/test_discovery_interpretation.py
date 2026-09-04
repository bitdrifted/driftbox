"""Hermetic tests for deterministic discovery explanations and next moves."""

from __future__ import annotations

from copy import deepcopy
import unittest

from driftbox.cli import build_parser, format_network_discovery
from driftbox.discovery_interpretation import (
    ACTIVITY_LEVELS,
    INTERPRETATION_SCHEMA_VERSION,
    build_discovery_interpretation,
    validate_recommendation_commands,
    with_discovery_interpretation,
)


def report() -> dict[str, object]:
    """Return a complete synthetic schema-v2 result without network activity."""
    return {
        "schema_version": 2,
        "generated_at": "2026-09-03T12:00:00+00:00",
        "collection_status": "partial",
        "target": {
            "cidr": "192.168.1.0/29",
            "address_count": 8,
            "host_address_count": 6,
            "probe_address_count": 5,
        },
        "settings": {"timeout_seconds": 0.5, "workers": 4},
        "authorization": {"scope": "explicitly authorized private IPv4 only"},
        "summary": {
            "local_machine": 1,
            "confirmed_responsive": 1,
            "known_neighbor": 1,
            "confirmed_gateway": 1,
            "addresses_probed": 5,
            "responses_received": 1,
            "no_response_observed": 1,
            "probe_timeouts": 1,
            "probe_unavailable": 1,
            "probe_errors": 1,
        },
        # Deliberately unordered input verifies numerical output ordering.
        "probe_outcomes": [
            {"address": "192.168.1.6", "status": "error", "detail": "adapter failed"},
            {"address": "192.168.1.4", "status": "timeout"},
            {"address": "192.168.1.5", "status": "unavailable"},
            {"address": "192.168.1.3", "status": "no_response"},
            {"address": "192.168.1.2", "status": "responsive"},
        ],
        "neighbor_cache": {"status": "available", "detail": None},
        "default_gateway": {
            "status": "available",
            "detail": None,
            "records": [{"address": "192.168.1.4", "interface": "eth0"}],
        },
        "sources": {
            "routing_table": {"status": "available", "detail": None},
            "reachability": {"status": "partial", "detail": "some probes failed"},
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
            },
            {
                "address": "192.168.1.2",
                "status": "confirmed_responsive",
                "evidence": [{"kind": "icmp_echo_reply", "source": "system_ping"}],
            },
            {
                "address": "192.168.1.3",
                "status": "known_neighbor",
                "evidence": [{"kind": "neighbor_cache", "source": "arp_cache"}],
            },
            {
                "address": "192.168.1.4",
                "status": "confirmed_gateway",
                "device_role": "gateway_router",
                "evidence": [{
                    "kind": "default_gateway_route",
                    "source": "routing_table",
                    "interface": "eth0",
                }],
            },
        ],
        "limitations": ["A silent address may still have a host; no absence claim is made."],
    }


class DiscoveryInterpretationTests(unittest.TestCase):
    """The next-move model stays safe, structured, and parser-valid."""

    def test_structured_summary_preserves_ordered_negative_addresses_and_gaps(self) -> None:
        interpretation = build_discovery_interpretation(report())
        summary = interpretation["discovery_summary"]
        evidence = interpretation["detailed_evidence"]
        assert isinstance(summary, dict)
        assert isinstance(evidence, dict)

        self.assertEqual(interpretation["schema_version"], INTERPRETATION_SCHEMA_VERSION)
        self.assertEqual(summary["addresses_without_response"], [
            "192.168.1.3", "192.168.1.4",
        ])
        self.assertEqual(summary["addresses_with_probe_errors"], [
            "192.168.1.5", "192.168.1.6",
        ])
        self.assertEqual(summary["local_computer_addresses"], ["192.168.1.1"])
        self.assertEqual(summary["responsive_devices"], ["192.168.1.2"])
        self.assertEqual(summary["cache_only_devices"], ["192.168.1.3"])
        self.assertEqual(summary["confirmed_in_scope_gateways"], ["192.168.1.4"])
        self.assertEqual(summary["collection_errors_or_incomplete_evidence"], {
            "sources": [
                {"source": "reachability", "status": "partial", "detail": "some probes failed"},
            ],
            "addresses_with_probe_errors": ["192.168.1.5", "192.168.1.6"],
            "outcomes_available": True,
        })
        incomplete = evidence["incomplete_evidence"]
        assert isinstance(incomplete, dict)
        self.assertEqual(incomplete["sources"], [
            {"source": "reachability", "status": "partial", "detail": "some probes failed"},
        ])

    def test_recommendations_are_exact_parser_valid_commands_with_required_fields(self) -> None:
        interpretation = build_discovery_interpretation(report())
        recommendations = interpretation["recommendations"]
        assert isinstance(recommendations, list)
        self.assertEqual([item["command"] for item in recommendations], [
            "driftbox ports",
            "driftbox firewall",
            "driftbox report",
            "driftbox discover 192.168.1.0/29 --json",
        ])
        for item in recommendations:
            for field in (
                "command", "purpose", "reason", "target", "activity_level",
                "authorization_required", "expected_result", "availability", "rank",
            ):
                self.assertIn(field, item)
            self.assertIn(item["activity_level"], ACTIVITY_LEVELS)
            self.assertIs(item["availability"]["available_now"], True)
        validate_recommendation_commands(recommendations, build_parser().parse_args)

    def test_recommendations_reject_unsafe_targets_and_non_driftbox_commands(self) -> None:
        unsafe = deepcopy(report())
        target = unsafe["target"]
        assert isinstance(target, dict)
        target["cidr"] = "192.168.1.0/29; driftbox ports"
        with self.assertRaises(ValueError):
            build_discovery_interpretation(unsafe)

        recommendations = build_discovery_interpretation(report())["recommendations"]
        assert isinstance(recommendations, list)
        altered = deepcopy(recommendations)
        altered[0]["command"] = "ports"
        with self.assertRaises(ValueError):
            validate_recommendation_commands(altered, build_parser().parse_args)

    def test_gateway_category_requires_route_evidence_and_cache_only_is_literal(self) -> None:
        data = report()
        hosts = data["hosts"]
        assert isinstance(hosts, list)
        cache_gateway = hosts[2]
        assert isinstance(cache_gateway, dict)
        evidence = cache_gateway["evidence"]
        assert isinstance(evidence, list)
        evidence.append({"kind": "default_gateway_route", "source": "routing_table"})
        claimed_without_evidence = hosts[3]
        assert isinstance(claimed_without_evidence, dict)
        claimed_without_evidence["evidence"] = []

        summary = build_discovery_interpretation(data)["discovery_summary"]
        assert isinstance(summary, dict)
        self.assertEqual(summary["cache_only_devices"], [])
        self.assertEqual(summary["confirmed_in_scope_gateways"], ["192.168.1.3"])

    def test_schema_v1_input_preserves_unknown_address_level_evidence(self) -> None:
        legacy = report()
        legacy["schema_version"] = 1
        legacy.pop("probe_outcomes")
        legacy.pop("default_gateway")
        sources = legacy["sources"]
        assert isinstance(sources, dict)
        sources.pop("routing_table")
        interpretation = build_discovery_interpretation(legacy)
        summary = interpretation["discovery_summary"]
        details = interpretation["detailed_evidence"]
        assert isinstance(summary, dict)
        assert isinstance(details, dict)
        self.assertEqual(summary["addresses_without_response"], [])
        self.assertIs(
            summary["collection_errors_or_incomplete_evidence"]["outcomes_available"],
            False,
        )
        self.assertEqual(
            details["collection"]["default_gateway"]["status"],
            "not_collected",
        )

    def test_malformed_or_out_of_scope_probe_outcomes_fail_closed(self) -> None:
        for address in (
            "192.168.1.0",
            "192.168.1.7",
            "192.168.2.1",
            "router.local",
            "192.168.1.2;whoami",
        ):
            with self.subTest(address=address):
                data = report()
                data["probe_outcomes"] = [
                    {"address": address, "status": "no_response"}
                ]
                with self.assertRaises(ValueError):
                    build_discovery_interpretation(data)

    def test_interpretation_is_deterministic_and_has_required_meaning(self) -> None:
        first = build_discovery_interpretation(report())
        second = build_discovery_interpretation(deepcopy(report()))
        self.assertEqual(first, second)
        meaning = first["what_this_means"]
        self.assertIn("A response proves only that the device answered at scan time.", meaning)
        self.assertIn(
            "Cache evidence means this computer has seen the device, not necessarily that it is currently online.",
            meaning,
        )
        self.assertIn("Silence does not prove an address is unused or offline.", meaning)
        self.assertIn(
            "The discovered device count is a minimum supported by positive evidence.",
            meaning,
        )
        self.assertIn(
            "Unknown devices are not automatically suspicious or malicious.", meaning
        )

    def test_terminal_output_has_all_explanation_sections_and_named_addresses(self) -> None:
        text = format_network_discovery(with_discovery_interpretation(report()))
        for heading in (
            "DISCOVERY SUMMARY",
            "WHAT THIS MEANS",
            "RECOMMENDED NEXT STEPS",
            "DETAILED EVIDENCE",
        ):
            self.assertIn(heading, text)
        self.assertIn("Addresses that did not respond: 192.168.1.3, 192.168.1.4", text)
        self.assertIn("Addresses with unavailable or failed probes: 192.168.1.5, 192.168.1.6", text)
        self.assertIn("This computer's address: 192.168.1.1", text)
        self.assertIn("Devices that responded during the scan: 192.168.1.2", text)
        self.assertIn("Devices supported only by neighbor/cache evidence: 192.168.1.3", text)
        self.assertIn("Confirmed default gateway: 192.168.1.4", text)
        self.assertIn(
            "Collection errors or incomplete evidence: reachability=partial (some probes failed); probe issues at 192.168.1.5, 192.168.1.6.",
            text,
        )
        self.assertIn("Risk/activity: LOCAL READ-ONLY", text)
        self.assertIn("Available now: yes.", text)
        self.assertIn("Discovery does not authorize port scanning", text)


if __name__ == "__main__":
    unittest.main()
