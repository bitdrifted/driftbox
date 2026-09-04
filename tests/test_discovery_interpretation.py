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


def manual_output_relationship_report() -> dict[str, object]:
    """Model the authorized /24 output relationships without network access."""
    local_address = "192.168.77.200"
    responsive_addresses = {
        f"192.168.77.{octet}" for octet in range(1, 10)
    }
    cache_only_addresses = {
        f"192.168.77.{octet}" for octet in range(65, 73)
    }
    remote_addresses = [
        f"192.168.77.{octet}" for octet in range(1, 255)
        if f"192.168.77.{octet}" != local_address
    ]
    hosts: list[dict[str, object]] = []
    for address in sorted(
        responsive_addresses | cache_only_addresses | {local_address},
        key=lambda value: int(value.rsplit(".", 1)[1]),
    ):
        if address == local_address:
            hosts.append({
                "address": address,
                "status": "local_machine",
                "evidence": [{
                    "kind": "local_interface_address",
                    "source": "psutil_interface_data",
                }],
            })
        elif address in responsive_addresses:
            evidence: list[dict[str, object]] = [
                {"kind": "icmp_echo_reply", "source": "system_ping"}
            ]
            host: dict[str, object] = {
                "address": address,
                "status": "confirmed_responsive",
                "evidence": evidence,
            }
            if address == "192.168.77.1":
                evidence.extend([
                    {"kind": "neighbor_cache", "source": "arp_cache"},
                    {
                        "kind": "default_gateway_route",
                        "source": "routing_table",
                        "interface": local_address,
                    },
                ])
                host["device_role"] = "gateway_router"
            hosts.append(host)
        else:
            hosts.append({
                "address": address,
                "status": "known_neighbor",
                "evidence": [{
                    "kind": "neighbor_cache",
                    "source": "arp_cache",
                }],
            })

    return {
        "schema_version": 2,
        "generated_at": "2026-09-03T12:00:00+00:00",
        "collection_status": "completed",
        "target": {
            "cidr": "192.168.77.0/24",
            "address_count": 256,
            "host_address_count": 254,
            "probe_address_count": 253,
        },
        "settings": {"timeout_seconds": 0.75, "workers": 16},
        "authorization": {"scope": "explicitly authorized private IPv4 only"},
        "summary": {
            "local_machine": 1,
            "confirmed_responsive": 9,
            "known_neighbor": 8,
            # The responsive gateway remains in its mutually exclusive
            # responsive classification. Its role is overlapping metadata.
            "confirmed_gateway": 0,
            "addresses_probed": 253,
            "responses_received": 9,
            "no_response_observed": 244,
            "probe_timeouts": 0,
            "probe_unavailable": 0,
            "probe_errors": 0,
        },
        "probe_outcomes": [
            {
                "address": address,
                "status": (
                    "responsive" if address in responsive_addresses
                    else "no_response"
                ),
            }
            for address in remote_addresses
        ],
        "neighbor_cache": {"status": "available", "detail": None},
        "default_gateway": {
            "status": "available",
            "detail": None,
            "records": [{"address": "192.168.77.1", "interface": local_address}],
        },
        "sources": {
            "routing_table": {"status": "available", "detail": None},
            "reachability": {"status": "available", "detail": None},
            "neighbor_cache": {"status": "available", "detail": None},
        },
        "hosts": hosts,
        "limitations": [
            "Only ICMP echo replies, local interface data, existing neighbor-cache records, and local default-route records are considered.",
            "A device is labeled gateway/router only when a local default-route entry confirms it; neighbor/cache and reachability evidence are insufficient.",
            "A silent or timed-out address may still have a host; no absence claim is made.",
            "Hostnames are not resolved, and ports and vulnerabilities are not scanned.",
        ],
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
        self.assertEqual(summary["neighbor_cache_evidence_addresses"], [
            "192.168.1.3",
        ])
        self.assertEqual(summary["evidence_overlap"], {
            "probe_no_reply_count": 2,
            "no_reply_with_neighbor_cache_count": 1,
            "no_reply_with_neighbor_cache_addresses": ["192.168.1.3"],
            "counts_are_additive": False,
            "outcomes_available": True,
        })
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
        json_recommendation = recommendations[3]
        self.assertIn("Display complete structured evidence", json_recommendation["purpose"])
        self.assertIn("standard output", json_recommendation["expected_result"])
        self.assertIn("does not save it automatically", json_recommendation["expected_result"])
        self.assertNotIn("retain", str(json_recommendation).lower())

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
        self.assertEqual(summary["evidence_overlap"], {
            "probe_no_reply_count": 0,
            "no_reply_with_neighbor_cache_count": 0,
            "no_reply_with_neighbor_cache_addresses": [],
            "counts_are_additive": False,
            "outcomes_available": False,
        })
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
        self.assertIn("Probes that received no reply: 2.", text)
        self.assertIn(
            "No-reply/cache overlap: 1 of the 2 addresses without a reply also "
            "have neighbor/cache evidence; these categories overlap and should "
            "not be added together.",
            text,
        )
        self.assertIn(
            "Addresses that did not respond (terminal preview): 192.168.1.3, 192.168.1.4",
            text,
        )
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

    def test_manual_output_relationships_separate_roles_and_overlap(self) -> None:
        enriched = with_discovery_interpretation(
            manual_output_relationship_report()
        )
        interpretation = enriched["interpretation"]
        assert isinstance(interpretation, dict)
        summary = interpretation["discovery_summary"]
        recommendations = interpretation["recommendations"]
        detailed_evidence = interpretation["detailed_evidence"]
        assert isinstance(summary, dict)
        assert isinstance(recommendations, list)
        assert isinstance(detailed_evidence, dict)

        self.assertEqual(summary["positive_host_evidence_count"], 18)
        self.assertEqual(len(summary["local_computer_addresses"]), 1)
        self.assertEqual(len(summary["responsive_devices"]), 9)
        self.assertEqual(len(summary["cache_only_devices"]), 8)
        self.assertEqual(summary["confirmed_in_scope_gateways"], ["192.168.77.1"])
        self.assertEqual(len(summary["neighbor_cache_evidence_addresses"]), 9)
        self.assertEqual(summary["evidence_overlap"], {
            "probe_no_reply_count": 244,
            "no_reply_with_neighbor_cache_count": 8,
            "no_reply_with_neighbor_cache_addresses": [
                f"192.168.77.{octet}" for octet in range(65, 73)
            ],
            "counts_are_additive": False,
            "outcomes_available": True,
        })
        self.assertEqual(len(detailed_evidence["probe_outcomes"]), 253)
        self.assertEqual(len(detailed_evidence["hosts"]), 18)
        self.assertTrue(detailed_evidence["limitations"])
        self.assertTrue(detailed_evidence["cautions"])

        text = format_network_discovery(enriched)
        self.assertIn(
            "18 host records: 1 local machine, 9 responsive, 8 cache-only.",
            text,
        )
        self.assertIn(
            "Confirmed gateway roles: 1 (192.168.77.1); role counts may overlap "
            "host classifications.",
            text,
        )
        self.assertNotIn("0 configured gateway/router", text)
        self.assertIn("Probes that received no reply: 244.", text)
        self.assertIn(
            "No-reply/cache overlap: 8 of the 244 addresses without a reply also "
            "have neighbor/cache evidence; these categories overlap and should "
            "not be added together.",
            text,
        )
        self.assertEqual(
            text.count("Silence does not prove an address is unused or offline."),
            1,
        )
        self.assertNotIn("Cautions:", text)
        self.assertNotIn("Next safe step:", text)
        self.assertEqual(text.count("Privacy:"), 1)
        self.assertEqual(
            text.count("Safety boundary: Discovery does not authorize"),
            1,
        )

        json_recommendation = recommendations[3]
        self.assertIn("Display complete structured evidence", json_recommendation["purpose"])
        self.assertIn("does not save it automatically", json_recommendation["expected_result"])
        self.assertNotIn("retain", str(json_recommendation).lower())

    def test_human_output_bounds_each_address_preview_and_host_table(self) -> None:
        data = report()
        target = data["target"]
        summary = data["summary"]
        assert isinstance(target, dict)
        assert isinstance(summary, dict)
        target.update({
            "cidr": "192.168.1.0/24",
            "address_count": 256,
            "host_address_count": 254,
            "probe_address_count": 254,
        })

        def host(address: int, status: str, evidence: list[dict[str, object]]) -> dict[str, object]:
            return {
                "address": f"192.168.1.{address}",
                "status": status,
                "evidence": evidence,
            }

        data["hosts"] = (
            [host(address, "local_machine", [{
                "kind": "local_interface_address", "source": "psutil_interface_data",
            }]) for address in range(1, 12)]
            + [host(address, "confirmed_responsive", [{
                "kind": "icmp_echo_reply", "source": "system_ping",
            }]) for address in range(20, 31)]
            + [host(address, "known_neighbor", [{
                "kind": "neighbor_cache", "source": "arp_cache",
            }]) for address in range(40, 51)]
            + [host(address, "confirmed_gateway", [{
                "kind": "default_gateway_route", "source": "routing_table",
            }]) for address in range(60, 71)]
        )
        data["probe_outcomes"] = (
            [{"address": f"192.168.1.{address}", "status": "no_response"}
             for address in range(80, 92)]
            + [{"address": f"192.168.1.{address}", "status": "unavailable"}
             for address in range(100, 112)]
        )
        summary.update({
            "local_machine": 11,
            "confirmed_responsive": 11,
            "known_neighbor": 11,
            "confirmed_gateway": 11,
            "addresses_probed": 24,
            "responses_received": 0,
            "no_response_observed": 12,
            "probe_timeouts": 0,
            "probe_unavailable": 12,
            "probe_errors": 0,
        })

        enriched = with_discovery_interpretation(data)
        self.assertEqual(enriched["probe_outcomes"], data["probe_outcomes"])
        text = format_network_discovery(enriched)

        self.assertIn(
            "This computer's address: 192.168.1.1, 192.168.1.2, 192.168.1.3, "
            "192.168.1.4, 192.168.1.5, 192.168.1.6, 192.168.1.7, 192.168.1.8, "
            "192.168.1.9, 192.168.1.10, and 1 more",
            text,
        )
        self.assertIn("Devices that responded during the scan: 192.168.1.20", text)
        self.assertIn("192.168.1.29, and 1 more", text)
        self.assertIn("Devices supported only by neighbor/cache evidence: 192.168.1.40", text)
        self.assertIn("192.168.1.49, and 1 more", text)
        self.assertIn("Confirmed default gateway: 192.168.1.60", text)
        self.assertIn("192.168.1.69, and 1 more", text)
        self.assertIn("Probes that received no reply: 12.", text)
        self.assertIn("Addresses that did not respond (terminal preview): 192.168.1.80", text)
        self.assertIn("192.168.1.89, and 2 more", text)
        self.assertIn("Addresses with unavailable or failed probes: 192.168.1.100", text)
        self.assertIn("192.168.1.109, and 2 more", text)
        self.assertIn("... and 34 more host evidence rows.", text)
        self.assertIn("Probe outcomes (aggregated): 24 attempted", text)
        self.assertIn(
            "Terminal previews show at most 10 addresses or host rows.", text
        )
        self.assertIn("driftbox discover 192.168.1.0/24 --json", text)
        self.assertNotIn("192.168.1.11     ", text)
        summary_text = text.split("WHAT THIS MEANS", maxsplit=1)[0]
        self.assertNotIn("192.168.1.80", summary_text)


if __name__ == "__main__":
    unittest.main()
