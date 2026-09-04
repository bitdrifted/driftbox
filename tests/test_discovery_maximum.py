"""Hermetic maximum-/24 regression coverage for discovery output bounds."""

from __future__ import annotations

import io
import ipaddress
import json
import re
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from driftbox.cli import format_network_discovery, run_network_discovery
from driftbox.discovery_interpretation import with_discovery_interpretation
from driftbox.network_discovery import (
    GatewaySnapshot,
    NeighborRecord,
    NeighborSnapshot,
    ProbeResult,
    discover_network,
)


TARGET = "192.168.50.0/24"
MAX_HUMAN_HOST_ROWS = 10
MAX_HUMAN_LINE_CHARS = 300
MAX_HUMAN_OUTPUT_CHARS = 12_000


class MaximumSubnetAdapter:
    """Fully synthetic adapter: no provider or command touches a real network."""

    def ping(
        self,
        address: ipaddress.IPv4Address,
        timeout_seconds: float,
    ) -> ProbeResult:
        del timeout_seconds
        octet = int(str(address).rsplit(".", 1)[1])
        if octet <= 64:
            return ProbeResult("responsive")
        if octet <= 192:
            return ProbeResult("no_response")
        if octet <= 224:
            return ProbeResult("timeout")
        return ProbeResult("error", "synthetic adapter failure")

    def neighbors(self, timeout_seconds: float) -> NeighborSnapshot:
        del timeout_seconds
        return NeighborSnapshot(
            "available",
            records=tuple(
                NeighborRecord(
                    ipaddress.IPv4Address(f"192.168.50.{octet}"),
                    "arp_cache",
                    f"02:00:00:00:32:{octet:02x}",
                    "dynamic",
                )
                for octet in range(65, 129)
            ),
        )

    def default_gateways(self, timeout_seconds: float) -> GatewaySnapshot:
        del timeout_seconds
        return GatewaySnapshot("available")


class MaximumSubnetDiscoveryTests(unittest.TestCase):
    """A /24 stays accurate in JSON and bounded in learner-facing text."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.report = discover_network(
            TARGET,
            adapter=MaximumSubnetAdapter(),
            local_addresses=[],
            timeout_seconds=0.1,
            workers=32,
            generated_at="2026-09-03T12:00:00+00:00",
        )

    def test_maximum_subnet_counts_and_schema_v2_outcomes_are_complete(self) -> None:
        summary = self.report["summary"]
        outcomes = self.report["probe_outcomes"]
        hosts = self.report["hosts"]
        assert isinstance(summary, dict)
        assert isinstance(outcomes, list)
        assert isinstance(hosts, list)

        self.assertEqual(self.report["schema_version"], 2)
        self.assertEqual(self.report["collection_status"], "partial")
        self.assertEqual(summary, {
            "local_machine": 0,
            "confirmed_responsive": 64,
            "known_neighbor": 64,
            "confirmed_gateway": 0,
            "addresses_probed": 254,
            "responses_received": 64,
            # Cache-only entries are still silent probes.  Cache evidence
            # establishes a known neighbor, not an ICMP response.
            "no_response_observed": 128,
            "probe_timeouts": 32,
            "probe_unavailable": 0,
            "probe_errors": 30,
        })
        self.assertEqual(len(hosts), 128)
        self.assertEqual(len(outcomes), 254)
        self.assertEqual([item["address"] for item in outcomes][:2], [
            "192.168.50.1", "192.168.50.2",
        ])
        self.assertEqual(outcomes[-1]["address"], "192.168.50.254")
        self.assertEqual(
            {item["status"] for item in outcomes[0:64]}, {"responsive"}
        )
        self.assertEqual(
            {item["status"] for item in outcomes[64:192]}, {"no_response"}
        )
        self.assertEqual(
            {item["status"] for item in outcomes[192:224]}, {"timeout"}
        )
        self.assertEqual(
            {item["status"] for item in outcomes[224:]}, {"error"}
        )

    def test_json_remains_complete_and_exit_code_stays_success_for_partial_evidence(self) -> None:
        output = io.StringIO()
        with patch("driftbox.cli.discover_network", return_value=self.report):
            with redirect_stdout(output):
                exit_code = run_network_discovery(TARGET, json_output=True)

        payload = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["schema_version"], 2)
        self.assertNotIn("truncated", json.dumps(payload).lower())
        self.assertEqual(payload["summary"], self.report["summary"])
        self.assertEqual(payload["probe_outcomes"], self.report["probe_outcomes"])
        self.assertEqual(len(payload["probe_outcomes"]), 254)
        self.assertEqual(payload["probe_outcomes"][-1]["address"], "192.168.50.254")
        interpretation = payload["interpretation"]
        discovery_summary = interpretation["discovery_summary"]
        detailed_evidence = interpretation["detailed_evidence"]
        self.assertEqual(len(discovery_summary["responsive_devices"]), 64)
        self.assertEqual(len(discovery_summary["cache_only_devices"]), 64)
        self.assertEqual(len(discovery_summary["addresses_without_response"]), 160)
        self.assertEqual(len(discovery_summary["addresses_with_probe_errors"]), 30)
        self.assertEqual(discovery_summary["evidence_overlap"], {
            "probe_no_reply_count": 160,
            "no_reply_with_neighbor_cache_count": 64,
            "no_reply_with_neighbor_cache_addresses": [
                f"192.168.50.{octet}" for octet in range(65, 129)
            ],
            "counts_are_additive": False,
            "outcomes_available": True,
        })
        self.assertEqual(len(detailed_evidence["probe_outcomes"]), 254)
        self.assertEqual(len(detailed_evidence["hosts"]), 128)

    def test_human_output_is_bounded_without_misrepresenting_categories(self) -> None:
        text = format_network_discovery(with_discovery_interpretation(self.report))
        lines = text.splitlines()
        host_rows = [
            line for line in lines if line.startswith("192.168.50.")
        ]

        def line_starting(prefix: str) -> str:
            return next(line for line in lines if line.startswith(prefix))

        responsive_line = line_starting("Devices that responded during the scan:")
        cache_line = line_starting(
            "Devices supported only by neighbor/cache evidence:"
        )
        silent_summary_line = line_starting("Probes that received no reply:")
        silent_preview_line = line_starting(
            "Addresses that did not respond (terminal preview):"
        )
        error_preview_line = line_starting(
            "Addresses with unavailable or failed probes:"
        )

        self.assertIn(
            "128 host records: 0 local machine, 64 responsive, 64 cache-only.",
            text,
        )
        self.assertIn(
            "Confirmed gateway roles: 0 (none recorded); role counts may overlap "
            "host classifications.",
            text,
        )
        self.assertIn(
            "Probe outcomes (aggregated): 254 attempted; 64 replies; 128 without an observed reply; 32 timed out; 0 unavailable; 30 errors.",
            text,
        )
        self.assertEqual(silent_summary_line, "Probes that received no reply: 160.")
        self.assertNotRegex(silent_summary_line, r"192\.168\.50\.\d+")
        self.assertIn(
            "No-reply/cache overlap: 64 of the 160 addresses without a reply "
            "also have neighbor/cache evidence; these categories overlap and "
            "should not be added together.",
            text,
        )
        self.assertEqual(len(re.findall(r"192\.168\.50\.\d+", responsive_line)), 10)
        self.assertTrue(responsive_line.endswith("192.168.50.10, and 54 more"))
        self.assertEqual(len(re.findall(r"192\.168\.50\.\d+", cache_line)), 10)
        self.assertTrue(cache_line.endswith("192.168.50.74, and 54 more"))
        self.assertEqual(len(re.findall(r"192\.168\.50\.\d+", silent_preview_line)), 10)
        self.assertTrue(silent_preview_line.endswith("192.168.50.74, and 150 more"))
        self.assertEqual(len(re.findall(r"192\.168\.50\.\d+", error_preview_line)), 10)
        self.assertTrue(error_preview_line.endswith("192.168.50.234, and 20 more"))
        self.assertEqual(len(host_rows), MAX_HUMAN_HOST_ROWS)
        self.assertIn("... and 118 more host evidence rows.", text)
        self.assertIn("driftbox discover 192.168.50.0/24 --json", text)
        self.assertIn("Silence does not prove an address is unused or offline.", text)
        self.assertLessEqual(max(map(len, lines)), MAX_HUMAN_LINE_CHARS)
        self.assertLessEqual(len(text), MAX_HUMAN_OUTPUT_CHARS)


if __name__ == "__main__":
    unittest.main()
