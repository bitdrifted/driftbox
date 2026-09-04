"""Hermetic tests for listener evidence normalization and presentation groups."""

from __future__ import annotations

import unittest

from driftbox.posture_listeners import (
    DYNAMIC_PORT_MAX,
    DYNAMIC_PORT_MIN,
    MAX_LISTENERS,
    ListenerValidationError,
    build_listener_presentation,
    normalize_listener,
)


def listener(
    protocol: object = "TCP",
    address: object = "0.0.0.0",
    port: object = 8443,
    process: object = "example-service",
    scope: object = "all interfaces",
    pid: object = 321,
) -> dict[str, object]:
    return {
        "protocol": protocol,
        "address": address,
        "port": port,
        "process": process,
        "scope": scope,
        "pid": pid,
    }


class PostureListenerTests(unittest.TestCase):
    def test_dual_stack_group_preserves_raw_endpoints_and_pid(self) -> None:
        ipv4 = listener(address="0.0.0.0", pid=11)
        ipv6 = listener(address="::", pid=12)
        report = build_listener_presentation([ipv6, ipv4], platform="Linux")

        self.assertEqual(report["listener_count"], 2)
        self.assertEqual(len(report["groups"]), 1)
        group = report["groups"][0]
        self.assertEqual(group["type"], "dual-stack-wildcard-observations")
        self.assertIn("does not claim they are one socket", group["reason"])
        self.assertEqual([member["pid"] for member in group["members"]], [11, 12])
        self.assertEqual(
            [member["raw"]["address"] for member in group["members"]],
            ["0.0.0.0", "::"],
        )

    def test_dual_stack_does_not_cross_protocol_or_process(self) -> None:
        process_mismatch = build_listener_presentation([
            listener(address="0.0.0.0", process="alpha"),
            listener(address="::", process="beta"),
        ])
        protocol_mismatch = build_listener_presentation([
            listener(address="0.0.0.0", protocol="TCP"),
            listener(address="::", protocol="UDP"),
        ])
        self.assertEqual(
            [group["type"] for group in process_mismatch["groups"]],
            ["endpoint-observation", "endpoint-observation"],
        )
        self.assertEqual(
            [group["type"] for group in protocol_mismatch["groups"]],
            ["endpoint-observation", "endpoint-observation"],
        )

    def test_wildcard_and_specific_bindings_never_merge(self) -> None:
        report = build_listener_presentation([
            listener(address="0.0.0.0"),
            listener(address="198.51.100.20", scope="public address"),
        ])
        self.assertEqual(len(report["groups"]), 2)
        self.assertTrue(all(group["type"] == "endpoint-observation" for group in report["groups"]))

    def test_pid_does_not_change_endpoint_group_id(self) -> None:
        first = build_listener_presentation([listener(pid=41)])
        second = build_listener_presentation([listener(pid=999)])
        self.assertEqual(first["groups"][0]["id"], second["groups"][0]["id"])
        self.assertEqual(second["groups"][0]["members"][0]["raw"]["pid"], 999)

    def test_windows_dynamic_rpc_group_is_windows_only(self) -> None:
        evidence = [
            listener(port=DYNAMIC_PORT_MIN, pid=70),
            listener(port=DYNAMIC_PORT_MIN + 1, pid=71),
        ]
        windows = build_listener_presentation(evidence, platform="Windows")
        self.assertEqual(windows["platform"], "windows")
        self.assertEqual(windows["groups"][0]["type"], "windows-dynamic-rpc-compatible")
        self.assertIn("do not prove every port is RPC", windows["groups"][0]["reason"])
        self.assertEqual(len(windows["groups"][0]["members"]), 2)

        for platform in ("Linux", "macOS", "unknown"):
            with self.subTest(platform=platform):
                report = build_listener_presentation(evidence, platform=platform)
                self.assertTrue(
                    all(group["type"] != "windows-dynamic-rpc-compatible" for group in report["groups"])
                )
                self.assertEqual(len(report["groups"]), 2)

    def test_dynamic_udp_groups_only_repeated_high_wildcards(self) -> None:
        report = build_listener_presentation([
            listener(protocol="UDP", port=DYNAMIC_PORT_MIN, pid=30),
            listener(protocol="UDP", port=DYNAMIC_PORT_MIN + 2, pid=31),
            listener(
                protocol="UDP",
                address="203.0.113.70",
                scope="public address",
                port=DYNAMIC_PORT_MIN + 3,
                pid=32,
            ),
        ], platform="macOS")
        group_types = [group["type"] for group in report["groups"]]
        self.assertIn("dynamic-udp-wildcard-observations", group_types)
        udp_group = next(group for group in report["groups"] if group["type"] == "dynamic-udp-wildcard-observations")
        self.assertEqual(len(udp_group["members"]), 2)
        self.assertIn("dynamic UDP observations", udp_group["reason"])
        self.assertNotIn("malicious", udp_group["reason"].casefold())
        self.assertNotIn("vulnerable", udp_group["reason"].casefold())
        self.assertNotIn("safe", udp_group["reason"].casefold())

    def test_unknown_processes_remain_visible(self) -> None:
        report = build_listener_presentation([
            listener(protocol="UDP", port=DYNAMIC_PORT_MIN, process="unavailable", pid=None),
            listener(protocol="UDP", port=DYNAMIC_PORT_MIN + 1, process="unavailable", pid=None),
        ])
        members = report["groups"][0]["members"]
        self.assertEqual(report["groups"][0]["type"], "dynamic-udp-wildcard-observations")
        self.assertEqual([member["process"] for member in members], ["unavailable", "unavailable"])
        self.assertEqual([member["pid"] for member in members], [None, None])

    def test_ordering_is_deterministic_for_groups_and_members(self) -> None:
        evidence = [
            listener(address="::", port=9000, process="agent", pid=5),
            listener(address="0.0.0.0", port=9000, process="agent", pid=4),
            listener(address="0.0.0.0", port=8000, process="other", pid=3),
        ]
        forward = build_listener_presentation(evidence, platform="linux")
        backward = build_listener_presentation(list(reversed(evidence)), platform="linux")
        self.assertEqual(forward, backward)

    def test_normalization_sanitizes_controls_unicode_and_ip(self) -> None:
        normalized = normalize_listener(listener(
            protocol="\x1b[31mTCP\x1b[0m",
            address="2001:0DB8:0:0:0:0:0:1",
            process="  caf\u00e9\x00-service  ",
            scope="public address",
        ))
        self.assertEqual(normalized["protocol"], "tcp")
        self.assertEqual(normalized["address"], "2001:db8::1")
        self.assertEqual(normalized["process"], "caf\u00e9-service")
        self.assertEqual(normalized["normalized_process"], "caf\u00e9-service")
        self.assertEqual(normalized["raw"]["protocol"], "TCP")

    def test_rejects_malformed_ambiguous_and_out_of_bounds_evidence(self) -> None:
        invalid = [
            listener(protocol="SCTP"),
            listener(address="not-an-address"),
            listener(address="0.0.0.0", scope="public address"),
            listener(port=0),
            listener(port=DYNAMIC_PORT_MAX + 1),
            listener(pid=True),
            {"protocol": "TCP"},
            {**listener(), "surprise": "field"},
        ]
        for item in invalid:
            with self.subTest(item=item):
                with self.assertRaises(ListenerValidationError):
                    normalize_listener(item)
        with self.assertRaises(ListenerValidationError):
            build_listener_presentation([listener()] * (MAX_LISTENERS + 1))
        with self.assertRaises(ListenerValidationError):
            build_listener_presentation([listener()], platform="FreeBSD")


if __name__ == "__main__":
    unittest.main()
