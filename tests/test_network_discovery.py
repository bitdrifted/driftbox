"""Hermetic safety and behavior tests for authorized network discovery."""

from __future__ import annotations

from concurrent.futures import Future
import ipaddress
import socket
import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from driftbox.network_discovery import (
    CandidateSelectionRequired,
    DiscoveryOperationalError,
    MAX_TARGET_ADDRESSES,
    MAX_TIMEOUT_SECONDS,
    MAX_WORKERS,
    MIN_TIMEOUT_SECONDS,
    MIN_WORKERS,
    NeighborRecord,
    NeighborSnapshot,
    NetworkCandidate,
    NoSuitableNetworkError,
    ProbeResult,
    SystemNetworkAdapter,
    TargetValidationError,
    clamp_timeout,
    clamp_workers,
    collect_local_ipv4_addresses,
    detect_local_network_candidates,
    discover_network,
    parse_arp_output,
    parse_ip_neighbor_output,
    resolve_target,
    validate_target,
)


def interface_record(
    address: str,
    netmask: str,
    family: int = socket.AF_INET,
) -> SimpleNamespace:
    return SimpleNamespace(family=family, address=address, netmask=netmask)


def candidate(
    cidr: str,
    interface: str = "ethernet",
    local: str = "192.168.1.10",
) -> NetworkCandidate:
    return NetworkCandidate(
        ipaddress.IPv4Network(cidr),
        (interface,),
        (ipaddress.IPv4Address(local),),
    )


class FakeAdapter:
    """An adapter that records calls and never touches the host network."""

    def __init__(
        self,
        outcomes: dict[str, ProbeResult] | None = None,
        neighbors: NeighborSnapshot | None = None,
    ) -> None:
        self.outcomes = outcomes or {}
        self.snapshot = neighbors or NeighborSnapshot("available")
        self.ping_calls: list[tuple[str, float]] = []
        self.neighbor_calls: list[float] = []

    def ping(
        self,
        address: ipaddress.IPv4Address,
        timeout_seconds: float,
    ) -> ProbeResult:
        self.ping_calls.append((str(address), timeout_seconds))
        return self.outcomes.get(str(address), ProbeResult("no_response"))

    def neighbors(self, timeout_seconds: float) -> NeighborSnapshot:
        self.neighbor_calls.append(timeout_seconds)
        return self.snapshot


class TargetValidationTests(unittest.TestCase):
    """The target allowlist must prevent expansion beyond authorization."""

    def test_accepts_canonical_allowed_ipv4_cidrs(self) -> None:
        for target in (
            "10.2.3.0/24",
            "172.31.255.0/24",
            "192.168.4.0/24",
            "169.254.8.0/24",
            "127.0.0.1/32",
        ):
            with self.subTest(target=target):
                self.assertEqual(str(validate_target(target)), target)

    def test_rejects_malformed_noncanonical_bare_and_hostname_targets(self) -> None:
        invalid = (
            "",
            " ",
            "192.168.1.1",
            "192.168.1.5/24",
            " 192.168.1.0/24",
            "192.168.1.0/24 ",
            "192.168.001.0/24",
            "router.local/24",
            "example.com",
            "example.com/24",
            "8.8.8.8; whoami/32",
        )
        for target in invalid:
            with self.subTest(target=target):
                with self.assertRaises(TargetValidationError):
                    validate_target(target)

    @patch("driftbox.network_discovery.socket.getaddrinfo")
    @patch("driftbox.network_discovery.socket.gethostbyname")
    def test_hostname_rejection_never_attempts_dns(
        self,
        gethostbyname: Mock,
        getaddrinfo: Mock,
    ) -> None:
        with self.assertRaises(TargetValidationError):
            validate_target("example.com/24")
        gethostbyname.assert_not_called()
        getaddrinfo.assert_not_called()

    def test_rejects_public_reserved_cgnat_and_mixed_ranges(self) -> None:
        invalid = (
            "8.8.8.0/24",
            "100.64.0.0/24",
            "192.0.2.0/24",
            "224.0.0.0/24",
            "0.0.0.0/24",
            "172.0.0.0/8",
            "192.168.0.0/15",
            "126.0.0.0/7",
        )
        for target in invalid:
            with self.subTest(target=target):
                with self.assertRaises(TargetValidationError):
                    validate_target(target)

    def test_rejects_ipv6_without_resolving_it(self) -> None:
        for target in ("::1/128", "fd00::/120", "fe80::/120"):
            with self.subTest(target=target):
                with self.assertRaisesRegex(TargetValidationError, "IPv6"):
                    validate_target(target)

    def test_allows_at_most_256_total_addresses(self) -> None:
        network = validate_target("192.168.9.0/24")
        self.assertEqual(network.num_addresses, MAX_TARGET_ADDRESSES)
        with self.assertRaisesRegex(TargetValidationError, "maximum"):
            validate_target("192.168.8.0/23")

    def test_timeout_is_finite_numeric_and_clamped_to_safe_bounds(self) -> None:
        self.assertEqual(clamp_timeout(-10), MIN_TIMEOUT_SECONDS)
        self.assertEqual(clamp_timeout(0.5), 0.5)
        self.assertEqual(clamp_timeout(99), MAX_TIMEOUT_SECONDS)
        for value in (True, None, "nope", float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value):
                with self.assertRaises(TargetValidationError):
                    clamp_timeout(value)  # type: ignore[arg-type]

    def test_workers_are_integral_and_clamped_to_safe_bounds(self) -> None:
        self.assertEqual(clamp_workers(-100), MIN_WORKERS)
        self.assertEqual(clamp_workers(4), 4)
        self.assertEqual(clamp_workers(10000), MAX_WORKERS)
        for value in (True, None, "4", "1.5", 1.5):
            with self.subTest(value=value):
                with self.assertRaises(TargetValidationError):
                    clamp_workers(value)  # type: ignore[arg-type]


class LocalCandidateTests(unittest.TestCase):
    """Local target selection must be deterministic and conservative."""

    def test_candidates_require_active_ipv4_private_bounded_interfaces(self) -> None:
        addresses = {
            "down": [interface_record("192.168.2.10", "255.255.255.0")],
            "public": [interface_record("203.0.113.9", "255.255.255.0")],
            "huge": [interface_record("10.2.3.4", "255.0.0.0")],
            "loopback": [interface_record("127.0.0.1", "255.0.0.0")],
            "ipv6": [interface_record("fe80::1", "ffff:ffff:ffff:ffff::", socket.AF_INET6)],
            "bad": [interface_record("not-an-ip", "255.255.255.0")],
            "good": [interface_record("192.168.1.10", "255.255.255.0")],
        }
        stats = {
            name: SimpleNamespace(isup=name != "down")
            for name in addresses
        }

        result = detect_local_network_candidates(
            addresses_provider=lambda: addresses,
            stats_provider=lambda: stats,
        )

        self.assertEqual([item.as_dict() for item in result], [{
            "cidr": "192.168.1.0/24",
            "interfaces": ["good"],
            "local_addresses": ["192.168.1.10"],
        }])

    def test_duplicate_candidates_merge_and_sort_deterministically(self) -> None:
        addresses = {
            "zeta": [interface_record("192.168.2.20", "255.255.255.0")],
            "bravo": [interface_record("10.0.0.20", "255.255.255.0")],
            "alpha": [
                interface_record("192.168.2.10", "255.255.255.0"),
                interface_record("192.168.2.10", "255.255.255.0"),
            ],
        }
        stats = {name: SimpleNamespace(isup=True) for name in addresses}

        result = detect_local_network_candidates(
            addresses_provider=lambda: addresses,
            stats_provider=lambda: stats,
        )

        self.assertEqual([str(item.network) for item in result], [
            "10.0.0.0/24",
            "192.168.2.0/24",
        ])
        self.assertEqual(result[1].interfaces, ("alpha", "zeta"))
        self.assertEqual(
            tuple(map(str, result[1].local_addresses)),
            ("192.168.2.10", "192.168.2.20"),
        )

    def test_interface_provider_failure_is_an_operational_error(self) -> None:
        with self.assertRaises(DiscoveryOperationalError):
            detect_local_network_candidates(
                addresses_provider=Mock(side_effect=OSError("denied")),
                stats_provider=lambda: {},
            )

    def test_local_address_collection_filters_public_ipv6_and_malformed_data(self) -> None:
        addresses = {
            "any": [
                interface_record("192.168.1.4", "255.255.255.0"),
                interface_record("8.8.8.8", "255.255.255.0"),
                interface_record("bad", "255.255.255.0"),
                interface_record("::1", "ffff:ffff::", socket.AF_INET6),
            ]
        }
        self.assertEqual(
            collect_local_ipv4_addresses(addresses_provider=lambda: addresses),
            {ipaddress.IPv4Address("192.168.1.4")},
        )
        self.assertEqual(
            collect_local_ipv4_addresses(
                addresses_provider=Mock(side_effect=OSError("denied"))
            ),
            set(),
        )

    def test_target_resolution_handles_zero_one_and_multiple_candidates(self) -> None:
        with self.assertRaises(NoSuitableNetworkError):
            resolve_target(None, candidates=[])
        self.assertEqual(
            str(resolve_target(None, candidates=[candidate("192.168.1.0/24")])),
            "192.168.1.0/24",
        )
        choices = [
            candidate("192.168.2.0/24", local="192.168.2.2"),
            candidate("10.0.0.0/24", local="10.0.0.2"),
        ]
        with self.assertRaises(CandidateSelectionRequired) as raised:
            resolve_target(None, candidates=choices)
        self.assertEqual(raised.exception.candidates, tuple(choices))

    @patch("driftbox.network_discovery.detect_local_network_candidates")
    def test_explicit_target_never_inspects_local_candidates(self, detect: Mock) -> None:
        self.assertEqual(str(resolve_target("10.0.0.0/24")), "10.0.0.0/24")
        detect.assert_not_called()


class NeighborParsingTests(unittest.TestCase):
    """Only strict, private IPv4 cache entries may become evidence."""

    def test_linux_neighbor_parser_normalizes_deduplicates_and_sorts(self) -> None:
        output = "\n".join((
            "192.168.1.20 dev eth0 lladdr AA-BB-CC-DD-EE-20 STALE",
            "192.168.1.2 dev eth0 lladdr aa:bb:cc:dd:ee:02 REACHABLE",
            "192.168.1.2 dev eth0 lladdr aa:bb:cc:dd:ee:02 REACHABLE",
        ))
        result = parse_ip_neighbor_output(output)
        self.assertEqual([str(item.address) for item in result], [
            "192.168.1.2",
            "192.168.1.20",
        ])
        self.assertEqual(result[0].mac_address, "aa:bb:cc:dd:ee:02")
        self.assertEqual(result[0].state, "reachable")

    def test_linux_parser_ignores_ipv6_public_and_malformed_or_localized_lines(self) -> None:
        output = "\n".join((
            "fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:01 REACHABLE",
            "8.8.8.8 dev eth0 lladdr aa:bb:cc:dd:ee:08 REACHABLE",
            "192.168.1.4 arbitrary localized prose",
            "192.168.1.5 dev eth0 lladdr not-a-mac REACHABLE",
            "192.168.1.6 dev eth0 lladdr aa:bb:cc:dd:ee:06 GARBAGE",
            "not-an-address dev eth0 lladdr aa:bb:cc:dd:ee:01 STALE",
        ))
        self.assertEqual(parse_ip_neighbor_output(output), [])

    def test_windows_and_macos_arp_entries_are_parsed_strictly(self) -> None:
        output = "\n".join((
            "Interface: 192.168.1.10 --- 0xb",
            "  192.168.1.2          aa-bb-cc-dd-ee-02     dynamic",
            "? (192.168.1.3) at aa:bb:cc:dd:ee:03 on en0 ifscope [ethernet]",
            "? (192.168.1.4) at aa:bb:cc:dd:ee:04 on en0 permanent [ethernet]",
            "  8.8.8.8              aa-bb-cc-dd-ee-08     dynamic",
            "  fe80::1               aa-bb-cc-dd-ee-09     dynamic",
        ))
        result = parse_arp_output(output)
        self.assertEqual([str(item.address) for item in result], [
            "192.168.1.2",
            "192.168.1.3",
            "192.168.1.4",
        ])
        self.assertEqual([item.state for item in result], ["dynamic", None, "static"])

    def test_arp_parser_ignores_headers_and_unstructured_or_malformed_lines(self) -> None:
        output = "\n".join((
            "Interface: 192.168.1.10 --- 0xb",
            "Internet Address      Physical Address      Type",
            "192.168.1.20 is mentioned in localized prose",
            "192.168.1.21 not-a-mac dynamic",
            "? (192.168.1.22) at (incomplete) on en0 ifscope [ethernet]",
        ))
        self.assertEqual(parse_arp_output(output), [])


class SystemAdapterTests(unittest.TestCase):
    """Platform commands must be fixed argv with Python-enforced deadlines."""

    def test_linux_ping_uses_exact_argv_shell_false_and_positive_exit_evidence(self) -> None:
        runner = Mock(return_value=subprocess.CompletedProcess(
            [], 0, "64 bytes from 192.168.1.2: icmp_seq=1 ttl=64", ""
        ))
        adapter = SystemNetworkAdapter(system_name="Linux", runner=runner)

        result = adapter.ping(ipaddress.IPv4Address("192.168.1.2"), 0.4)

        self.assertEqual(result.status, "responsive")
        runner.assert_called_once_with(
            ["ping", "-n", "-c", "1", "192.168.1.2"],
            capture_output=True,
            text=True,
            timeout=0.4,
            check=False,
            shell=False,
        )

    def test_windows_ping_uses_millisecond_timeout_and_exact_target_token(self) -> None:
        runner = Mock(return_value=subprocess.CompletedProcess([], 1, "", "timeout"))
        adapter = SystemNetworkAdapter(system_name="Windows", runner=runner)

        result = adapter.ping(ipaddress.IPv4Address("10.0.0.2"), 0.25)

        self.assertEqual(result.status, "no_response")
        self.assertEqual(runner.call_args.args[0], [
            "ping", "-n", "1", "-w", "250", "10.0.0.2",
        ])
        self.assertIs(runner.call_args.kwargs["shell"], False)

    def test_success_exit_without_exact_target_evidence_is_not_responsive(self) -> None:
        for output in ("", "reply", "reply from 192.168.1.20"):
            with self.subTest(output=output):
                runner = Mock(
                    return_value=subprocess.CompletedProcess([], 0, output, "")
                )
                result = SystemNetworkAdapter(
                    system_name="Linux", runner=runner
                ).ping(ipaddress.IPv4Address("192.168.1.2"), 0.2)
                self.assertEqual(result.status, "error")

    def test_probe_rejects_injection_hostname_ipv6_and_public_without_a_command(self) -> None:
        runner = Mock()
        adapter = SystemNetworkAdapter(system_name="Linux", runner=runner)
        for address in (
            "192.168.1.2;whoami",
            "router.local",
            "::1",
            "8.8.8.8",
            " 192.168.1.2",
        ):
            with self.subTest(address=address):
                with self.assertRaises(TargetValidationError):
                    adapter.ping(address, 0.5)  # type: ignore[arg-type]
        runner.assert_not_called()

    def test_ping_reports_unavailable_timeout_error_and_silent_without_claiming_absence(self) -> None:
        cases = (
            (FileNotFoundError(), "unavailable"),
            (subprocess.TimeoutExpired(["ping"], 0.2), "timeout"),
            (OSError("failure"), "error"),
        )
        for error, status in cases:
            with self.subTest(status=status):
                adapter = SystemNetworkAdapter(
                    system_name="Darwin", runner=Mock(side_effect=error)
                )
                result = adapter.ping(ipaddress.IPv4Address("169.254.1.2"), 0.2)
                self.assertEqual(result.status, status)
        self.assertIn("without an observed reply", ProbeResult(
            "no_response", "The probe completed without an observed reply."
        ).detail or "")

    def test_linux_neighbor_command_falls_back_to_arp_if_ip_is_unavailable(self) -> None:
        runner = Mock(side_effect=(
            FileNotFoundError(),
            subprocess.CompletedProcess(
                [], 0, "? (192.168.1.2) at aa:bb:cc:dd:ee:02 on eth0", ""
            ),
        ))
        snapshot = SystemNetworkAdapter(system_name="Linux", runner=runner).neighbors(0.3)
        self.assertEqual(snapshot.status, "available")
        self.assertEqual(str(snapshot.records[0].address), "192.168.1.2")
        self.assertEqual([call.args[0] for call in runner.call_args_list], [
            ["ip", "neighbor", "show"],
            ["arp", "-an"],
        ])
        for call in runner.call_args_list:
            self.assertIs(call.kwargs["shell"], False)

    def test_macos_neighbor_command_uses_fixed_argv(self) -> None:
        runner = Mock(return_value=subprocess.CompletedProcess([], 0, "", ""))
        snapshot = SystemNetworkAdapter(system_name="Darwin", runner=runner).neighbors(0.3)
        self.assertEqual(snapshot.status, "available")
        runner.assert_called_once_with(
            ["arp", "-an"],
            capture_output=True,
            text=True,
            timeout=0.3,
            check=False,
            shell=False,
        )

    def test_neighbor_commands_report_unavailable_timeout_and_failure(self) -> None:
        missing = SystemNetworkAdapter(
            system_name="Windows", runner=Mock(side_effect=FileNotFoundError())
        ).neighbors(0.2)
        timed_out = SystemNetworkAdapter(
            system_name="Windows",
            runner=Mock(side_effect=subprocess.TimeoutExpired(["arp"], 0.2)),
        ).neighbors(0.2)
        failed = SystemNetworkAdapter(
            system_name="Windows",
            runner=Mock(return_value=subprocess.CompletedProcess([], 1, "", "denied")),
        ).neighbors(0.2)
        self.assertEqual((missing.status, timed_out.status, failed.status), (
            "unavailable", "timeout", "unavailable",
        ))

    def test_unsupported_platform_does_not_guess_a_system_command(self) -> None:
        runner = Mock()
        snapshot = SystemNetworkAdapter(
            system_name="Plan9", runner=runner
        ).neighbors(0.2)
        self.assertEqual(snapshot.status, "unavailable")
        runner.assert_not_called()


class DiscoveryOrchestrationTests(unittest.TestCase):
    """Discovery reports only positive evidence and remains deterministic."""

    def test_excludes_network_and_broadcast_and_counts_each_probe_outcome(self) -> None:
        adapter = FakeAdapter({
            "192.168.1.1": ProbeResult("responsive"),
            "192.168.1.2": ProbeResult("timeout"),
            "192.168.1.3": ProbeResult("unavailable"),
            "192.168.1.4": ProbeResult("error"),
            "192.168.1.5": ProbeResult("no_response"),
        })
        report = discover_network(
            "192.168.1.0/29",
            adapter=adapter,
            local_addresses=[],
            timeout_seconds=0.2,
            generated_at="2026-09-03T00:00:00+00:00",
        )
        self.assertEqual([call[0] for call in adapter.ping_calls], [
            "192.168.1.1", "192.168.1.2", "192.168.1.3",
            "192.168.1.4", "192.168.1.5", "192.168.1.6",
        ])
        self.assertNotIn("192.168.1.0", str(adapter.ping_calls))
        self.assertNotIn("192.168.1.7", str(adapter.ping_calls))
        self.assertEqual(report["summary"], {
            "local_machine": 0,
            "confirmed_responsive": 1,
            "known_neighbor": 0,
            "addresses_probed": 6,
            "responses_received": 1,
            "no_response_observed": 2,
            "probe_timeouts": 1,
            "probe_unavailable": 1,
            "probe_errors": 1,
        })
        self.assertEqual([host["address"] for host in report["hosts"]], ["192.168.1.1"])

    def test_slash_31_and_32_treat_all_addresses_as_hosts(self) -> None:
        for cidr, expected in (
            ("10.0.0.0/31", ["10.0.0.0", "10.0.0.1"]),
            ("127.0.0.1/32", ["127.0.0.1"]),
        ):
            with self.subTest(cidr=cidr):
                adapter = FakeAdapter()
                discover_network(cidr, adapter=adapter, local_addresses=[])
                self.assertEqual([item[0] for item in adapter.ping_calls], expected)

    def test_classifies_local_confirmed_and_cache_only_with_exact_evidence(self) -> None:
        neighbors = NeighborSnapshot("available", records=(
            NeighborRecord(
                ipaddress.IPv4Address("10.0.0.1"),
                "arp_cache",
                "aa:bb:cc:dd:ee:01",
                "dynamic",
            ),
            NeighborRecord(
                ipaddress.IPv4Address("10.0.0.2"),
                "ip_neighbor_cache",
                "aa:bb:cc:dd:ee:02",
                "stale",
            ),
            NeighborRecord(
                ipaddress.IPv4Address("10.0.0.3"),
                "arp_cache",
            ),
        ))
        adapter = FakeAdapter(
            {"10.0.0.2": ProbeResult("responsive")}, neighbors
        )
        report = discover_network(
            "10.0.0.0/29",
            adapter=adapter,
            local_addresses=["10.0.0.1"],
            generated_at="fixed",
        )

        self.assertEqual([host["status"] for host in report["hosts"]], [
            "local_machine", "confirmed_responsive", "known_neighbor",
        ])
        self.assertEqual(report["hosts"][0]["evidence"][0], {
            "kind": "local_interface_address",
            "source": "psutil_interface_data",
        })
        self.assertEqual(report["hosts"][1]["evidence"][0], {
            "kind": "icmp_echo_reply",
            "source": "system_ping",
        })
        self.assertEqual(report["hosts"][2]["evidence"], [{
            "kind": "neighbor_cache",
            "source": "arp_cache",
        }])
        self.assertNotIn("10.0.0.1", [call[0] for call in adapter.ping_calls])

    def test_silent_host_is_not_reported_absent_and_hostname_is_optional_metadata(self) -> None:
        report = discover_network(
            "192.168.1.1/32",
            adapter=FakeAdapter({"192.168.1.1": ProbeResult("no_response")}),
            local_addresses=[],
            generated_at="fixed",
        )
        self.assertEqual(report["hosts"], [])
        self.assertEqual(report["summary"]["no_response_observed"], 1)
        self.assertTrue(any("may still have a host" in item for item in report["limitations"]))

        responsive = discover_network(
            "192.168.1.1/32",
            adapter=FakeAdapter({"192.168.1.1": ProbeResult("responsive")}),
            local_addresses=[],
            generated_at="fixed",
        )
        self.assertEqual(responsive["hosts"][0]["metadata"]["hostname"], {
            "value": None,
            "status": "not_collected",
            "reason": "Reverse DNS is intentionally disabled.",
        })

    def test_filters_out_of_target_ipv6_and_public_neighbor_records(self) -> None:
        snapshot = NeighborSnapshot("available", records=(
            NeighborRecord(ipaddress.IPv4Address("192.168.2.2"), "arp_cache"),
            NeighborRecord(ipaddress.IPv4Address("8.8.8.8"), "arp_cache"),
        ))
        report = discover_network(
            "192.168.1.0/30",
            adapter=FakeAdapter(neighbors=snapshot),
            local_addresses=["::1", "8.8.8.8"],
            generated_at="fixed",
        )
        self.assertEqual(report["hosts"], [])

    def test_duplicate_neighbors_do_not_duplicate_hosts_or_evidence(self) -> None:
        record = NeighborRecord(
            ipaddress.IPv4Address("192.168.1.2"),
            "arp_cache",
            "aa:bb:cc:dd:ee:02",
            "dynamic",
        )
        report = discover_network(
            "192.168.1.0/30",
            adapter=FakeAdapter(neighbors=NeighborSnapshot(
                "available", records=(record, record)
            )),
            local_addresses=[],
            generated_at="fixed",
        )
        self.assertEqual(len(report["hosts"]), 1)
        self.assertEqual(len(report["hosts"][0]["evidence"]), 1)

    def test_output_is_schema_versioned_and_numerically_ordered(self) -> None:
        outcomes = {
            "192.168.1.10": ProbeResult("responsive"),
            "192.168.1.2": ProbeResult("responsive"),
        }
        report = discover_network(
            "192.168.1.0/28",
            adapter=FakeAdapter(outcomes),
            local_addresses=[],
            generated_at="2026-09-03T12:00:00+00:00",
        )
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["generated_at"], "2026-09-03T12:00:00+00:00")
        self.assertEqual([host["address"] for host in report["hosts"]], [
            "192.168.1.2", "192.168.1.10",
        ])
        self.assertEqual(report["target"]["address_count"], 16)

    def test_workers_are_capped_at_executor_boundary(self) -> None:
        created_with: list[int] = []

        class InlineExecutor:
            def __init__(self, max_workers: int) -> None:
                created_with.append(max_workers)

            def __enter__(self) -> "InlineExecutor":
                return self

            def __exit__(self, *_: object) -> None:
                return None

            def submit(self, function: object, *args: object) -> Future[ProbeResult]:
                future: Future[ProbeResult] = Future()
                future.set_result(function(*args))  # type: ignore[operator]
                return future

        with patch("driftbox.network_discovery.ThreadPoolExecutor", InlineExecutor):
            report = discover_network(
                "10.0.0.0/30",
                adapter=FakeAdapter(),
                local_addresses=[],
                workers=10_000,
            )
        self.assertEqual(created_with, [MAX_WORKERS])
        self.assertEqual(report["settings"]["workers"], MAX_WORKERS)

    def test_adapter_exceptions_become_errors_without_aborting(self) -> None:
        class BrokenAdapter(FakeAdapter):
            def ping(self, address: ipaddress.IPv4Address, timeout_seconds: float) -> ProbeResult:
                raise RuntimeError("adapter defect")

            def neighbors(self, timeout_seconds: float) -> NeighborSnapshot:
                raise RuntimeError("adapter defect")

        report = discover_network(
            "10.0.0.1/32",
            adapter=BrokenAdapter(),
            local_addresses=[],
            generated_at="fixed",
        )
        self.assertEqual(report["summary"]["probe_errors"], 1)
        self.assertEqual(report["neighbor_cache"]["status"], "error")
        self.assertEqual(report["hosts"], [])

    def test_all_failed_sources_are_unavailable_not_partial(self) -> None:
        class FailedAdapter(FakeAdapter):
            def ping(
                self,
                address: ipaddress.IPv4Address,
                timeout_seconds: float,
            ) -> ProbeResult:
                status = "error" if int(address) % 2 else "unavailable"
                return ProbeResult(status)

        report = discover_network(
            "10.0.0.0/30",
            adapter=FailedAdapter(neighbors=NeighborSnapshot("unavailable")),
            local_addresses=[],
            generated_at="fixed",
        )
        self.assertEqual(report["collection_status"], "unavailable")
        self.assertEqual(report["sources"]["reachability"]["status"], "error")
        self.assertEqual(report["target"]["address_count"], 4)
        self.assertEqual(report["target"]["host_address_count"], 2)
        self.assertEqual(report["target"]["probe_address_count"], 2)


if __name__ == "__main__":
    unittest.main()
