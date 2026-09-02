"""Tests for the Driftbox command-line interface."""

import io
import json
import socket
import unittest
import psutil
from contextlib import redirect_stdout
from unittest.mock import patch
from types import SimpleNamespace

from driftbox.cli import (
    build_report,
    collect_network_addresses,
    collect_listening_ports,
    environment_name,
    running_in_wsl,
    show_report,
    classify_address_scope,
)


class EnvironmentTests(unittest.TestCase):
    """Test execution-environment detection."""

    @patch.dict("os.environ", {"WSL_DISTRO_NAME": "kali-linux"}, clear=True)
    def test_running_in_wsl_from_environment(self) -> None:
        self.assertTrue(running_in_wsl())

    @patch("driftbox.cli.running_in_wsl", return_value=True)
    @patch.dict("os.environ", {"WSL_DISTRO_NAME": "kali-linux"}, clear=True)
    def test_wsl_environment_name(self, _: object) -> None:
        self.assertEqual(environment_name(), "WSL (kali-linux)")

    @patch("driftbox.cli.running_in_wsl", return_value=False)
    @patch.dict("os.environ", {"WT_SESSION": "test-session"}, clear=True)
    def test_windows_terminal_environment_name(self, _: object) -> None:
        self.assertEqual(environment_name(), "Windows Terminal")


class NetworkTests(unittest.TestCase):
    """Test local network-address collection."""

    @patch("driftbox.cli.psutil.net_if_addrs")
    def test_collects_addresses_and_removes_loopback(self, net_if_addrs: object) -> None:
        net_if_addrs.return_value = {
            "loopback": [
                SimpleNamespace(
                    family=socket.AF_INET,
                    address="127.0.0.1",
                ),
            ],
            "ethernet": [
                SimpleNamespace(
                    family=socket.AF_INET,
                    address="192.168.0.10",
                ),
                SimpleNamespace(
                    family=socket.AF_INET6,
                    address="fe80::1%12",
                ),
            ],
        }

        ipv4_addresses, ipv6_addresses = collect_network_addresses()

        self.assertEqual(ipv4_addresses, ["192.168.0.10"])
        self.assertEqual(ipv6_addresses, ["fe80::1"])

    @patch(
        "driftbox.cli.psutil.net_if_addrs",
        side_effect=OSError,
    )
    def test_handles_interface_lookup_failure(self, _: object) -> None:
        self.assertEqual(collect_network_addresses(), ([], []))
class PortTests(unittest.TestCase):
    """Test listening-port collection."""

    def test_classifies_common_address_scopes(self) -> None:
        self.assertEqual(classify_address_scope("0.0.0.0"), "all interfaces")
        self.assertEqual(classify_address_scope("::"), "all interfaces")
        self.assertEqual(classify_address_scope("127.0.0.1"), "local only")
        self.assertEqual(classify_address_scope("192.168.1.10"), "private network")
        self.assertEqual(classify_address_scope("fe80::1%12"), "link local")
        self.assertEqual(classify_address_scope("8.8.8.8"), "public address")

    @patch("driftbox.cli.psutil.Process")
    @patch("driftbox.cli.psutil.net_connections")
    def test_collects_tcp_listeners_and_udp_ports(
        self,
        net_connections: object,
        process: object,
    ) -> None:
        net_connections.return_value = [
            SimpleNamespace(
                type=socket.SOCK_STREAM,
                status=psutil.CONN_LISTEN,
                laddr=SimpleNamespace(ip="0.0.0.0", port=8080),
                pid=42,
            ),
            SimpleNamespace(
                type=socket.SOCK_STREAM,
                status=psutil.CONN_ESTABLISHED,
                laddr=SimpleNamespace(ip="192.168.0.10", port=50000),
                pid=42,
            ),
            SimpleNamespace(
                type=socket.SOCK_DGRAM,
                status=psutil.CONN_NONE,
                laddr=SimpleNamespace(ip="0.0.0.0", port=53),
                pid=None,
            ),
        ]
        process.return_value.name.return_value = "test-server"

        ports = collect_listening_ports()

        self.assertEqual(
            ports,
            [
                {
                    "protocol": "UDP",
                    "address": "0.0.0.0",
                    "scope": "all interfaces",
                    "port": 53,
                    "pid": None,
                    "process": "unavailable",
                },
                {
                    "protocol": "TCP",
                    "address": "0.0.0.0",
                    "scope": "all interfaces",
                    "port": 8080,
                    "pid": 42,
                    "process": "test-server",
                },
            ],
        )

    @patch(
        "driftbox.cli.psutil.net_connections",
        side_effect=psutil.AccessDenied,
    )
    def test_handles_connection_lookup_failure(self, _: object) -> None:
        self.assertEqual(collect_listening_ports(), [])

class ReportTests(unittest.TestCase):
    """Test portable report generation and serialization."""

    @patch(
        "driftbox.cli.collect_network_info",
        return_value={"ipv4_addresses": ["192.168.0.10"]},
    )
    @patch(
        "driftbox.cli.collect_system_info",
        return_value={"operating_system": "TestOS"},
    )
    def test_build_report_contains_expected_sections(
        self,
        _: object,
        __: object,
    ) -> None:
        report = build_report()

        self.assertEqual(report["schema_version"], 1)
        self.assertIn("driftbox_version", report)
        self.assertIn("generated_at", report)
        self.assertEqual(report["system"], {"operating_system": "TestOS"})
        self.assertEqual(
            report["network"],
            {"ipv4_addresses": ["192.168.0.10"]},
        )

    @patch(
        "driftbox.cli.build_report",
        return_value={"schema_version": 1, "status": "ok"},
    )
    def test_show_report_emits_valid_json(self, _: object) -> None:
        output = io.StringIO()

        with redirect_stdout(output):
            show_report()

        self.assertEqual(
            json.loads(output.getvalue()),
            {"schema_version": 1, "status": "ok"},
        )


if __name__ == "__main__":
    unittest.main()