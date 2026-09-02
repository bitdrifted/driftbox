"""Tests for the Driftbox command-line interface."""

import io
import json
import socket
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch
from types import SimpleNamespace

from driftbox.cli import (
    build_report,
    collect_network_addresses,
    environment_name,
    running_in_wsl,
    show_report,
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