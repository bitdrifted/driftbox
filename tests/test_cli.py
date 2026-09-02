"""Tests for the Driftbox command-line interface."""

import socket
import unittest
from unittest.mock import patch

from driftbox.cli import (
    collect_network_addresses,
    environment_name,
    running_in_wsl,
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

    @patch("driftbox.cli.socket.getaddrinfo")
    def test_collects_addresses_and_removes_loopback(self, getaddrinfo: object) -> None:
        getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.0.10", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("fe80::1%12", 0, 0, 12)),
        ]

        ipv4_addresses, ipv6_addresses = collect_network_addresses()

        self.assertEqual(ipv4_addresses, ["192.168.0.10"])
        self.assertEqual(ipv6_addresses, ["fe80::1"])

    @patch(
        "driftbox.cli.socket.getaddrinfo",
        side_effect=socket.gaierror,
    )
    def test_handles_address_lookup_failure(self, _: object) -> None:
        self.assertEqual(collect_network_addresses(), ([], []))


if __name__ == "__main__":
    unittest.main()