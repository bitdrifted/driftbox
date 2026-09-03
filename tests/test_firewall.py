"""Tests for Driftbox's read-only firewall inspection."""

import json
import unittest
from unittest.mock import Mock, patch

from driftbox.firewall import collect_firewall_info


class FirewallTests(unittest.TestCase):
    """Verify firewall detection across supported operating systems."""

    def test_collects_enabled_windows_profiles(self) -> None:
        profiles = [
            {
                "name": "Domain",
                "enabled": "True",
                "default_inbound": "NotConfigured",
                "default_outbound": "NotConfigured",
            },
            {
                "name": "Private",
                "enabled": "True",
                "default_inbound": "Block",
                "default_outbound": "Allow",
            },
            {
                "name": "Public",
                "enabled": "True",
                "default_inbound": "Block",
                "default_outbound": "Allow",
            },
        ]
        command_result = Mock(
            returncode=0,
            stdout=json.dumps(profiles),
        )

        with (
            patch(
                "driftbox.firewall.platform.system",
                return_value="Windows",
            ),
            patch(
                "driftbox.firewall._run_command",
                return_value=command_result,
            ),
        ):
            firewall = collect_firewall_info()

        self.assertEqual(firewall["status"], "enabled")
        self.assertEqual(
            firewall["provider"],
            "Microsoft Defender Firewall",
        )
        self.assertEqual(len(firewall["profiles"]), 3)

    def test_windows_command_failure_returns_unknown(self) -> None:
        command_result = Mock(returncode=1, stdout="")

        with (
            patch(
                "driftbox.firewall.platform.system",
                return_value="Windows",
            ),
            patch(
                "driftbox.firewall._run_command",
                return_value=command_result,
            ),
        ):
            firewall = collect_firewall_info()

        self.assertEqual(firewall["status"], "unknown")
        self.assertEqual(firewall["profiles"], [])

    def test_detects_active_ufw_on_linux(self) -> None:
        command_result = Mock(
            returncode=0,
            stdout="Status: active\n",
        )

        with (
            patch(
                "driftbox.firewall.platform.system",
                return_value="Linux",
            ),
            patch(
                "driftbox.firewall.shutil.which",
                return_value="/usr/sbin/ufw",
            ),
            patch(
                "driftbox.firewall._run_command",
                return_value=command_result,
            ),
        ):
            firewall = collect_firewall_info()

        self.assertEqual(firewall["provider"], "UFW")
        self.assertEqual(firewall["status"], "enabled")

    def test_linux_without_known_manager_returns_unknown(self) -> None:
        with (
            patch(
                "driftbox.firewall.platform.system",
                return_value="Linux",
            ),
            patch(
                "driftbox.firewall.shutil.which",
                return_value=None,
            ),
        ):
            firewall = collect_firewall_info()

        self.assertEqual(firewall["provider"], "not detected")
        self.assertEqual(firewall["status"], "unknown")

    def test_detects_enabled_macos_firewall(self) -> None:
        command_result = Mock(
            returncode=0,
            stdout="Firewall is enabled. (State = 1)\n",
        )

        with (
            patch(
                "driftbox.firewall.platform.system",
                return_value="Darwin",
            ),
            patch(
                "driftbox.firewall._run_command",
                return_value=command_result,
            ),
        ):
            firewall = collect_firewall_info()

        self.assertEqual(
            firewall["provider"],
            "macOS Application Firewall",
        )
        self.assertEqual(firewall["status"], "enabled")

    def test_unknown_platform_is_handled_safely(self) -> None:
        with patch(
            "driftbox.firewall.platform.system",
            return_value="MysteryOS",
        ):
            firewall = collect_firewall_info()

        self.assertEqual(firewall["provider"], "unsupported")
        self.assertEqual(firewall["status"], "unknown")


if __name__ == "__main__":
    unittest.main()