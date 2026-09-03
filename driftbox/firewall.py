"""Read-only, cross-platform firewall inspection."""

from __future__ import annotations

import json
import platform
import shutil
import subprocess

COMMAND_TIMEOUT_SECONDS = 5


def _run_command(
    command: list[str],
) -> subprocess.CompletedProcess[str] | None:
    """Run an inspection command without modifying firewall settings."""
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def _unknown_result(
    operating_system: str,
    provider: str,
) -> dict[str, object]:
    """Return a consistent result when firewall status cannot be confirmed."""
    return {
        "platform": operating_system,
        "provider": provider,
        "status": "unknown",
        "profiles": [],
    }


def _boolean_value(value: object) -> bool | None:
    """Convert firewall command output into a boolean when possible."""
    normalized = str(value).strip().lower()

    if normalized == "true":
        return True
    if normalized == "false":
        return False
    return None


def _collect_windows_firewall() -> dict[str, object]:
    """Inspect Microsoft Defender Firewall profiles through PowerShell."""
    script = (
        "Get-NetFirewallProfile | ForEach-Object { "
        "[PSCustomObject]@{"
        "name=$_.Name;"
        "enabled=\"$($_.Enabled)\";"
        "default_inbound=\"$($_.DefaultInboundAction)\";"
        "default_outbound=\"$($_.DefaultOutboundAction)\""
        "} } | ConvertTo-Json -Compress"
    )

    result = _run_command(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ],
    )

    if result is None or result.returncode != 0:
        return _unknown_result("Windows", "Microsoft Defender Firewall")

    try:
        raw_profiles = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError):
        return _unknown_result("Windows", "Microsoft Defender Firewall")

    if isinstance(raw_profiles, dict):
        raw_profiles = [raw_profiles]

    profiles = []
    for profile in raw_profiles:
        profiles.append(
            {
                "name": profile.get("name", "Unknown"),
                "enabled": _boolean_value(profile.get("enabled")),
                "default_inbound": profile.get(
                    "default_inbound",
                    "Unknown",
                ),
                "default_outbound": profile.get(
                    "default_outbound",
                    "Unknown",
                ),
            },
        )

    enabled_values = [profile["enabled"] for profile in profiles]

    if enabled_values and all(value is True for value in enabled_values):
        status = "enabled"
    elif enabled_values and all(value is False for value in enabled_values):
        status = "disabled"
    elif any(value is None for value in enabled_values):
        status = "unknown"
    else:
        status = "mixed"

    return {
        "platform": "Windows",
        "provider": "Microsoft Defender Firewall",
        "status": status,
        "profiles": profiles,
    }


def _collect_linux_firewall() -> dict[str, object]:
    """Inspect common Linux firewall managers without requiring changes."""
    if shutil.which("ufw"):
        result = _run_command(["ufw", "status"])

        if result is not None and result.returncode == 0:
            output = result.stdout.lower()

            if "status: active" in output:
                status = "enabled"
            elif "status: inactive" in output:
                status = "disabled"
            else:
                status = "unknown"

            return {
                "platform": "Linux",
                "provider": "UFW",
                "status": status,
                "profiles": [],
            }

    if shutil.which("firewall-cmd"):
        result = _run_command(["firewall-cmd", "--state"])

        if result is not None:
            output = result.stdout.strip().lower()
            status = "enabled" if output == "running" else "disabled"

            return {
                "platform": "Linux",
                "provider": "firewalld",
                "status": status,
                "profiles": [],
            }

    # "Unknown" is safer than claiming a Linux system has no firewall.
    return _unknown_result("Linux", "not detected")


def _collect_macos_firewall() -> dict[str, object]:
    """Inspect the macOS application firewall."""
    provider = "macOS Application Firewall"
    result = _run_command(
        [
            "/usr/libexec/ApplicationFirewall/socketfilterfw",
            "--getglobalstate",
        ],
    )

    if result is None or result.returncode != 0:
        return _unknown_result("macOS", provider)

    output = result.stdout.lower()

    if "disabled" in output:
        status = "disabled"
    elif "enabled" in output:
        status = "enabled"
    else:
        status = "unknown"

    return {
        "platform": "macOS",
        "provider": provider,
        "status": status,
        "profiles": [],
    }


def collect_firewall_info() -> dict[str, object]:
    """Collect firewall information for the current operating system."""
    operating_system = platform.system()

    if operating_system == "Windows":
        return _collect_windows_firewall()
    if operating_system == "Linux":
        return _collect_linux_firewall()
    if operating_system == "Darwin":
        return _collect_macos_firewall()

    return _unknown_result(operating_system, "unsupported")