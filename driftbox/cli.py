"""Command-line interface for Driftbox."""

import argparse
import ipaddress
import json
import os
import platform
import socket
import sys
from datetime import datetime, timezone

from driftbox import __version__


def running_in_wsl() -> bool:
    """Return True when Driftbox is running inside Windows Subsystem for Linux."""
    # WSL exposes its distribution name in normal sessions.
    if os.environ.get("WSL_DISTRO_NAME"):
        return True

    # The kernel release provides a fallback when the environment variable is absent.
    return "microsoft" in platform.release().lower()


def environment_name() -> str:
    """Return a readable name for the current execution environment."""
    if running_in_wsl():
        distro = os.environ.get("WSL_DISTRO_NAME", "Linux")
        return f"WSL ({distro})"

    if os.environ.get("WT_SESSION"):
        return "Windows Terminal"

    return platform.system()


def collect_network_addresses() -> tuple[list[str], list[str]]:
    """Collect non-loopback IP addresses associated with the hostname."""
    ipv4_addresses: set[str] = set()
    ipv6_addresses: set[str] = set()

    try:
        address_info = socket.getaddrinfo(socket.gethostname(), None)
    except socket.gaierror:
        # Hostname resolution can fail on offline or unusually configured systems.
        return [], []

    for family, _, _, _, socket_address in address_info:
        # IPv6 scope identifiers describe an interface but are not part of the address.
        address = socket_address[0].split("%", maxsplit=1)[0]

        try:
            parsed_address = ipaddress.ip_address(address)
        except ValueError:
            continue

        if parsed_address.is_loopback:
            continue

        if family == socket.AF_INET:
            ipv4_addresses.add(address)
        elif family == socket.AF_INET6:
            ipv6_addresses.add(address)

    # Stable ordering keeps reports predictable for humans, tests, and automation.
    return sorted(ipv4_addresses), sorted(ipv6_addresses)


def collect_system_info() -> dict[str, object]:
    """Collect system details without formatting them for a specific output."""
    return {
        "environment": environment_name(),
        "operating_system": platform.system(),
        "os_release": platform.release(),
        "architecture": platform.machine(),
        "hostname": socket.gethostname(),
        "python_version": platform.python_version(),
        "python_executable": sys.executable,
        "wsl": running_in_wsl(),
    }


def collect_network_info() -> dict[str, object]:
    """Collect hostname and local network-address information."""
    ipv4_addresses, ipv6_addresses = collect_network_addresses()

    return {
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "ipv4_addresses": ipv4_addresses,
        "ipv6_addresses": ipv6_addresses,
    }


def build_report() -> dict[str, object]:
    """Build a portable, machine-readable Driftbox report."""
    return {
        "schema_version": 1,
        "driftbox_version": __version__,
        # UTC prevents reports from becoming ambiguous when systems use different zones.
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "system": collect_system_info(),
        "network": collect_network_info(),
    }


def show_system_info() -> None:
    """Display basic information about the current system."""
    system_info = collect_system_info()

    print("driftbox :: system information")
    print("-" * 32)
    print(f"environment : {system_info['environment']}")
    print(
        "operating OS: "
        f"{system_info['operating_system']} {system_info['os_release']}"
    )
    print(f"architecture: {system_info['architecture']}")
    print(f"hostname    : {system_info['hostname']}")
    print(f"python      : {system_info['python_version']}")
    print(f"executable  : {system_info['python_executable']}")
    print(f"wsl         : {'yes' if system_info['wsl'] else 'no'}")


def show_network_info() -> None:
    """Display hostname and local network-address information."""
    network_info = collect_network_info()
    ipv4_addresses = network_info["ipv4_addresses"]
    ipv6_addresses = network_info["ipv6_addresses"]

    print("driftbox :: network information")
    print("-" * 32)
    print(f"hostname    : {network_info['hostname']}")
    print(f"fqdn        : {network_info['fqdn']}")
    print(f"ipv4        : {', '.join(ipv4_addresses) or 'not detected'}")
    print(f"ipv6        : {', '.join(ipv6_addresses) or 'not detected'}")


def show_report() -> None:
    """Write the complete Driftbox report as formatted JSON."""
    print(json.dumps(build_report(), indent=2, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    """Create the Driftbox argument parser."""
    parser = argparse.ArgumentParser(
        prog="driftbox",
        description="Cross-platform system inspection from the terminal.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    commands = parser.add_subparsers(dest="command")
    commands.add_parser("info", help="Display system and environment information")
    commands.add_parser("network", help="Display local network information")
    commands.add_parser("report", help="Generate a portable JSON system report")

    return parser


def main() -> None:
    """Run Driftbox."""
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "info":
        show_system_info()
    elif args.command == "network":
        show_network_info()
    elif args.command == "report":
        show_report()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()