"""Command-line interface for Driftbox."""

import argparse
import ipaddress
import os
import platform
import socket
import sys

from driftbox import __version__


def running_in_wsl() -> bool:
    """Return True when Driftbox is running inside Windows Subsystem for Linux."""
    if os.environ.get("WSL_DISTRO_NAME"):
        return True

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
        return [], []

    for family, _, _, _, socket_address in address_info:
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

    return sorted(ipv4_addresses), sorted(ipv6_addresses)


def show_system_info() -> None:
    """Display basic information about the current system."""
    print("driftbox :: system information")
    print("-" * 32)
    print(f"environment : {environment_name()}")
    print(f"operating OS: {platform.system()} {platform.release()}")
    print(f"architecture: {platform.machine()}")
    print(f"hostname    : {socket.gethostname()}")
    print(f"python      : {platform.python_version()}")
    print(f"executable  : {sys.executable}")
    print(f"wsl         : {'yes' if running_in_wsl() else 'no'}")


def show_network_info() -> None:
    """Display hostname and local network-address information."""
    ipv4_addresses, ipv6_addresses = collect_network_addresses()

    print("driftbox :: network information")
    print("-" * 32)
    print(f"hostname    : {socket.gethostname()}")
    print(f"fqdn        : {socket.getfqdn()}")
    print(f"ipv4        : {', '.join(ipv4_addresses) or 'not detected'}")
    print(f"ipv6        : {', '.join(ipv6_addresses) or 'not detected'}")


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

    return parser


def main() -> None:
    """Run Driftbox."""
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "info":
        show_system_info()
    elif args.command == "network":
        show_network_info()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()