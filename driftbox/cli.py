"""Command-line interface for Driftbox."""

import argparse
import ipaddress
import json
import os
import platform
import socket
import sys
from datetime import datetime, timezone
import psutil

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
    """Collect non-loopback IP addresses from local network interfaces."""
    ipv4_addresses: set[str] = set()
    ipv6_addresses: set[str] = set()

    try:
        interfaces = psutil.net_if_addrs()
    except (OSError, RuntimeError, psutil.Error):
        # Inspection should fail safely on restricted or unusual systems.
        return [], []

    for interface_addresses in interfaces.values():
        for interface_address in interface_addresses:
            if interface_address.family not in (socket.AF_INET, socket.AF_INET6):
                continue

            # IPv6 scope identifiers describe an interface, not the address itself.
            address = interface_address.address.split("%", maxsplit=1)[0]

            try:
                parsed_address = ipaddress.ip_address(address)
            except ValueError:
                continue

            if parsed_address.is_loopback:
                continue

            if interface_address.family == socket.AF_INET:
                ipv4_addresses.add(address)
            else:
                ipv6_addresses.add(address)

    # Stable ordering keeps reports predictable for humans, tests, and automation.
    return sorted(ipv4_addresses), sorted(ipv6_addresses)

def classify_address_scope(address: str) -> str:
    """Describe the network scope of a local listening address."""
    # IPv6 addresses may include an interface identifier after a percent sign.
    normalized_address = address.split("%", maxsplit=1)[0]

    try:
        parsed_address = ipaddress.ip_address(normalized_address)
    except ValueError:
        return "unknown"

    if parsed_address.is_unspecified:
        return "all interfaces"
    if parsed_address.is_loopback:
        return "local only"
    if parsed_address.is_link_local:
        return "link local"
    if parsed_address.is_private:
        return "private network"

    # A public binding may still be protected by a firewall or upstream router.
    return "public address"

def collect_listening_ports() -> list[dict[str, object]]:
    """Collect TCP listeners and locally bound UDP ports."""
    listening_ports: list[dict[str, object]] = []

    try:
        connections = psutil.net_connections(kind="inet")
    except (OSError, RuntimeError, psutil.Error):
        # Some systems restrict access to connection information for non-admin users.
        return []

    for connection in connections:
        if not connection.laddr:
            continue

        if connection.type == socket.SOCK_STREAM:
            if connection.status != psutil.CONN_LISTEN:
                continue
            protocol = "TCP"
        elif connection.type == socket.SOCK_DGRAM:
            # UDP has no connection handshake, so a bound socket has no LISTEN state.
            protocol = "UDP"
        else:
            continue

        process_name = "unavailable"
        if connection.pid is not None:
            try:
                process_name = psutil.Process(connection.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

        listening_ports.append(
            {
                "protocol": protocol,
                "address": connection.laddr.ip,
                "scope": classify_address_scope(connection.laddr.ip),
                "port": connection.laddr.port,
                "pid": connection.pid,
                "process": process_name,
            }
        )

    # Predictable ordering makes terminal output and JSON reports easier to compare.
    return sorted(
        listening_ports,
        key=lambda item: (
            item["port"],
            item["protocol"],
            item["address"],
            item["pid"] or -1,
        ),
    )

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
        "exposure": {
            "listening_ports": collect_listening_ports(),
        },
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

def show_listening_ports() -> None:
    """Display TCP listeners and locally bound UDP ports."""
    listening_ports = collect_listening_ports()

    print("driftbox :: listening ports")

    if not listening_ports:
        print("-" * 32)
        print("No accessible listening ports detected.")
        return

    print(
        f"{'NET':<3} "
        f"{'SCOPE':<17} "
        f"{'ENDPOINT':<45} "
        f"{'PID':<7} "
        "PROCESS"
    )
    print("-" * 92)

    for item in listening_ports:
        address = str(item["address"])
        host = f"[{address}]" if ":" in address else address
        endpoint = f"{host}:{item['port']}"
        pid = item["pid"] if item["pid"] is not None else "-"

        print(
            f"{item['protocol']:<3} "
            f"{item['scope']:<17} "
            f"{endpoint:<45} "
            f"{str(pid):<7} "
            f"{item['process']}"
        )

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
    commands.add_parser("ports", help="Display listening TCP and bound UDP ports")
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
    elif args.command == "ports":
        show_listening_ports()
    elif args.command == "report":
        show_report()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()