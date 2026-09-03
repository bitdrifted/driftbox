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

from driftbox.configuration import (
    load_configuration,
    reset_configuration,
    set_configuration_value,
)
from driftbox.firewall import collect_firewall_info
from driftbox.findings import (
    combine_findings,
    drift_findings,
    format_findings,
    integrity_findings,
    posture_findings,
)
from driftbox.integrity import (
    compare_integrity,
    create_manifest,
    load_manifest,
    scan_path,
)
from driftbox.history import (
    capture_snapshot,
    list_snapshots,
    read_snapshot,
    snapshot_listing_data,
)
from driftbox.report_diff import (
    compare_snapshots,
    format_drift,
    load_baseline,
    normalize_report,
)
from driftbox.security_checks import analyze_security_posture
from driftbox.scan_runner import run_scan
from driftbox.scheduler import scheduler_for_platform

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
        "firewall": collect_firewall_info(),
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


def show_firewall_info() -> None:
    """Display firewall status without changing its configuration."""
    firewall = collect_firewall_info()

    print("driftbox :: firewall information")
    print("-" * 72)
    print(f"platform : {firewall['platform']}")
    print(f"provider : {firewall['provider']}")
    print(f"status   : {firewall['status']}")

    profiles = firewall.get("profiles", [])

    if not isinstance(profiles, list) or not profiles:
        return

    print()
    print(f"{'PROFILE':<10} {'ENABLED':<9} {'INBOUND':<18} {'OUTBOUND'}")
    print("-" * 72)

    for profile in profiles:
        if not isinstance(profile, dict):
            continue

        enabled = profile.get("enabled")

        if enabled is True:
            enabled_text = "yes"
        elif enabled is False:
            enabled_text = "no"
        else:
            enabled_text = "unknown"

        print(
            f"{str(profile.get('name', 'Unknown')):<10} "
            f"{enabled_text:<9} "
            f"{str(profile.get('default_inbound', 'Unknown')):<18} "
            f"{profile.get('default_outbound', 'Unknown')}"
        )


def show_report() -> None:
    """Write the complete Driftbox report as formatted JSON."""
    print(json.dumps(build_report(), indent=2, sort_keys=True))


def show_report_diff(baseline_path: str) -> int:
    """Compare the current report with a saved baseline and return an exit code."""
    try:
        baseline = load_baseline(baseline_path)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        print(
            f"driftbox: invalid baseline {baseline_path!r}: {error}",
            file=sys.stderr,
        )
        return 2

    current = normalize_report(build_report())
    drift = compare_snapshots(baseline, current)
    print(format_drift(drift))
    return 1 if drift.found else 0


def create_integrity_manifest(path: str, output_path: str) -> int:
    """Create a file-integrity manifest and return a command exit code."""
    try:
        file_count = create_manifest(path, output_path)
    except (OSError, UnicodeError, ValueError) as error:
        print(f"driftbox: integrity create failed: {error}", file=sys.stderr)
        return 2
    print(f"Created integrity manifest: {output_path}")
    print(f"Files recorded: {file_count}")
    return 0


def verify_integrity(path: str, manifest_path: str) -> int:
    """Verify a path against an integrity manifest and return an exit code."""
    try:
        baseline = load_manifest(manifest_path)
        current = scan_path(path, excluded_path=manifest_path)
        changes = compare_integrity(baseline, current)
        findings = integrity_findings(changes)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        print(f"driftbox: integrity verify failed: {error}", file=sys.stderr)
        return 2
    print(format_findings(findings, "file integrity"))
    return 1 if findings.actionable else 0


def show_security_checks(json_output: bool = False) -> int:
    """Analyze current inspection data and return a command exit code."""
    try:
        result = posture_findings(
            analyze_security_posture(
                collect_firewall_info(),
                collect_listening_ports(),
            )
        )
        if json_output:
            output = json.dumps(result.as_dict(), indent=2, sort_keys=True)
        else:
            output = format_findings(result, "security posture")
        print(output)
    except Exception as error:
        try:
            print(f"driftbox: security check failed: {error}", file=sys.stderr)
        except Exception:
            # The original failure may be the output stream itself.
            pass
        return 2

    return 1 if result.actionable else 0


def analyze_history_snapshot(identifier: str, json_output: bool = False) -> int:
    """Combine snapshot drift and current security posture findings."""
    try:
        _, baseline_report = read_snapshot(identifier)
        current_report = build_report()
        drift = compare_snapshots(
            normalize_report(baseline_report),
            normalize_report(current_report),
        )
        exposure = current_report.get("exposure")
        if not isinstance(exposure, dict):
            raise ValueError("current report exposure must be an object")
        result = combine_findings(
            drift_findings(drift),
            posture_findings(
                analyze_security_posture(
                    current_report.get("firewall"),
                    exposure.get("listening_ports"),
                )
            ),
        )
        if json_output:
            output = json.dumps(result.as_dict(), indent=2, sort_keys=True)
        else:
            output = format_findings(result, "unified analysis")
        print(output)
    except Exception as error:
        try:
            print(f"driftbox: analysis failed: {error}", file=sys.stderr)
        except Exception:
            pass
        return 2
    return 1 if result.actionable else 0


def _show_history_error(action: str, error: Exception) -> None:
    """Write a history error when the error stream remains available."""
    try:
        print(f"driftbox: history {action} failed: {error}", file=sys.stderr)
    except Exception:
        pass


def capture_history() -> int:
    """Capture the current report in persistent local history."""
    try:
        snapshot = capture_snapshot(build_report())
        print(f"Captured snapshot: {snapshot.identifier}")
        print(f"Created at: {snapshot.created_at}")
        print(f"Size: {snapshot.size} bytes")
    except Exception as error:
        _show_history_error("capture", error)
        return 2
    return 0


def show_history_list(json_output: bool = False) -> int:
    """List saved report snapshots newest first."""
    try:
        snapshots = list_snapshots()
        if json_output:
            output = json.dumps(
                snapshot_listing_data(snapshots),
                indent=2,
                sort_keys=True,
            )
        else:
            lines = ["driftbox :: report history", "-" * 32]
            if snapshots:
                lines.extend(
                    f"{item.identifier}  {item.created_at}  {item.size} bytes"
                    for item in snapshots
                )
            else:
                lines.append("No snapshots captured.")
            output = "\n".join(lines)
        print(output)
    except Exception as error:
        _show_history_error("list", error)
        return 2
    return 0


def show_history_snapshot(identifier: str) -> int:
    """Write a stored snapshot without reformatting it."""
    try:
        snapshot_text, _ = read_snapshot(identifier)
        sys.stdout.write(snapshot_text)
    except Exception as error:
        _show_history_error("show", error)
        return 2
    return 0


def diff_history_snapshot(identifier: str) -> int:
    """Compare the current report with a stored history snapshot."""
    try:
        _, baseline_report = read_snapshot(identifier)
        baseline = normalize_report(baseline_report)
        current = normalize_report(build_report())
        drift = compare_snapshots(baseline, current)
        print(format_drift(drift))
    except Exception as error:
        _show_history_error("diff", error)
        return 2
    return 1 if drift.found else 0


def _show_command_error(command: str, error: Exception) -> None:
    """Write a consistent operational error without masking output failures."""
    try:
        print(f"driftbox: {command} failed: {error}", file=sys.stderr)
    except Exception:
        pass


def show_configuration(json_output: bool = False) -> int:
    """Display the validated configuration, creating defaults if needed."""
    try:
        configuration = load_configuration()
        if json_output:
            output = json.dumps(configuration, indent=2, sort_keys=True)
        else:
            settings = configuration["settings"]
            output = "\n".join(
                [
                    "driftbox :: configuration",
                    "-" * 32,
                    f"schema_version: {configuration['schema_version']}",
                    *(
                        f"{key}: {json.dumps(value, sort_keys=True)}"
                        for key, value in sorted(settings.items())
                    ),
                ]
            )
        print(output)
    except Exception as error:
        _show_command_error("config show", error)
        return 2
    return 0


def set_configuration(key: str, value: str) -> int:
    """Set one validated configuration value."""
    try:
        configuration = set_configuration_value(key, value)
        print(
            f"Updated {key}: "
            f"{json.dumps(configuration['settings'][key], sort_keys=True)}"
        )
    except Exception as error:
        _show_command_error("config set", error)
        return 2
    return 0


def reset_configuration_command() -> int:
    """Reset the saved configuration to Driftbox defaults."""
    try:
        reset_configuration()
        print("Driftbox configuration reset to defaults.")
    except Exception as error:
        _show_command_error("config reset", error)
        return 2
    return 0


def run_configured_scan(json_output: bool = False) -> int:
    """Run a configured report, posture, integrity, and history scan."""
    try:
        configuration = load_configuration()
        result = run_scan(build_report, configuration)
        settings = configuration["settings"]
        use_json = json_output or settings["scan_output"] == "json"
        if use_json:
            output = json.dumps(result.as_dict(), indent=2, sort_keys=True)
        else:
            previous = result.previous_snapshot or "none (baseline initialized)"
            output = "\n".join(
                [
                    format_findings(result.findings, "configured scan"),
                    "",
                    f"Previous snapshot: {previous}",
                    f"Captured snapshot: {result.captured_snapshot.identifier}",
                ]
            )
        print(output)
    except Exception as error:
        _show_command_error("scan", error)
        return 2
    return 1 if result.findings.actionable else 0


def install_schedule(daily_time: str, dry_run: bool = False) -> int:
    """Install or preview the platform's per-user daily scan schedule."""
    try:
        result = scheduler_for_platform().install(daily_time, dry_run)
        print(f"Schedule state: {result.state}")
        print(result.message)
    except Exception as error:
        _show_command_error("schedule install", error)
        return 2
    return 2 if result.state == "unsupported" else 0


def show_schedule_status() -> int:
    """Display installed, absent, unsupported, or malformed schedule state."""
    try:
        result = scheduler_for_platform().status()
        print(f"Schedule state: {result.state}")
        print(result.message)
    except Exception as error:
        _show_command_error("schedule status", error)
        return 2
    return 2 if result.state in ("malformed", "unsupported") else 0


def remove_schedule() -> int:
    """Remove only Driftbox's owned scheduled scan."""
    try:
        result = scheduler_for_platform().remove()
        print(f"Schedule state: {result.state}")
        print(result.message)
    except Exception as error:
        _show_command_error("schedule remove", error)
        return 2
    return 2 if result.state == "unsupported" else 0


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
    check_parser = commands.add_parser(
        "check",
        help="Analyze firewall and listening-port security posture",
    )
    check_parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Write a machine-readable JSON result",
    )
    analyze_parser = commands.add_parser(
        "analyze",
        help="Analyze current posture and drift from a history snapshot",
    )
    analyze_parser.add_argument(
        "snapshot",
        nargs="?",
        default="latest",
        help="Snapshot identifier or latest (default: latest)",
    )
    analyze_parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Write versioned machine-readable findings",
    )
    history_parser = commands.add_parser(
        "history",
        help="Capture and inspect persistent local report history",
    )
    history_commands = history_parser.add_subparsers(
        dest="history_command",
        required=True,
    )
    history_commands.add_parser("capture", help="Capture the current report")
    history_list = history_commands.add_parser("list", help="List snapshots")
    history_list.add_argument("--json", action="store_true", dest="json_output")
    history_show = history_commands.add_parser("show", help="Show a snapshot")
    history_show.add_argument("snapshot", help="Snapshot identifier or latest")
    history_diff = history_commands.add_parser("diff", help="Compare a snapshot")
    history_diff.add_argument("snapshot", help="Snapshot identifier or latest")
    diff_parser = commands.add_parser(
        "diff",
        help="Compare the current report with a saved baseline",
    )
    diff_parser.add_argument("baseline", help="Path to a baseline JSON report")
    integrity_parser = commands.add_parser(
        "integrity",
        help="Create or verify SHA-256 file-integrity manifests",
    )
    integrity_commands = integrity_parser.add_subparsers(
        dest="integrity_command",
        required=True,
    )
    integrity_create = integrity_commands.add_parser("create")
    integrity_create.add_argument("path", help="Regular file or directory to scan")
    integrity_create.add_argument("--output", required=True)
    integrity_verify = integrity_commands.add_parser("verify")
    integrity_verify.add_argument("path", help="Regular file or directory to scan")
    integrity_verify.add_argument("manifest", help="Integrity manifest to verify")

    config_parser = commands.add_parser(
        "config",
        help="Show or update persistent per-user configuration",
    )
    config_commands = config_parser.add_subparsers(
        dest="config_command",
        required=True,
    )
    config_show = config_commands.add_parser("show", help="Show configuration")
    config_show.add_argument("--json", action="store_true", dest="json_output")
    config_set = config_commands.add_parser("set", help="Set one configuration value")
    config_set.add_argument("key", help="Configuration key")
    config_set.add_argument("value", help="Configuration value")
    config_commands.add_parser("reset", help="Reset configuration to defaults")
    scan_parser = commands.add_parser(
        "scan",
        help="Run configured analysis and capture the report to history",
    )
    scan_parser.add_argument("--json", action="store_true", dest="json_output")
    schedule_parser = commands.add_parser(
        "schedule",
        help="Manage a per-user scheduled Driftbox scan",
    )
    schedule_commands = schedule_parser.add_subparsers(
        dest="schedule_command",
        required=True,
    )
    schedule_install = schedule_commands.add_parser(
        "install", help="Install a daily scheduled scan"
    )
    schedule_install.add_argument("--daily", required=True, metavar="HH:MM")
    schedule_install.add_argument("--dry-run", action="store_true")
    schedule_commands.add_parser("status", help="Show scheduled scan status")
    schedule_commands.add_parser("remove", help="Remove the scheduled scan")

    commands.add_parser(
        "firewall",
        help="inspect local firewall status",
    )

    return parser


def main() -> int:
    """Run Driftbox."""
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "info":
        show_system_info()
    elif args.command == "network":
        show_network_info()
    elif args.command == "ports":
        show_listening_ports()
    elif args.command == "firewall":
        show_firewall_info()
    elif args.command == "report":
        show_report()
    elif args.command == "diff":
        return show_report_diff(args.baseline)
    elif args.command == "integrity":
        if args.integrity_command == "create":
            return create_integrity_manifest(args.path, args.output)
        return verify_integrity(args.path, args.manifest)
    elif args.command == "check":
        return show_security_checks(args.json_output)
    elif args.command == "analyze":
        return analyze_history_snapshot(args.snapshot, args.json_output)
    elif args.command == "history":
        if args.history_command == "capture":
            return capture_history()
        if args.history_command == "list":
            return show_history_list(args.json_output)
        if args.history_command == "show":
            return show_history_snapshot(args.snapshot)
        return diff_history_snapshot(args.snapshot)
    elif args.command == "config":
        if args.config_command == "show":
            return show_configuration(args.json_output)
        if args.config_command == "set":
            return set_configuration(args.key, args.value)
        return reset_configuration_command()
    elif args.command == "scan":
        return run_configured_scan(args.json_output)
    elif args.command == "schedule":
        if args.schedule_command == "install":
            return install_schedule(args.daily, args.dry_run)
        if args.schedule_command == "status":
            return show_schedule_status()
        return remove_schedule()
    else:
        parser.print_help()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
