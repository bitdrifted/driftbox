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
from driftbox.mission_commands import (
    reset_mission,
    show_mission_brief,
    show_mission_list,
    show_mission_status,
    show_next_hint,
    start_mission,
    submit_mission,
)
from driftbox.network_discovery import (
    CandidateSelectionRequired,
    DEFAULT_TIMEOUT_SECONDS,
    DEFAULT_WORKERS,
    DiscoveryOperationalError,
    MAX_TIMEOUT_SECONDS,
    MAX_WORKERS,
    MIN_TIMEOUT_SECONDS,
    MIN_WORKERS,
    NoSuitableNetworkError,
    SCHEMA_VERSION as DISCOVERY_SCHEMA_VERSION,
    TargetValidationError,
    detect_local_network_candidates,
    discover_network,
    resolve_target,
)
from driftbox.discovery_interpretation import (
    build_discovery_interpretation,
    validate_recommendation_commands,
    with_discovery_interpretation,
)
from driftbox.service_inventory import (
    AuthorizationRequiredError,
    DEFAULT_TOP_PORTS,
    NmapAdapter,
    NmapExecutionError,
    NmapExecutionTimeoutError,
    NmapUnavailableError,
    NmapXMLParseError,
    NmapXMLSecurityError,
    ServiceTargetValidationError,
    SERVICE_INVENTORY_SCHEMA_VERSION,
    TopPortsValidationError,
    build_nmap_command,
    sanitize_display,
    validate_service_target,
    validate_top_ports,
)
from driftbox.service_inventory_interpretation import (
    build_service_inventory_interpretation,
    validate_service_recommendation_commands,
    with_service_inventory_interpretation,
)
from driftbox.vulnerability_analysis import (
    VULNERABILITY_ANALYSIS_SCHEMA_VERSION,
    ServiceReportValidationError,
    VulnerabilityAnalysisError,
    build_lookup_plan,
    build_vulnerability_analysis_report,
    format_vulnerability_analysis,
    load_service_inventory_report,
)
from driftbox.vulnerability_sources import (
    CISA_KEV_CATALOG_URL,
    CISA_KEV_URL,
    NVD_API_URL,
    NVD_DETAIL_URL,
    SourceCoordinator,
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


def run_mission_command(args: argparse.Namespace) -> int:
    """Run a synthetic training command with consistent error handling."""
    try:
        if args.mission_command == "list":
            show_mission_list(args.json_output)
        elif args.mission_command == "start":
            start_mission(args.mission)
        elif args.mission_command == "brief":
            show_mission_brief()
        elif args.mission_command == "status":
            show_mission_status()
        elif args.mission_command == "hint":
            show_next_hint()
        elif args.mission_command == "submit":
            submit_mission()
        else:
            reset_mission()
    except Exception as error:
        _show_command_error("mission", error)
        return 2
    return 0


_DISCOVERY_STATUS_LABELS = {
    "local_machine": "local machine",
    "confirmed_responsive": "confirmed responsive",
    "known_neighbor": "locally known neighbor",
    "confirmed_gateway": "routing evidence only",
}

_DISCOVERY_EVIDENCE_LABELS = {
    "local_interface_address": "local interface address",
    "icmp_echo_reply": "ICMP echo reply",
    "neighbor_cache": "neighbor/cache entry",
    "default_gateway_route": "configured default-gateway route",
}

_DISCOVERY_SOURCE_LABELS = {
    "psutil_interface_data": "local interface data",
    "system_ping": "system ping",
    "ip_neighbor_cache": "IP neighbor cache",
    "arp_cache": "ARP cache",
    "routing_table": "local routing table",
}

_HUMAN_DISCOVERY_ITEM_LIMIT = 10


def _format_bounded_discovery_items(items: list[object]) -> str:
    """Render a deterministic terminal preview without losing JSON evidence."""
    values = [str(item) for item in items]
    if not values:
        return "none recorded"
    preview = ", ".join(values[:_HUMAN_DISCOVERY_ITEM_LIMIT])
    remaining = len(values) - _HUMAN_DISCOVERY_ITEM_LIMIT
    if remaining > 0:
        return f"{preview}, and {remaining} more"
    return preview


def _format_discovery_evidence(evidence: object) -> str:
    """Format one host's evidence without overstating what it proves."""
    if not isinstance(evidence, list):
        return "evidence metadata unavailable"

    labels: list[str] = []
    for item in evidence:
        if not isinstance(item, dict):
            continue
        kind = str(item.get("kind", "unavailable"))
        label = _DISCOVERY_EVIDENCE_LABELS.get(kind, kind.replace("_", " "))
        details: list[str] = []
        if item.get("source") is not None:
            source = str(item["source"])
            details.append(f"source: {_DISCOVERY_SOURCE_LABELS.get(source, source)}")
        if item.get("mac_address") is not None:
            details.append(f"MAC: {item['mac_address']}")
        if item.get("state") is not None:
            details.append(f"state: {item['state']}")
        if item.get("interface") is not None:
            details.append(f"interface: {item['interface']}")
        if item.get("metric") is not None:
            details.append(f"metric: {item['metric']}")
        if details:
            label = f"{label} ({', '.join(details)})"
        labels.append(label)
    return "; ".join(labels) or "evidence metadata unavailable"


def format_network_discovery(report: dict[str, object]) -> str:
    """Return a deterministic, learner-friendly discovery report."""
    target = report["target"]
    settings = report["settings"]
    summary = report["summary"]
    neighbor_cache = report["neighbor_cache"]
    hosts = report["hosts"]
    limitations = report["limitations"]

    if not isinstance(target, dict) or not isinstance(settings, dict):
        raise ValueError("Discovery report target or settings are malformed.")
    if not isinstance(summary, dict) or not isinstance(neighbor_cache, dict):
        raise ValueError("Discovery report summary is malformed.")
    if not isinstance(hosts, list) or not isinstance(limitations, list):
        raise ValueError("Discovery report host or limitation data are malformed.")

    interpretation = build_discovery_interpretation(report)
    discovery_summary = interpretation["discovery_summary"]
    recommendations = interpretation["recommendations"]
    detailed_evidence = interpretation["detailed_evidence"]
    if not isinstance(discovery_summary, dict) or not isinstance(recommendations, list):
        raise ValueError("Discovery interpretation is malformed.")
    if not isinstance(detailed_evidence, dict):
        raise ValueError("Discovery interpretation evidence is malformed.")

    addresses_without_response = discovery_summary.get("addresses_without_response", [])
    addresses_with_probe_errors = discovery_summary.get("addresses_with_probe_errors", [])
    local_computer_addresses = discovery_summary.get("local_computer_addresses", [])
    responsive_devices = discovery_summary.get("responsive_devices", [])
    cache_only_devices = discovery_summary.get("cache_only_devices", [])
    confirmed_gateways = discovery_summary.get("confirmed_in_scope_gateways", [])
    evidence_overlap = discovery_summary.get("evidence_overlap", {})
    incomplete_evidence = detailed_evidence.get("incomplete_evidence", {})
    collection_issues = discovery_summary.get("collection_errors_or_incomplete_evidence", {})
    if not all(
        isinstance(value, list)
        for value in (
            addresses_without_response,
            addresses_with_probe_errors,
            local_computer_addresses,
            responsive_devices,
            cache_only_devices,
            confirmed_gateways,
        )
    ):
        raise ValueError("Discovery interpretation response addresses are malformed.")
    if not isinstance(incomplete_evidence, dict):
        raise ValueError("Discovery interpretation incomplete evidence is malformed.")
    if not isinstance(collection_issues, dict):
        raise ValueError("Discovery interpretation collection issues are malformed.")
    if not isinstance(evidence_overlap, dict):
        raise ValueError("Discovery interpretation overlap evidence is malformed.")
    source_issues = collection_issues.get("sources", [])
    if not isinstance(source_issues, list):
        raise ValueError("Discovery interpretation source issues are malformed.")
    source_issue_text = "; ".join(
        f"{item.get('source', 'unavailable')}={item.get('status', 'unavailable')}"
        + (f" ({item['detail']})" if item.get("detail") else "")
        for item in source_issues
        if isinstance(item, dict)
    )
    collection_issue_text = source_issue_text or "none reported"
    if addresses_with_probe_errors:
        collection_issue_text += (
            "; probe issues at "
            + _format_bounded_discovery_items(addresses_with_probe_errors)
        )

    host_address_count = int(target["host_address_count"])
    probe_address_count = int(target["probe_address_count"])
    response_count = int(summary.get("responses_received", 0))
    positive_count = int(discovery_summary.get("positive_host_evidence_count", 0))
    host_address_label = (
        "host address" if host_address_count == 1 else "host addresses"
    )
    probe_label = "remote probe" if probe_address_count == 1 else "remote probes"
    response_label = "reply" if response_count == 1 else "replies"
    positive_label = "address" if positive_count == 1 else "addresses"
    error_count = int(summary.get("probe_errors", 0))
    error_label = "error" if error_count == 1 else "errors"
    no_reply_count = int(evidence_overlap.get("probe_no_reply_count", 0))
    no_reply_cache_count = int(
        evidence_overlap.get("no_reply_with_neighbor_cache_count", 0)
    )
    no_reply_label = "address" if no_reply_count == 1 else "addresses"
    target_cidr = discovery_summary.get("target_cidr")
    if not isinstance(target_cidr, str):
        raise ValueError("Discovery interpretation target is malformed.")

    lines = [
        "driftbox :: authorized private-network discovery",
        "",
        "DISCOVERY SUMMARY",
        "-----------------",
        (
            f"Network inspected: {target['cidr']} ({target['address_count']} addresses; "
            f"{host_address_count} {host_address_label}; "
            f"{probe_address_count} {probe_label})"
        ),
        "Authorization: scan only networks you own or have explicit permission to inspect.",
        "Method: bounded, unprivileged ICMP echo plus read-only local neighbor/cache and routing-table evidence.",
        (
            f"Parameters: timeout {settings['timeout_seconds']} seconds; "
            f"workers {settings['workers']}"
        ),
        f"Collection status: {report.get('collection_status', 'unavailable')}",
        (
            "Positive host evidence: "
            f"{positive_count} {positive_label}; "
            f"{response_count} {response_label}."
        ),
        (
            "This computer's address: "
            f"{_format_bounded_discovery_items(local_computer_addresses)}"
        ),
        (
            "Devices that responded during the scan: "
            f"{_format_bounded_discovery_items(responsive_devices)}"
        ),
        (
            "Devices supported only by neighbor/cache evidence: "
            f"{_format_bounded_discovery_items(cache_only_devices)}"
        ),
        (
            f"Probes that received no reply: {no_reply_count}."
        ),
        *(
            [
                "No-reply/cache overlap: "
                f"{no_reply_cache_count} of the {no_reply_count} {no_reply_label} "
                "without a reply also have neighbor/cache evidence; these categories "
                "overlap and should not be added together."
            ]
            if no_reply_count
            else []
        ),
        (
            "Confirmed default gateway: "
            f"{_format_bounded_discovery_items(confirmed_gateways)}"
        ),
        (
            "Collection errors or incomplete evidence: "
            f"{collection_issue_text}."
        ),
        "",
        "WHAT THIS MEANS",
        "---------------",
    ]

    what_this_means = interpretation.get("what_this_means", [])
    if not isinstance(what_this_means, list):
        raise ValueError("Discovery interpretation meaning is malformed.")
    lines.extend(f"- {item}" for item in what_this_means)
    lines.extend(["", "RECOMMENDED NEXT STEPS", "----------------------"])
    for index, recommendation in enumerate(recommendations, start=1):
        if not isinstance(recommendation, dict):
            continue
        availability = recommendation.get("availability", {})
        if not isinstance(availability, dict):
            availability = {}
        lines.extend(
            [
                f"{recommendation.get('rank', index)}. {recommendation.get('command', 'unavailable')}",
                f"   Purpose: {recommendation.get('purpose', 'unavailable')}",
                f"   Reason: {recommendation.get('reason', 'unavailable')}",
                f"   Target: {recommendation.get('target', 'unavailable')}",
                f"   Risk/activity: {recommendation.get('activity_level', 'unavailable')}",
                f"   Authorization: {recommendation.get('authorization_required', 'unavailable')}",
                f"   Expected result: {recommendation.get('expected_result', 'unavailable')}",
                (
                    "   Available now: "
                    + (
                        "yes. "
                        if availability.get("available_now") is True
                        else "no. "
                        if availability.get("available_now") is False
                        else "not established. "
                    )
                    + f"{availability.get('condition', 'unavailable')}"
                ),
            ]
        )

    lines.extend(["", "DETAILED EVIDENCE", "-----------------"])
    lines.append(
        "Terminal previews show at most "
        f"{_HUMAN_DISCOVERY_ITEM_LIMIT} addresses or host rows. To display complete "
        f"structured evidence from a newly authorized collection, use: "
        f"driftbox discover {target_cidr} --json. JSON is written to standard "
        "output and is not saved automatically."
    )

    if hosts:
        lines.extend(
            [
                f"{'ADDRESS':<15} {'CLASSIFICATION':<27} EVIDENCE",
                f"{'-' * 15} {'-' * 27} {'-' * 32}",
            ]
        )
        for host in hosts[:_HUMAN_DISCOVERY_ITEM_LIMIT]:
            if not isinstance(host, dict):
                continue
            address = str(host.get("address", "unavailable"))
            status = str(host.get("status", "unavailable"))
            classification = _DISCOVERY_STATUS_LABELS.get(
                status, status.replace("_", " ")
            )
            lines.append(
                f"{address:<15} {classification:<27} "
                f"{_format_discovery_evidence(host.get('evidence'))}"
            )
        remaining_hosts = len(hosts) - _HUMAN_DISCOVERY_ITEM_LIMIT
        if remaining_hosts > 0:
            lines.append(f"... and {remaining_hosts} more host evidence rows.")
    else:
        lines.append("No positive host evidence was collected.")

    local_host_count = int(summary.get("local_machine", 0))
    responsive_host_count = int(summary.get("confirmed_responsive", 0))
    cache_host_count = int(summary.get("known_neighbor", 0))
    routing_only_host_count = int(summary.get("confirmed_gateway", 0))
    total_hosts = (
        local_host_count
        + responsive_host_count
        + cache_host_count
        + routing_only_host_count
    )
    host_record_label = "host record" if total_hosts == 1 else "host records"
    host_classifications = (
        f"{local_host_count} local machine, "
        f"{responsive_host_count} responsive, "
        f"{cache_host_count} cache-only"
    )
    if routing_only_host_count:
        host_classifications += (
            f", {routing_only_host_count} routing-evidence-only"
        )
    gateway_role_count = len(confirmed_gateways)
    lines.extend(
        [
            "",
            (
                f"{total_hosts} {host_record_label}: {host_classifications}."
            ),
            (
                f"Confirmed gateway roles: {gateway_role_count} "
                f"({_format_bounded_discovery_items(confirmed_gateways)}); "
                "role counts may overlap host classifications."
            ),
            (
                f"Probe outcomes (aggregated): {summary.get('addresses_probed', 0)} attempted; "
                f"{response_count} {response_label}; "
                f"{summary.get('no_response_observed', 0)} without an observed reply; "
                f"{summary.get('probe_timeouts', 0)} timed out; "
                f"{summary.get('probe_unavailable', 0)} unavailable; "
                f"{error_count} {error_label}."
            ),
            (
                "Neighbor/cache evidence: "
                f"{neighbor_cache.get('status', 'unavailable')}"
                + (
                    f" ({neighbor_cache['detail']})"
                    if neighbor_cache.get("detail")
                    else ""
                )
                + "."
            ),
            "Hostnames: not collected (unavailable metadata; reverse DNS is disabled).",
            (
                "Addresses that did not respond (terminal preview): "
                f"{_format_bounded_discovery_items(addresses_without_response)}"
            ),
            (
                "Addresses with unavailable or failed probes: "
                f"{_format_bounded_discovery_items(addresses_with_probe_errors)}"
            ),
            "Evidence sources: ICMP reachability, local interface data, local neighbor/cache records, and local default-route records only.",
            "Incomplete collection sources:",
            *(
                f"- {item.get('source', 'unavailable')}: {item.get('status', 'unavailable')}"
                + (f" ({item['detail']})" if item.get("detail") else "")
                for item in incomplete_evidence.get("sources", [])
                if isinstance(item, dict)
            ),
            *(
                ["- none recorded"]
                if not incomplete_evidence.get("sources", [])
                else []
            ),
            "Privacy: review this private network inventory before storing or sharing it.",
            "Limitations:",
            *(f"- {item}" for item in limitations),
            "Safety boundary: Discovery does not authorize port scanning or any other additional network activity.",
        ]
    )
    return "\n".join(lines)


def _show_discovery_error(
    status: str,
    message: str,
    *,
    json_output: bool,
    candidates: list[dict[str, object]] | None = None,
    probes_started: bool | None = False,
) -> None:
    """Show a discovery error in the selected output format."""
    if json_output:
        payload: dict[str, object] = {
            "schema_version": DISCOVERY_SCHEMA_VERSION,
            "status": status,
            "message": message,
        }
        if probes_started is not None:
            payload["probes_started"] = probes_started
        if candidates is not None:
            payload["candidates"] = candidates
        print(json.dumps(payload, indent=2, sort_keys=True))
        return

    print(f"driftbox: discover: {message}", file=sys.stderr)
    if candidates:
        print("Suitable candidates (no probes were started):", file=sys.stderr)
        for candidate in candidates:
            interfaces = ", ".join(candidate["interfaces"]) or "unavailable"
            local_addresses = ", ".join(candidate["local_addresses"]) or "unavailable"
            print(
                f"  {candidate['cidr']}  interfaces: {interfaces}; "
                f"local addresses: {local_addresses}",
                file=sys.stderr,
            )
        print(
            "Choose one explicitly, for example: driftbox discover CIDR",
            file=sys.stderr,
        )


def run_network_discovery(
    cidr: str | None = None,
    *,
    json_output: bool = False,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    workers: int = DEFAULT_WORKERS,
) -> int:
    """Safely resolve, run, and present authorized network discovery."""
    try:
        candidates = detect_local_network_candidates() if cidr is None else None
        target = resolve_target(cidr, candidates=candidates)
        report = discover_network(
            target,
            timeout_seconds=timeout_seconds,
            workers=workers,
        )
        report = with_discovery_interpretation(report)
        interpretation = report["interpretation"]
        if not isinstance(interpretation, dict):
            raise ValueError("Discovery interpretation is malformed.")
        recommendations = interpretation.get("recommendations")
        if not isinstance(recommendations, list):
            raise ValueError("Discovery recommendations are malformed.")
        parser = build_parser()
        validate_recommendation_commands(recommendations, parser.parse_args)
    except TargetValidationError as error:
        _show_discovery_error("invalid_request", str(error), json_output=json_output)
        return 2
    except CandidateSelectionRequired as error:
        candidate_data = [candidate.as_dict() for candidate in error.candidates]
        _show_discovery_error(
            "selection_required",
            str(error),
            json_output=json_output,
            candidates=candidate_data,
        )
        return 3
    except (NoSuitableNetworkError, DiscoveryOperationalError) as error:
        _show_discovery_error("unavailable", str(error), json_output=json_output)
        return 4
    except Exception as error:
        _show_discovery_error(
            "unavailable",
            f"Discovery could not operate safely: {error}",
            json_output=json_output,
            probes_started=None,
        )
        return 4

    try:
        if json_output:
            output = json.dumps(report, indent=2, sort_keys=True)
        else:
            output = format_network_discovery(report)
        print(output)
        return 4 if report.get("collection_status") == "unavailable" else 0
    except Exception as error:
        _show_command_error("discover output", error)
        return 4


def _service_attribute(value: object, name: str, default: object = None) -> object:
    """Read a dataclass or mapping adapter value without accepting surprises."""
    if isinstance(value, dict):
        return value.get(name, default)
    return getattr(value, name, default)


def _timestamp_text(value: object) -> str:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    if isinstance(value, str) and value:
        return value
    raise ValueError("Nmap returned malformed timestamp evidence.")


def _service_inventory_report(
    target: str,
    top_ports: int,
    result: object,
) -> dict[str, object]:
    """Build the public, bounded service-inventory transport document."""
    installation = _service_attribute(result, "installation")
    parsed = _service_attribute(result, "parsed")
    command = _service_attribute(result, "command")
    host = _service_attribute(parsed, "host")
    services = _service_attribute(parsed, "services")
    incomplete = _service_attribute(parsed, "evidence_incomplete")
    incomplete_reasons = _service_attribute(parsed, "incomplete_reasons")
    nmap_xml_version = _service_attribute(parsed, "nmap_xml_version")
    if not isinstance(host, dict) or not isinstance(services, (list, tuple)):
        raise ValueError("Nmap returned malformed service evidence.")
    if not isinstance(incomplete, bool) or not isinstance(
        incomplete_reasons, (list, tuple)
    ):
        raise ValueError("Nmap returned malformed evidence completeness metadata.")
    if not isinstance(command, (list, tuple)) or any(
        not isinstance(item, str) for item in command
    ):
        raise ValueError("Nmap returned malformed command evidence.")
    version = _service_attribute(installation, "version")
    executable = _service_attribute(installation, "executable")
    if not isinstance(version, str) or not isinstance(executable, str):
        raise ValueError("Nmap installation metadata is malformed.")
    expected_command = build_nmap_command(executable, target, top_ports)
    if list(command) != expected_command:
        raise ValueError("Nmap returned unexpected scan-profile evidence.")
    if nmap_xml_version is not None and not isinstance(nmap_xml_version, str):
        raise ValueError("Nmap returned malformed XML-version evidence.")
    normalized_services = [
        dict(item) for item in services if isinstance(item, dict)
    ]
    if len(normalized_services) != len(services):
        raise ValueError("Nmap returned malformed service evidence.")
    normalized_services.sort(
        key=lambda item: (str(item.get("protocol", "")), int(item.get("port", 0)))
    )
    if len(normalized_services) > top_ports:
        raise ValueError("Nmap returned more services than the selected port scope.")
    reasons = sorted(str(reason) for reason in incomplete_reasons)
    status = "partial" if incomplete else "completed"
    started_at = _timestamp_text(_service_attribute(result, "started_at"))
    completed_at = _timestamp_text(_service_attribute(result, "completed_at"))
    if _service_attribute(result, "exit_code") != 0:
        raise ValueError("Nmap returned unexpected successful-execution metadata.")
    return {
        "schema_version": SERVICE_INVENTORY_SCHEMA_VERSION,
        "driftbox_version": __version__,
        "generated_at": completed_at,
        "target": {"address": target, "canonical_numeric_ipv4": True},
        "authorization": {
            "confirmed": True,
            "confirmation_flag": "--confirm-authorization",
            "statement": (
                "The operator confirmed authorization for this exact target. "
                "Private addressing does not prove authorization."
            ),
        },
        "nmap": {
            "version": version,
            "xml_version": nmap_xml_version,
            "installation": "operator-installed executable detected",
        },
        "scan_profile": {
            "classification": "active authorized single-device service inventory",
            "protocol": "tcp",
            "tcp_connect_scan": True,
            "dns_resolution": "disabled",
            "host_discovery": "disabled",
            "arp_host_discovery": "disabled",
            "privilege_mode": "unprivileged",
            "service_detection": "lightweight version detection",
            "scripts": "disabled",
            "os_detection": "disabled",
            "udp_scanning": "disabled",
            "xml_output": "standard output",
            "top_ports": top_ports,
            "host_timeout_seconds": 60,
            # Keep the transparent fixed profile without publishing an
            # operator-specific absolute installation path in saved JSON.
            "arguments": ["nmap", *list(command)[1:]],
        },
        "execution": {
            "status": status,
            "started_at": started_at,
            "completed_at": completed_at,
            "exit_code": 0,
        },
        "port_scope": {
            "protocol": "tcp",
            "selection": "Nmap top common TCP ports",
            "ports_examined": top_ports,
        },
        "host": dict(host),
        "services": normalized_services,
        "evidence": {"incomplete": incomplete, "incomplete_reasons": reasons},
        "limitations": [
            "Only the selected common TCP ports were examined.",
            "Nmap service and version labels are evidence, not guaranteed identity.",
            "Open services are not automatically vulnerable or malicious.",
            "Firewalls, filtering, and network conditions can affect observations.",
            "This scan does not establish internet reachability.",
            "Vulnerability correlation is not performed by this service-inventory command.",
        ],
    }


def format_service_inventory(report: dict[str, object]) -> str:
    """Render bounded, plain-English service evidence for an operator."""
    interpretation = build_service_inventory_interpretation(report)
    target = report.get("target", {})
    nmap = report.get("nmap", {})
    profile = report.get("scan_profile", {})
    execution = report.get("execution", {})
    host = report.get("host", {})
    evidence = report.get("evidence", {})
    services = report.get("services", [])
    report_sections = (target, nmap, profile, execution, host, evidence)
    if not all(isinstance(item, dict) for item in report_sections) or not isinstance(
        services, list
    ):
        raise ValueError("Service inventory report is malformed.")
    summary = interpretation.get("service_summary")
    meaning = interpretation.get("what_this_means")
    recognized = interpretation.get("recognized_common_services")
    bottom_line = interpretation.get("bottom_line")
    limitations = interpretation.get("limitations")
    recommendations = interpretation.get("recommendations")
    if (
        not isinstance(summary, dict)
        or not isinstance(meaning, list)
        or not isinstance(recognized, list)
        or not isinstance(bottom_line, str)
        or not isinstance(limitations, list)
        or not isinstance(recommendations, list)
    ):
        raise ValueError("Service inventory interpretation is malformed.")

    recognized_by_key = {
        (
            item.get("protocol"),
            item.get("port"),
            item.get("observed_name").casefold()
            if isinstance(item.get("observed_name"), str)
            else None,
        ): item.get("explanation")
        for item in recognized
        if isinstance(item, dict) and isinstance(item.get("explanation"), str)
    }

    def display_service_value(value: object) -> str:
        if value is None or value == "" or value == []:
            return "unavailable"
        if isinstance(value, list):
            return sanitize_display(", ".join(str(item) for item in value))
        return sanitize_display(value)

    lines = [
        "driftbox :: authorized single-device service inventory",
        "",
        "SERVICE INVENTORY SUMMARY",
        "-------------------------",
        f"Target: {target.get('address', 'unavailable')}",
        "Authorization confirmation: yes (--confirm-authorization). "
        "Private addressing does not prove authorization.",
        f"Nmap version: {sanitize_display(nmap.get('version', 'unavailable'))}",
        "Scan profile: active authorized TCP connect scan; no DNS; no host "
        "discovery; lightweight service version detection.",
        "TCP ports examined: "
        f"{profile.get('top_ports', 'unavailable')} (common-port scope)",
        f"Completion status: {execution.get('status', 'unavailable')}",
        f"Open ports: {summary.get('open_port_count', 'unavailable')}",
        "Evidence incomplete: " + ("yes" if evidence.get("incomplete") is True else "no"),
        "",
        "WHAT THIS MEANS",
        "---------------",
        *(f"- {sanitize_display(item, maximum=240)}" for item in meaning),
        "",
        "SERVICE EVIDENCE",
        "----------------",
    ]
    if not services:
        lines.append(
            "No reported open ports in the selected common TCP-port scope."
        )
    for item in services:
        service = item.get("service", {})
        if not isinstance(service, dict):
            service = {}
        port = item.get("port", "unavailable")
        protocol = sanitize_display(item.get("protocol", "unknown"))
        state = sanitize_display(item.get("state", "unknown"))
        reason = sanitize_display(item.get("reason", "unavailable"))
        method = display_service_value(service.get("method", "unavailable"))
        confidence = display_service_value(
            service.get("confidence", "unavailable")
        )
        service_name = service.get("name", "unknown")
        service_lines = [
            f"{protocol}/{port}",
            f"  State/reason: {state} / {reason}",
            f"  Service name: {display_service_value(service_name)}",
        ]
        association = recognized_by_key.get(
            (
                str(item.get("protocol", "")).casefold(),
                port,
                service_name.casefold() if isinstance(service_name, str) else None,
            )
        )
        if isinstance(association, str):
            service_lines.append(
                f"  Common association: {sanitize_display(association, maximum=240)}"
            )
        service_lines.extend(
            [
                "  Product: "
                f"{display_service_value(service.get('product', 'unavailable'))}",
                "  Version: "
                f"{display_service_value(service.get('version', 'unavailable'))}",
                "  Extra information: "
                f"{display_service_value(service.get('extrainfo', 'unavailable'))}",
                "  Tunnel/TLS: "
                f"{display_service_value(service.get('tunnel', 'unavailable'))}",
                f"  CPE: {display_service_value(service.get('cpe', 'unavailable'))}",
                f"  Detection method/confidence: {method} / {confidence}",
            ]
        )
        lines.extend(service_lines)
    reasons = evidence.get("incomplete_reasons", [])
    if evidence.get("incomplete") is True:
        reason_text = (
            ", ".join(sanitize_display(reason) for reason in reasons)
            if isinstance(reasons, list) and reasons
            else "unavailable"
        )
        lines.append(f"Incomplete evidence reasons: {reason_text}")
    lines.extend(
        [
            "",
            "BOTTOM LINE",
            "-----------",
            sanitize_display(bottom_line, maximum=1_200),
            "",
            "RECOMMENDED NEXT STEPS",
            "----------------------",
            "Recommendations are suggestions only; Driftbox never executes them "
            "automatically.",
        ]
    )
    for recommendation in recommendations:
        if not isinstance(recommendation, dict):
            continue
        availability = recommendation.get("availability", {})
        if not isinstance(availability, dict):
            availability = {}
        activity = recommendation.get("activity_level", "unavailable")
        recommendation_lines = [
            f"{recommendation.get('rank', 'unavailable')}. "
            f"[{sanitize_display(activity)}] "
            f"{sanitize_display(recommendation.get('command', 'unavailable'), maximum=300)}",
            "   "
            f"{sanitize_display(recommendation.get('purpose', 'unavailable'), maximum=360)}",
            "   Scope: "
            f"{sanitize_display(availability.get('condition', 'unavailable'), maximum=360)}",
        ]
        if activity == "ACTIVE AUTHORIZED SCAN":
            recommendation_lines.append(
                "   Authorization: "
                f"{sanitize_display(recommendation.get('authorization_required', 'unavailable'), maximum=360)}"
            )
        lines.extend(recommendation_lines)
    lines.extend(
        [
            "",
            "LIMITATIONS",
            "-----------",
            *(f"- {sanitize_display(item, maximum=240)}" for item in limitations),
        ]
    )
    return "\n".join(lines)


def _show_service_inventory_error(
    status: str,
    message: str,
    *,
    json_output: bool,
    scan_started: bool = False,
) -> None:
    """Present stable service-inventory errors without exposing a traceback."""
    if json_output:
        print(
            json.dumps(
                {
                    "schema_version": SERVICE_INVENTORY_SCHEMA_VERSION,
                    "status": status,
                    "message": message,
                    "scan_started": scan_started,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return
    print(f"driftbox: services: {message}", file=sys.stderr)


def run_service_inventory(
    target_text: str,
    *,
    authorization_confirmed: bool,
    json_output: bool = False,
    top_ports: object = DEFAULT_TOP_PORTS,
) -> int:
    """Authorize, run one bounded Nmap scan, and render evidence."""
    scan_completed = False
    try:
        if not authorization_confirmed:
            raise AuthorizationRequiredError(
                "Refused: --confirm-authorization is required for an active scan. "
                "Private addressing does not prove authorization."
            )
        target = validate_service_target(target_text)
        ports = validate_top_ports(top_ports)
        result = NmapAdapter().scan(target, top_ports=ports)
        scan_completed = True
        report = with_service_inventory_interpretation(
            _service_inventory_report(target, ports, result)
        )
        recommendations = report["interpretation"].get("recommendations")
        if not isinstance(recommendations, list):
            raise ValueError("Service inventory recommendations are malformed.")
        validate_service_recommendation_commands(
            recommendations, build_parser().parse_args
        )
    except AuthorizationRequiredError as error:
        _show_service_inventory_error(
            "authorization_required", str(error), json_output=json_output
        )
        return 2
    except (ServiceTargetValidationError, TopPortsValidationError) as error:
        _show_service_inventory_error(
            "invalid_request", str(error), json_output=json_output
        )
        return 2
    except NmapUnavailableError as error:
        _show_service_inventory_error(
            "nmap_unavailable", str(error), json_output=json_output
        )
        return 4
    except NmapExecutionTimeoutError as error:
        _show_service_inventory_error(
            "nmap_timeout", str(error), json_output=json_output, scan_started=True
        )
        return 4
    except NmapExecutionError as error:
        _show_service_inventory_error(
            "nmap_failed", str(error), json_output=json_output, scan_started=True
        )
        return 4
    except (NmapXMLSecurityError, NmapXMLParseError) as error:
        _show_service_inventory_error(
            "invalid_evidence",
            str(error),
            json_output=json_output,
            scan_started=True,
        )
        return 4
    except Exception as error:
        _show_service_inventory_error(
            "unavailable",
            f"Service inventory could not operate safely: {error}",
            json_output=json_output,
            scan_started=scan_completed,
        )
        return 4
    try:
        print(
            json.dumps(report, indent=2, sort_keys=True)
            if json_output
            else format_service_inventory(report)
        )
    except Exception as error:
        _show_command_error("services output", error)
        return 4
    return 0


def _show_vulnerability_error(
    status: str,
    message: str,
    *,
    json_output: bool,
    source_status: object | None = None,
) -> None:
    """Present stable vulnerability-analysis errors without source secrets."""
    if json_output:
        payload: dict[str, object] = {
            "schema_version": VULNERABILITY_ANALYSIS_SCHEMA_VERSION,
            "status": status,
            "message": message,
        }
        if isinstance(source_status, dict):
            payload["source_status"] = source_status
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    print(f"driftbox: vulnerabilities: {message}", file=sys.stderr)


def run_vulnerability_intelligence(
    report_path: str,
    *,
    json_output: bool = False,
    offline: bool = False,
    refresh: bool = False,
    coordinator: object | None = None,
) -> int:
    """Correlate one validated saved service report with official sources.

    Loading, complete transport validation, and eligibility planning all finish
    before a source coordinator is constructed.  An ineligible report therefore
    cannot produce an HTTP or cache request.
    """
    if offline and refresh:
        _show_vulnerability_error(
            "conflicting_options",
            "--offline and --refresh cannot be used together.",
            json_output=json_output,
        )
        return 2

    try:
        service_report = load_service_inventory_report(report_path)
        lookup_plan = build_lookup_plan(service_report)
    except (ServiceReportValidationError, VulnerabilityAnalysisError) as error:
        _show_vulnerability_error(
            "invalid_input",
            str(error),
            json_output=json_output,
        )
        return 2
    except Exception:
        _show_vulnerability_error(
            "invalid_input",
            "Service report validation could not complete safely.",
            json_output=json_output,
        )
        return 2

    provenance = {
        "nvd": {
            "api": NVD_API_URL,
            "detail_template": f"{NVD_DETAIL_URL}CVE-ID",
        },
        "cisa_kev": {
            "json": CISA_KEV_URL,
            "catalog": CISA_KEV_CATALOG_URL,
        },
    }
    source_status: dict[str, object] = {
        "nvd": {"state": "not-requested", "by_cpe": {}},
        "cisa-kev": {"state": "not-requested"},
    }
    nvd_by_cpe: dict[str, object] = {}
    kev: dict[str, object] = {}
    source_candidate_summary: dict[str, object] | None = None
    queries = lookup_plan.get("queries")
    if not isinstance(queries, list):
        _show_vulnerability_error(
            "invalid_input",
            "Service evidence eligibility could not be represented safely.",
            json_output=json_output,
        )
        return 2

    if queries:
        cpes = [
            query.get("canonical_cpe")
            for query in queries
            if isinstance(query, dict)
        ]
        try:
            active_coordinator = coordinator or SourceCoordinator()
            fetch = getattr(active_coordinator, "fetch", None)
            if not callable(fetch):
                raise ValueError("source coordinator is unavailable")
            source_result = fetch(cpes, offline=offline, refresh=refresh)
            if not isinstance(source_result, dict):
                raise ValueError("source result is malformed")
            raw_status = source_result.get("sources")
            raw_nvd = source_result.get("nvd_by_cpe")
            raw_kev = source_result.get("kev")
            raw_candidate_summary = source_result.get("candidate_summary")
            if (
                not isinstance(raw_status, dict)
                or not isinstance(raw_nvd, dict)
                or not isinstance(raw_kev, dict)
                or not isinstance(raw_candidate_summary, dict)
            ):
                raise ValueError("source result is malformed")
            source_status = raw_status
            nvd_by_cpe = raw_nvd
            kev = raw_kev
            source_candidate_summary = raw_candidate_summary
            if source_result.get("usable") is not True:
                _show_vulnerability_error(
                    "sources_unavailable",
                    "No usable authoritative or cached vulnerability evidence is available.",
                    json_output=json_output,
                    source_status=source_status,
                )
                return 4
        except Exception:
            _show_vulnerability_error(
                "sources_unavailable",
                "Authoritative vulnerability sources could not operate safely.",
                json_output=json_output,
                source_status=source_status,
            )
            return 4

    try:
        analysis = build_vulnerability_analysis_report(
            service_report,
            nvd_by_cpe,
            kev,
            source_status=source_status,
            provenance=provenance,
            source_candidate_summary=source_candidate_summary,
        )
        rendered = (
            json.dumps(analysis, indent=2, sort_keys=True)
            if json_output
            else format_vulnerability_analysis(analysis)
        )
        print(rendered)
    except Exception:
        try:
            _show_vulnerability_error(
                "output_failure",
                "Vulnerability analysis output could not be produced safely.",
                json_output=json_output,
                source_status=source_status,
            )
        except Exception:
            pass
        return 4
    candidates = analysis.get("candidates")
    return 1 if isinstance(candidates, list) and candidates else 0


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
    discover_parser = commands.add_parser(
        "discover",
        help="Discover host evidence on an authorized private IPv4 network",
        description=(
            "Use bounded, unprivileged host discovery only on a private IPv4 "
            "network you own or have explicit permission to inspect."
        ),
    )
    discover_parser.add_argument(
        "cidr",
        nargs="?",
        metavar="CIDR",
        help=(
            "Canonical private IPv4 CIDR; omit to detect safe local candidates"
        ),
    )
    discover_parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Write a schema-versioned machine-readable discovery result",
    )
    discover_parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        metavar="SECONDS",
        help=(
            f"Per-command timeout, safely bounded to {MIN_TIMEOUT_SECONDS}-"
            f"{MAX_TIMEOUT_SECONDS} seconds (default: {DEFAULT_TIMEOUT_SECONDS})"
        ),
    )
    discover_parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        metavar="N",
        help=(
            f"Concurrent probe workers, safely bounded to {MIN_WORKERS}-"
            f"{MAX_WORKERS} (default: {DEFAULT_WORKERS})"
        ),
    )
    services_parser = commands.add_parser(
        "services",
        help="Inventory common TCP services on one authorized private IPv4 device",
        description=(
            "Run a bounded active TCP connect scan only against one private, "
            "loopback, or link-local IPv4 device you are explicitly authorized to inspect."
        ),
    )
    services_parser.add_argument(
        "target",
        metavar="TARGET",
        help="Exactly one canonical numeric IPv4 address; no hostname, CIDR, range, or public address",
    )
    services_parser.add_argument(
        "--confirm-authorization",
        action="store_true",
        dest="authorization_confirmed",
        help="Confirm you are authorized to actively scan this exact target",
    )
    services_parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Write schema-versioned service inventory evidence to standard output",
    )
    services_parser.add_argument(
        "--top-ports",
        default=DEFAULT_TOP_PORTS,
        metavar="NUMBER",
        help="Common TCP port scope, 1-1000 (default: 100)",
    )
    vulnerabilities_parser = commands.add_parser(
        "vulnerabilities",
        help="Correlate saved exact service evidence with NVD and CISA KEV",
        description=(
            "Validate a saved Driftbox service-inventory JSON report and "
            "cautiously correlate only exact, high-confidence CPE evidence. "
            "This command does not scan the target or execute recommendations."
        ),
    )
    vulnerabilities_parser.add_argument(
        "service_report",
        metavar="SERVICE_REPORT.json",
        help="Previously created Driftbox service-inventory JSON report",
    )
    vulnerabilities_parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Write complete bounded schema-versioned correlation evidence",
    )
    vulnerability_source_mode = vulnerabilities_parser.add_mutually_exclusive_group()
    vulnerability_source_mode.add_argument(
        "--offline",
        action="store_true",
        help="Make zero network requests and use only valid cache entries",
    )
    vulnerability_source_mode.add_argument(
        "--refresh",
        action="store_true",
        help="Bypass fresh-cache reuse and request current official source data",
    )
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
    mission_parser = commands.add_parser(
        "mission",
        help="Play isolated synthetic cybersecurity training missions",
    )
    mission_commands = mission_parser.add_subparsers(
        dest="mission_command",
        required=True,
    )
    mission_list = mission_commands.add_parser("list", help="List missions")
    mission_list.add_argument("--json", action="store_true", dest="json_output")
    mission_start = mission_commands.add_parser("start", help="Start a mission")
    mission_start.add_argument("mission", help="Mission identifier")
    mission_commands.add_parser("brief", help="Show the active mission brief")
    mission_commands.add_parser("status", help="Show active mission progress")
    mission_commands.add_parser("hint", help="Request the next progressive hint")
    mission_commands.add_parser("submit", help="Submit findings for scoring")
    mission_commands.add_parser("reset", help="Reset the active mission session")

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
    elif args.command == "discover":
        return run_network_discovery(
            args.cidr,
            json_output=args.json_output,
            timeout_seconds=args.timeout,
            workers=args.workers,
        )
    elif args.command == "services":
        return run_service_inventory(
            args.target,
            authorization_confirmed=args.authorization_confirmed,
            json_output=args.json_output,
            top_ports=args.top_ports,
        )
    elif args.command == "vulnerabilities":
        return run_vulnerability_intelligence(
            args.service_report,
            json_output=args.json_output,
            offline=args.offline,
            refresh=args.refresh,
        )
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
    elif args.command == "mission":
        return run_mission_command(args)
    else:
        parser.print_help()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
