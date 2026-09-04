"""Bounded, authorized discovery of hosts on private IPv4 networks.

This module deliberately provides host discovery only.  It does not scan ports,
resolve hostnames, use raw sockets, or require administrator privileges.  Every
address passed to an operating-system command is first parsed as an allowlisted
IPv4 address and is then supplied as one argument with ``shell=False``.

The orchestration functions accept adapters and interface data so tests and
other callers can run without touching a live network.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import platform
import re
import socket
import subprocess
from typing import Callable, Iterable, Mapping, Protocol, Sequence

import psutil


# Version 2 adds ordered per-address probe outcomes and an explicitly scoped,
# read-only default-gateway evidence source.  Host reachability semantics remain
# unchanged.
SCHEMA_VERSION = 2
MAX_TARGET_ADDRESSES = 256

MIN_WORKERS = 1
MAX_WORKERS = 32
DEFAULT_WORKERS = 16

MIN_TIMEOUT_SECONDS = 0.1
MAX_TIMEOUT_SECONDS = 2.0
DEFAULT_TIMEOUT_SECONDS = 0.75

_ALLOWED_NETWORKS = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("169.254.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),
)
_POSITIVE_LINUX_NEIGHBOR_STATES = {
    "reachable",
    "stale",
    "delay",
    "probe",
    "permanent",
    "noarp",
}
_MAC_ADDRESS_PATTERN = re.compile(
    r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f])"
)
_WINDOWS_ARP_ENTRY_PATTERN = re.compile(
    r"^\s*(?P<address>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(?P<mac>(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})\s+"
    r"(?P<state>dynamic|static)\s*$",
    re.IGNORECASE,
)
_BSD_ARP_ENTRY_PATTERN = re.compile(
    r"^\s*\S+\s+\((?P<address>\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+"
    r"(?P<mac>(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})"
    r"(?:\s+\[[^\]]+\])?\s+on\s+\S+",
    re.IGNORECASE,
)


class NetworkDiscoveryError(Exception):
    """Base class for expected network-discovery failures."""


class TargetValidationError(NetworkDiscoveryError, ValueError):
    """Raised when a requested target is malformed or outside the safe scope."""


class CandidateSelectionRequired(NetworkDiscoveryError):
    """Raised when several safe local networks require an explicit choice."""

    def __init__(self, candidates: Sequence["NetworkCandidate"]) -> None:
        self.candidates = tuple(candidates)
        super().__init__(
            "Multiple suitable private IPv4 networks were found; select one "
            "explicitly by CIDR."
        )


class NoSuitableNetworkError(NetworkDiscoveryError):
    """Raised when omitted-target discovery has no safe local candidate."""


class DiscoveryOperationalError(NetworkDiscoveryError):
    """Raised when discovery cannot start because local inspection failed."""


@dataclass(frozen=True)
class NetworkCandidate:
    """A bounded private network derived from one or more active interfaces."""

    network: ipaddress.IPv4Network
    interfaces: tuple[str, ...]
    local_addresses: tuple[ipaddress.IPv4Address, ...]

    def as_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-compatible candidate representation."""
        return {
            "cidr": str(self.network),
            "interfaces": list(self.interfaces),
            "local_addresses": [str(address) for address in self.local_addresses],
        }


@dataclass(frozen=True)
class ProbeResult:
    """The honest outcome of one unprivileged reachability probe."""

    status: str
    detail: str | None = None

    def __post_init__(self) -> None:
        allowed = {"responsive", "no_response", "timeout", "unavailable", "error"}
        if self.status not in allowed:
            raise ValueError(f"Unsupported probe status: {self.status}")


@dataclass(frozen=True)
class NeighborRecord:
    """One address learned from an operating-system neighbor or ARP cache."""

    address: ipaddress.IPv4Address
    source: str
    mac_address: str | None = None
    state: str | None = None


@dataclass(frozen=True)
class NeighborSnapshot:
    """Neighbor-cache records and their collection availability."""

    status: str
    records: tuple[NeighborRecord, ...] = ()
    detail: str | None = None

    def __post_init__(self) -> None:
        if self.status not in {"available", "unavailable", "error", "timeout"}:
            raise ValueError(f"Unsupported neighbor snapshot status: {self.status}")


@dataclass(frozen=True)
class GatewayRecord:
    """A default gateway explicitly reported by the local routing table."""

    address: ipaddress.IPv4Address
    interface: str | None = None
    metric: int | None = None


@dataclass(frozen=True)
class GatewaySnapshot:
    """Default-route records and availability of their local collection."""

    status: str
    records: tuple[GatewayRecord, ...] = ()
    detail: str | None = None

    def __post_init__(self) -> None:
        if self.status not in {"available", "unavailable", "error", "timeout"}:
            raise ValueError(f"Unsupported gateway snapshot status: {self.status}")


class DiscoveryAdapter(Protocol):
    """Testable boundary around operating-system network commands."""

    def ping(
        self,
        address: ipaddress.IPv4Address,
        timeout_seconds: float,
    ) -> ProbeResult:
        """Probe one validated address without raw sockets or elevated access."""

    def neighbors(self, timeout_seconds: float) -> NeighborSnapshot:
        """Read locally cached neighbor evidence without sending traffic."""

    def default_gateways(self, timeout_seconds: float) -> GatewaySnapshot:
        """Read locally configured default routes without sending traffic."""


CompletedCommand = subprocess.CompletedProcess[str]
CommandRunner = Callable[..., CompletedCommand]


def _is_allowed_network(network: ipaddress.IPv4Network) -> bool:
    return any(network.subnet_of(allowed) for allowed in _ALLOWED_NETWORKS)


def _is_allowed_address(address: ipaddress.IPv4Address) -> bool:
    return any(address in allowed for allowed in _ALLOWED_NETWORKS)


def validate_target(
    target: str | ipaddress.IPv4Network,
) -> ipaddress.IPv4Network:
    """Validate a canonical, bounded, allowlisted private IPv4 CIDR.

    Hostnames and bare IP addresses are intentionally not accepted.  Requiring a
    canonical CIDR prevents host bits from silently expanding the requested
    scope.  The whole range must fit in exactly one approved address family:
    RFC1918, IPv4 link-local, or IPv4 loopback.
    """
    if isinstance(target, ipaddress.IPv4Network):
        network = target
    elif isinstance(target, str):
        if target != target.strip() or "/" not in target:
            raise TargetValidationError(
                "Target must be a canonical numeric IPv4 CIDR, such as "
                "192.168.1.0/24; hostnames and bare addresses are not accepted."
            )
        try:
            parsed = ipaddress.ip_network(target, strict=True)
        except ValueError as exc:
            raise TargetValidationError(
                "Target must be a canonical numeric IPv4 CIDR with no host bits set."
            ) from exc
        if not isinstance(parsed, ipaddress.IPv4Network):
            raise TargetValidationError("IPv6 discovery is not supported in this version.")
        network = parsed
    else:
        raise TargetValidationError("Target must be provided as an IPv4 CIDR string.")

    if not _is_allowed_network(network):
        raise TargetValidationError(
            "Target must be wholly contained in RFC1918 private, IPv4 link-local, "
            "or IPv4 loopback space. Public, reserved, and mixed ranges are refused."
        )
    if network.num_addresses > MAX_TARGET_ADDRESSES:
        raise TargetValidationError(
            f"Target contains {network.num_addresses} addresses; the maximum is "
            f"{MAX_TARGET_ADDRESSES}. Select a smaller authorized subnet."
        )
    return network


def clamp_timeout(timeout_seconds: float) -> float:
    """Return a finite probe timeout within Driftbox's short safety bounds."""
    if isinstance(timeout_seconds, bool):
        raise TargetValidationError("Timeout must be a number of seconds.")
    try:
        value = float(timeout_seconds)
    except (TypeError, ValueError) as exc:
        raise TargetValidationError("Timeout must be a number of seconds.") from exc
    if value != value or value in {float("inf"), float("-inf")}:
        raise TargetValidationError("Timeout must be a finite number of seconds.")
    return min(MAX_TIMEOUT_SECONDS, max(MIN_TIMEOUT_SECONDS, value))


def clamp_workers(workers: int) -> int:
    """Return a worker count within the fixed concurrency safety bounds."""
    if isinstance(workers, bool):
        raise TargetValidationError("Worker count must be an integer.")
    try:
        value = int(workers)
    except (TypeError, ValueError) as exc:
        raise TargetValidationError("Worker count must be an integer.") from exc
    if value != workers:
        raise TargetValidationError("Worker count must be an integer.")
    return min(MAX_WORKERS, max(MIN_WORKERS, value))


def _interface_data(
    addresses_provider: Callable[[], Mapping[str, Sequence[object]]],
    stats_provider: Callable[[], Mapping[str, object]],
) -> tuple[Mapping[str, Sequence[object]], Mapping[str, object]]:
    try:
        return addresses_provider(), stats_provider()
    except (OSError, RuntimeError, psutil.Error) as exc:
        raise DiscoveryOperationalError(
            "Local network interfaces could not be inspected without elevated access."
        ) from exc


def detect_local_network_candidates(
    *,
    addresses_provider: Callable[[], Mapping[str, Sequence[object]]] = psutil.net_if_addrs,
    stats_provider: Callable[[], Mapping[str, object]] = psutil.net_if_stats,
) -> list[NetworkCandidate]:
    """Return suitable bounded networks from active, non-loopback interfaces.

    Malformed interface records are ignored.  Duplicate networks are merged and
    results are ordered numerically so CLI selection is stable.
    """
    interface_addresses, interface_stats = _interface_data(
        addresses_provider, stats_provider
    )
    grouped: dict[
        ipaddress.IPv4Network,
        tuple[set[str], set[ipaddress.IPv4Address]],
    ] = {}

    for interface_name in sorted(interface_addresses):
        stats = interface_stats.get(interface_name)
        if stats is None or not bool(getattr(stats, "isup", False)):
            continue
        for record in interface_addresses[interface_name]:
            if getattr(record, "family", None) != socket.AF_INET:
                continue
            address_text = getattr(record, "address", None)
            netmask_text = getattr(record, "netmask", None)
            if not address_text or not netmask_text:
                continue
            try:
                interface = ipaddress.IPv4Interface(f"{address_text}/{netmask_text}")
            except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
                continue
            if interface.ip.is_loopback:
                continue
            try:
                network = validate_target(interface.network)
            except TargetValidationError:
                continue
            interfaces, local_addresses = grouped.setdefault(network, (set(), set()))
            interfaces.add(interface_name)
            local_addresses.add(interface.ip)

    return [
        NetworkCandidate(
            network=network,
            interfaces=tuple(sorted(interfaces)),
            local_addresses=tuple(sorted(local_addresses)),
        )
        for network, (interfaces, local_addresses) in sorted(
            grouped.items(), key=lambda item: (int(item[0].network_address), item[0].prefixlen)
        )
    ]


def collect_local_ipv4_addresses(
    *,
    addresses_provider: Callable[[], Mapping[str, Sequence[object]]] = psutil.net_if_addrs,
) -> set[ipaddress.IPv4Address]:
    """Collect allowlisted IPv4 addresses assigned to this machine."""
    try:
        interface_addresses = addresses_provider()
    except (OSError, RuntimeError, psutil.Error):
        return set()

    result: set[ipaddress.IPv4Address] = set()
    for records in interface_addresses.values():
        for record in records:
            if getattr(record, "family", None) != socket.AF_INET:
                continue
            try:
                address = ipaddress.IPv4Address(getattr(record, "address", ""))
            except ipaddress.AddressValueError:
                continue
            if _is_allowed_address(address):
                result.add(address)
    return result


def resolve_target(
    target: str | None,
    *,
    candidates: Sequence[NetworkCandidate] | None = None,
) -> ipaddress.IPv4Network:
    """Resolve an explicit target or safely select one detected local candidate."""
    if target is not None:
        return validate_target(target)

    available = list(candidates) if candidates is not None else detect_local_network_candidates()
    if not available:
        raise NoSuitableNetworkError(
            "No active, bounded private IPv4 network was found. Provide an authorized "
            "canonical CIDR of at most 256 addresses explicitly."
        )
    if len(available) > 1:
        raise CandidateSelectionRequired(available)
    return validate_target(available[0].network)


def _safe_probe_address(
    address: ipaddress.IPv4Address | str,
) -> ipaddress.IPv4Address:
    if isinstance(address, ipaddress.IPv4Address):
        parsed = address
    elif isinstance(address, str):
        if address != address.strip():
            raise TargetValidationError("Probe address must be a canonical IPv4 address.")
        try:
            parsed = ipaddress.IPv4Address(address)
        except ipaddress.AddressValueError as exc:
            raise TargetValidationError("Probe address must be a numeric IPv4 address.") from exc
        if str(parsed) != address:
            raise TargetValidationError("Probe address must be a canonical IPv4 address.")
    else:
        raise TargetValidationError("Probe address must be a numeric IPv4 address.")
    if not _is_allowed_address(parsed):
        raise TargetValidationError("Probe address is outside the approved private scope.")
    return parsed


def parse_ip_neighbor_output(output: str) -> list[NeighborRecord]:
    """Parse Linux ``ip neighbor show`` output, ignoring malformed records."""
    records: list[NeighborRecord] = []
    for line in output.splitlines():
        fields = line.split()
        if not fields:
            continue
        try:
            address = ipaddress.IPv4Address(fields[0])
        except ipaddress.AddressValueError:
            continue
        if not _is_allowed_address(address):
            continue
        lowered = [field.lower() for field in fields]
        if "dev" not in lowered or lowered.index("dev") + 1 >= len(fields):
            continue
        state = fields[-1].lower() if fields[-1].isalpha() else None
        if state not in _POSITIVE_LINUX_NEIGHBOR_STATES:
            continue
        mac_address = None
        has_link_address = "lladdr" in lowered
        if has_link_address:
            index = lowered.index("lladdr") + 1
            if index < len(fields) and _MAC_ADDRESS_PATTERN.fullmatch(fields[index]):
                mac_address = fields[index].lower().replace("-", ":")
            else:
                continue
        # A valid link-layer address is positive cache evidence.  Linux may also
        # keep deliberate non-ARP/permanent routes without a link-layer value.
        if mac_address is None and state not in {"permanent", "noarp"}:
            continue
        records.append(
            NeighborRecord(
                address=address,
                source="ip_neighbor_cache",
                mac_address=mac_address,
                state=state,
            )
        )
    return _deduplicate_neighbors(records)


def parse_arp_output(output: str) -> list[NeighborRecord]:
    """Parse Windows or BSD ``arp`` output, ignoring malformed records."""
    records: list[NeighborRecord] = []
    for line in output.splitlines():
        windows_match = _WINDOWS_ARP_ENTRY_PATTERN.match(line)
        bsd_match = _BSD_ARP_ENTRY_PATTERN.match(line)
        match = windows_match or bsd_match
        if match is None:
            continue
        try:
            address = ipaddress.IPv4Address(match.group("address"))
        except ipaddress.AddressValueError:
            continue
        if not _is_allowed_address(address):
            continue
        mac_address = match.group("mac").lower().replace("-", ":")
        state = match.groupdict().get("state")
        if state is not None:
            state = state.lower()
        elif bsd_match is not None and re.search(
            r"\spermanent(?:\s|$)", line, re.IGNORECASE
        ):
            state = "static"
        records.append(
            NeighborRecord(
                address=address,
                source="arp_cache",
                mac_address=mac_address,
                state=state,
            )
        )
    return _deduplicate_neighbors(records)


def _gateway_record(
    address_text: str,
    *,
    interface: str | None = None,
    metric_text: str | None = None,
) -> GatewayRecord | None:
    """Build a reportable gateway record without accepting non-local scope."""
    try:
        address = ipaddress.IPv4Address(address_text)
    except ipaddress.AddressValueError:
        return None
    # Discovery remains strictly private/local.  A route to a public next hop is
    # not host evidence and must never expand the collection scope.
    if not _is_allowed_address(address) or address.is_loopback:
        return None
    metric: int | None = None
    if metric_text is not None:
        if not metric_text.isdecimal():
            return None
        metric = int(metric_text)
    cleaned_interface = interface.strip() if interface and interface.strip() else None
    if cleaned_interface and any(
        ord(character) < 32 or ord(character) == 127
        for character in cleaned_interface
    ):
        cleaned_interface = None
    return GatewayRecord(address, cleaned_interface, metric)


def _deduplicate_gateways(records: Iterable[GatewayRecord]) -> list[GatewayRecord]:
    """Return stable routing evidence without relying on command output order."""
    unique = {
        (record.address, record.interface, record.metric): record for record in records
    }
    return sorted(
        unique.values(),
        key=lambda item: (int(item.address), item.interface or "", item.metric or -1),
    )


def parse_linux_default_route_output(output: str) -> list[GatewayRecord]:
    """Parse only ``ip -4 route show default`` records with an IPv4 next hop."""
    records: list[GatewayRecord] = []
    for line in output.splitlines():
        fields = line.split()
        if not fields or fields[0] != "default":
            continue
        lowered = [field.lower() for field in fields]
        if "via" not in lowered or "dev" not in lowered:
            continue
        via_index = lowered.index("via") + 1
        dev_index = lowered.index("dev") + 1
        if via_index >= len(fields) or dev_index >= len(fields):
            continue
        metric_text = None
        if "metric" in lowered:
            metric_index = lowered.index("metric") + 1
            if metric_index >= len(fields):
                continue
            metric_text = fields[metric_index]
        record = _gateway_record(
            fields[via_index], interface=fields[dev_index], metric_text=metric_text
        )
        if record is not None:
            records.append(record)
    return _deduplicate_gateways(records)


def parse_windows_default_route_output(output: str) -> list[GatewayRecord]:
    """Parse IPv4 default rows from ``route print -4`` conservatively."""
    records: list[GatewayRecord] = []
    for line in output.splitlines():
        fields = line.split()
        # The IPv4 Active Routes table uses destination, mask, gateway,
        # interface, metric.  Requiring all five prevents header/prose matches.
        if len(fields) != 5 or fields[0] != "0.0.0.0" or fields[1] != "0.0.0.0":
            continue
        record = _gateway_record(
            fields[2], interface=fields[3], metric_text=fields[4]
        )
        if record is not None:
            records.append(record)
    return _deduplicate_gateways(records)


def parse_macos_default_route_output(output: str) -> list[GatewayRecord]:
    """Parse the structured IPv4 fields from ``route -n get default``."""
    values: dict[str, str] = {}
    for line in output.splitlines():
        match = re.match(r"^\s*(gateway|interface):\s*(\S+)\s*$", line, re.IGNORECASE)
        if match is not None:
            values[match.group(1).lower()] = match.group(2)
    gateway = values.get("gateway")
    if gateway is None:
        return []
    record = _gateway_record(gateway, interface=values.get("interface"))
    return [] if record is None else [record]


def _deduplicate_neighbors(records: Iterable[NeighborRecord]) -> list[NeighborRecord]:
    unique: dict[
        tuple[ipaddress.IPv4Address, str, str | None, str | None], NeighborRecord
    ] = {}
    for record in records:
        key = (record.address, record.source, record.mac_address, record.state)
        unique[key] = record
    return sorted(
        unique.values(),
        key=lambda item: (
            int(item.address),
            item.source,
            item.mac_address or "",
            item.state or "",
        ),
    )


class SystemNetworkAdapter:
    """Unprivileged subprocess adapter for Windows, Linux, and macOS."""

    def __init__(
        self,
        *,
        system_name: str | None = None,
        runner: CommandRunner = subprocess.run,
    ) -> None:
        self.system_name = (system_name or platform.system()).lower()
        self._runner = runner

    def _run(self, argv: Sequence[str], timeout_seconds: float) -> CompletedCommand:
        return self._runner(
            list(argv),
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
            shell=False,
        )

    def ping(
        self,
        address: ipaddress.IPv4Address,
        timeout_seconds: float,
    ) -> ProbeResult:
        """Run one system ping with a Python-enforced deadline."""
        safe_address = _safe_probe_address(address)
        timeout = clamp_timeout(timeout_seconds)
        target_token = str(safe_address)
        if self.system_name == "windows":
            argv = ["ping", "-n", "1", "-w", str(round(timeout * 1000)), target_token]
        elif self.system_name in {"linux", "darwin"}:
            argv = ["ping", "-n", "-c", "1", target_token]
        else:
            return ProbeResult(
                "unavailable", "This operating system has no supported ping adapter."
            )
        if argv[-1] != target_token:
            return ProbeResult("error", "The validated target token changed unexpectedly.")

        try:
            completed = self._run(argv, timeout)
        except FileNotFoundError:
            return ProbeResult("unavailable", "The system ping command is unavailable.")
        except subprocess.TimeoutExpired:
            return ProbeResult("timeout", "No response was observed before the timeout.")
        except (OSError, subprocess.SubprocessError):
            return ProbeResult("error", "The system ping command could not be completed.")

        output = f"{completed.stdout or ''}\n{completed.stderr or ''}"
        address_pattern = re.compile(
            rf"(?<![0-9.]){re.escape(target_token)}(?![0-9.])"
        )
        if completed.returncode == 0 and address_pattern.search(output):
            return ProbeResult("responsive", "The system ping command received a reply.")
        if completed.returncode == 0:
            return ProbeResult(
                "error",
                "The ping command reported success without verifiable target evidence.",
            )
        return ProbeResult("no_response", "The probe completed without an observed reply.")

    def neighbors(self, timeout_seconds: float) -> NeighborSnapshot:
        """Read a fixed local neighbor-cache command with no user-controlled argv."""
        timeout = clamp_timeout(timeout_seconds)
        if self.system_name == "linux":
            commands = ((["ip", "neighbor", "show"], parse_ip_neighbor_output),
                        (["arp", "-an"], parse_arp_output))
        elif self.system_name == "windows":
            commands = ((["arp", "-a"], parse_arp_output),)
        elif self.system_name == "darwin":
            commands = ((["arp", "-an"], parse_arp_output),)
        else:
            return NeighborSnapshot(
                "unavailable",
                detail="This operating system has no supported neighbor-cache adapter.",
            )

        missing = 0
        for argv, parser in commands:
            try:
                completed = self._run(argv, timeout)
            except FileNotFoundError:
                missing += 1
                continue
            except subprocess.TimeoutExpired:
                return NeighborSnapshot(
                    "timeout", detail="Neighbor-cache inspection reached its timeout."
                )
            except (OSError, subprocess.SubprocessError):
                return NeighborSnapshot(
                    "error", detail="Neighbor-cache inspection could not be completed."
                )
            if completed.returncode != 0:
                continue
            try:
                records = tuple(parser(completed.stdout or ""))
            except (TypeError, ValueError):
                return NeighborSnapshot(
                    "error", detail="Neighbor-cache output could not be interpreted safely."
                )
            return NeighborSnapshot("available", records=records)

        detail = (
            "No supported neighbor-cache command is installed."
            if missing == len(commands)
            else "No supported neighbor-cache command completed successfully."
        )
        return NeighborSnapshot("unavailable", detail=detail)

    def default_gateways(self, timeout_seconds: float) -> GatewaySnapshot:
        """Read one fixed routing-table command; no packets are sent.

        This is deliberately separate from neighbor-cache collection.  A MAC or
        ARP entry cannot establish that a device routes traffic, whereas an OS
        default-route entry can establish that limited, local fact.
        """
        timeout = clamp_timeout(timeout_seconds)
        if self.system_name == "linux":
            argv = ["ip", "-4", "route", "show", "default"]
            parser = parse_linux_default_route_output
        elif self.system_name == "windows":
            argv = ["route", "print", "-4"]
            parser = parse_windows_default_route_output
        elif self.system_name == "darwin":
            argv = ["route", "-n", "get", "default"]
            parser = parse_macos_default_route_output
        else:
            return GatewaySnapshot(
                "unavailable",
                detail="This operating system has no supported routing-table adapter.",
            )

        try:
            completed = self._run(argv, timeout)
        except FileNotFoundError:
            return GatewaySnapshot(
                "unavailable", detail="The system routing-table command is unavailable."
            )
        except subprocess.TimeoutExpired:
            return GatewaySnapshot(
                "timeout", detail="Routing-table inspection reached its timeout."
            )
        except (OSError, subprocess.SubprocessError):
            return GatewaySnapshot(
                "error", detail="Routing-table inspection could not be completed."
            )
        if completed.returncode != 0:
            return GatewaySnapshot(
                "unavailable",
                detail="The system routing-table command did not complete successfully.",
            )
        try:
            records = tuple(parser(completed.stdout or ""))
        except (TypeError, ValueError):
            return GatewaySnapshot(
                "error", detail="Routing-table output could not be interpreted safely."
            )
        return GatewaySnapshot("available", records=records)


def _addresses_to_probe(
    network: ipaddress.IPv4Network,
) -> tuple[ipaddress.IPv4Address, ...]:
    # Network and broadcast addresses are not treated as hosts on ordinary IPv4
    # subnets.  ipaddress correctly keeps both addresses usable for /31 and the
    # sole address usable for /32.
    return tuple(network.hosts())


def _evidence_for_neighbor(record: NeighborRecord) -> dict[str, object]:
    evidence: dict[str, object] = {
        "kind": "neighbor_cache",
        "source": record.source,
    }
    if record.mac_address is not None:
        evidence["mac_address"] = record.mac_address
    if record.state is not None:
        evidence["state"] = record.state
    return evidence


def _evidence_for_gateway(record: GatewayRecord) -> dict[str, object]:
    """Represent routing evidence without implying reachability or identity."""
    evidence: dict[str, object] = {
        "kind": "default_gateway_route",
        "source": "routing_table",
    }
    if record.interface is not None:
        evidence["interface"] = record.interface
    if record.metric is not None:
        evidence["metric"] = record.metric
    return evidence


def discover_network(
    target: str | ipaddress.IPv4Network,
    *,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    workers: int = DEFAULT_WORKERS,
    adapter: DiscoveryAdapter | None = None,
    local_addresses: Iterable[ipaddress.IPv4Address | str] | None = None,
    generated_at: str | None = None,
) -> dict[str, object]:
    """Discover authorized hosts and return a deterministic schema-v2 report.

    Only positive evidence becomes a host record.  Silent and timed-out probes
    are counted as addresses without an observed reply; they are never described
    as absent hosts.  Hostname lookup is intentionally skipped to avoid reverse-
    DNS traffic and delays.
    """
    network = validate_target(target)
    timeout = clamp_timeout(timeout_seconds)
    worker_count = clamp_workers(workers)
    system_adapter = adapter or SystemNetworkAdapter()
    probe_addresses = _addresses_to_probe(network)
    probe_address_set = set(probe_addresses)

    if local_addresses is None:
        known_local = collect_local_ipv4_addresses()
    else:
        known_local = set()
        for item in local_addresses:
            try:
                address = _safe_probe_address(item)
            except TargetValidationError:
                continue
            known_local.add(address)
    target_local = known_local & probe_address_set

    outcomes: dict[ipaddress.IPv4Address, ProbeResult] = {}
    remote_addresses = [address for address in probe_addresses if address not in target_local]
    if remote_addresses:
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = {
                executor.submit(system_adapter.ping, address, timeout): address
                for address in remote_addresses
            }
            for future in as_completed(futures):
                address = futures[future]
                try:
                    outcomes[address] = future.result()
                except Exception:
                    # Adapter defects or unusual platform failures must not abort the
                    # bounded run or invent reachability evidence.
                    outcomes[address] = ProbeResult(
                        "error", "The reachability adapter failed for this address."
                    )

    try:
        neighbor_snapshot = system_adapter.neighbors(timeout)
    except Exception:
        neighbor_snapshot = NeighborSnapshot(
            "error", detail="The neighbor-cache adapter failed."
        )

    gateway_method = getattr(system_adapter, "default_gateways", None)
    if not callable(gateway_method):
        # Adapters predating schema v2 remain usable.  Missing routing evidence
        # means no role is inferred; it is never replaced by a heuristic.
        gateway_snapshot = GatewaySnapshot(
            "unavailable",
            detail="The discovery adapter does not supply routing-table evidence.",
        )
    else:
        try:
            gateway_snapshot = gateway_method(timeout)
        except Exception:
            gateway_snapshot = GatewaySnapshot(
                "error", detail="The routing-table adapter failed."
            )
        if not isinstance(gateway_snapshot, GatewaySnapshot):
            gateway_snapshot = GatewaySnapshot(
                "error", detail="The routing-table adapter returned invalid evidence."
            )

    neighbors_by_address: dict[ipaddress.IPv4Address, list[NeighborRecord]] = {}
    for record in neighbor_snapshot.records:
        if record.address not in probe_address_set or not _is_allowed_address(record.address):
            continue
        neighbors_by_address.setdefault(record.address, []).append(record)

    # Records are trusted only when the adapter says route collection completed.
    # A contradictory custom adapter cannot attach a role to an error snapshot.
    trusted_gateway_records = (
        gateway_snapshot.records if gateway_snapshot.status == "available" else ()
    )
    gateways_by_address: dict[ipaddress.IPv4Address, list[GatewayRecord]] = {}
    for record in trusted_gateway_records:
        if record.address not in probe_address_set or not _is_allowed_address(record.address):
            continue
        gateways_by_address.setdefault(record.address, []).append(record)

    hosts: list[dict[str, object]] = []
    for address in probe_addresses:
        outcome = outcomes.get(address)
        neighbor_records = _deduplicate_neighbors(neighbors_by_address.get(address, []))
        gateway_records = _deduplicate_gateways(gateways_by_address.get(address, []))
        evidence: list[dict[str, object]] = []
        if address in target_local:
            status = "local_machine"
            evidence.append(
                {
                    "kind": "local_interface_address",
                    "source": "psutil_interface_data",
                }
            )
        elif outcome is not None and outcome.status == "responsive":
            status = "confirmed_responsive"
            evidence.append(
                {
                    "kind": "icmp_echo_reply",
                    "source": "system_ping",
                }
            )
        elif neighbor_records:
            status = "known_neighbor"
        elif gateway_records:
            # A default route is positive local routing-table evidence.  It
            # establishes a configured next hop, not a response to a probe.
            status = "confirmed_gateway"
        else:
            continue
        evidence.extend(_evidence_for_neighbor(record) for record in neighbor_records)
        evidence.extend(_evidence_for_gateway(record) for record in gateway_records)
        hosts.append(
            {
                "address": str(address),
                "status": status,
                "evidence": evidence,
                # This field is intentionally absent unless the operating
                # system's routing table itself names the address as a default
                # next hop.  ICMP/neighbor evidence never assigns a device role.
                **({"device_role": "gateway_router"} if gateway_records else {}),
                "metadata": {
                    "hostname": {
                        "value": None,
                        "status": "not_collected",
                        "reason": "Reverse DNS is intentionally disabled.",
                    }
                },
            }
        )

    outcome_counts = {
        status: sum(result.status == status for result in outcomes.values())
        for status in ("responsive", "no_response", "timeout", "unavailable", "error")
    }
    status_counts = {
        status: sum(host["status"] == status for host in hosts)
        for status in (
            "local_machine",
            "confirmed_responsive",
            "known_neighbor",
            "confirmed_gateway",
        )
    }
    operational_probe = any(
        result.status in {"responsive", "no_response", "timeout"}
        for result in outcomes.values()
    )
    failed_probe = any(
        result.status in {"unavailable", "error"} for result in outcomes.values()
    )
    if not remote_addresses:
        reachability_status = "not_needed"
    elif operational_probe and failed_probe:
        reachability_status = "partial"
    elif operational_probe:
        reachability_status = "available"
    elif any(result.status == "error" for result in outcomes.values()):
        reachability_status = "error"
    else:
        reachability_status = "unavailable"

    source_worked = (
        reachability_status in {"available", "partial", "not_needed"}
        or neighbor_snapshot.status == "available"
        or bool(target_local)
    )
    all_sources_complete = (
        reachability_status in {"available", "not_needed"}
        and neighbor_snapshot.status == "available"
    )
    if all_sources_complete:
        collection_status = "completed"
    elif source_worked:
        collection_status = "partial"
    else:
        collection_status = "unavailable"

    timestamp = generated_at or datetime.now(timezone.utc).isoformat()
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": timestamp,
        "collection_status": collection_status,
        "target": {
            "cidr": str(network),
            "address_count": network.num_addresses,
            "host_address_count": len(probe_addresses),
            "probe_address_count": len(remote_addresses),
        },
        "settings": {
            "timeout_seconds": timeout,
            "workers": worker_count,
            "maximum_target_addresses": MAX_TARGET_ADDRESSES,
        },
        "authorization": {
            "scope": "explicitly authorized private IPv4 only",
            "allowed_ranges": [str(network) for network in _ALLOWED_NETWORKS],
        },
        "summary": {
            **status_counts,
            "addresses_probed": len(remote_addresses),
            "responses_received": outcome_counts["responsive"],
            "no_response_observed": outcome_counts["no_response"],
            "probe_timeouts": outcome_counts["timeout"],
            "probe_unavailable": outcome_counts["unavailable"],
            "probe_errors": outcome_counts["error"],
        },
        # Every remote probe has a validated numeric address.  Preserve its
        # bounded outcome so interpretation can name incomplete evidence rather
        # than reducing it to a potentially misleading aggregate count.
        "probe_outcomes": [
            {
                "address": str(address),
                "status": outcome.status,
                **({"detail": outcome.detail} if outcome.detail else {}),
            }
            for address, outcome in sorted(outcomes.items(), key=lambda item: int(item[0]))
        ],
        "neighbor_cache": {
            "status": neighbor_snapshot.status,
            "detail": neighbor_snapshot.detail,
        },
        "default_gateway": {
            "status": gateway_snapshot.status,
            "detail": gateway_snapshot.detail,
            "records": [
                {
                    "address": str(record.address),
                    **({"interface": record.interface} if record.interface else {}),
                    **({"metric": record.metric} if record.metric is not None else {}),
                }
                for record in _deduplicate_gateways(trusted_gateway_records)
                if record.address in probe_address_set
            ],
        },
        "sources": {
            "reachability": {"status": reachability_status},
            "neighbor_cache": {
                "status": neighbor_snapshot.status,
                "detail": neighbor_snapshot.detail,
            },
            "routing_table": {
                "status": gateway_snapshot.status,
                "detail": gateway_snapshot.detail,
            },
        },
        "hosts": hosts,
        "limitations": [
            "Only ICMP echo replies, local interface data, existing neighbor-cache records, and local default-route records are considered.",
            "A device is labeled gateway/router only when a local default-route entry confirms it; neighbor/cache and reachability evidence are insufficient.",
            "A silent or timed-out address may still have a host; no absence claim is made.",
            "Hostnames are not resolved, and ports and vulnerabilities are not scanned.",
        ],
    }


__all__ = [
    "CandidateSelectionRequired",
    "DEFAULT_TIMEOUT_SECONDS",
    "DEFAULT_WORKERS",
    "DiscoveryAdapter",
    "DiscoveryOperationalError",
    "GatewayRecord",
    "GatewaySnapshot",
    "MAX_TARGET_ADDRESSES",
    "MAX_TIMEOUT_SECONDS",
    "MAX_WORKERS",
    "MIN_TIMEOUT_SECONDS",
    "MIN_WORKERS",
    "NeighborRecord",
    "NeighborSnapshot",
    "NetworkCandidate",
    "NetworkDiscoveryError",
    "NoSuitableNetworkError",
    "ProbeResult",
    "SCHEMA_VERSION",
    "SystemNetworkAdapter",
    "TargetValidationError",
    "clamp_timeout",
    "clamp_workers",
    "collect_local_ipv4_addresses",
    "detect_local_network_candidates",
    "discover_network",
    "parse_arp_output",
    "parse_linux_default_route_output",
    "parse_macos_default_route_output",
    "parse_ip_neighbor_output",
    "parse_windows_default_route_output",
    "resolve_target",
    "validate_target",
]
