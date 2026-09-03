"""Normalize and compare Driftbox reports for security-relevant drift."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

Listener = tuple[str, str, int, str, str]


@dataclass(frozen=True)
class ReportSnapshot:
    """Security-relevant report fields with volatile data removed."""

    listeners: frozenset[Listener]
    firewall_status: str


@dataclass(frozen=True)
class ReportDrift:
    """Differences between a baseline and current report."""

    added_listeners: tuple[Listener, ...]
    removed_listeners: tuple[Listener, ...]
    firewall_change: tuple[str, str] | None

    @property
    def found(self) -> bool:
        """Return True when any security-relevant value changed."""
        return bool(
            self.added_listeners
            or self.removed_listeners
            or self.firewall_change
        )


def _listener_value(listener: dict[str, object], field: str, index: int) -> object:
    """Return a required listener value with a useful validation error."""
    if field not in listener:
        raise ValueError(f"listener {index} is missing {field!r}")
    return listener[field]


def normalize_report(report: object) -> ReportSnapshot:
    """Validate and retain only fields that represent meaningful drift."""
    if not isinstance(report, dict):
        raise ValueError("report must be a JSON object")

    exposure = report.get("exposure")
    if not isinstance(exposure, dict):
        raise ValueError("report exposure must be a JSON object")

    raw_listeners = exposure.get("listening_ports")
    if not isinstance(raw_listeners, list):
        raise ValueError("report exposure.listening_ports must be a JSON array")

    listeners: set[Listener] = set()
    for index, listener in enumerate(raw_listeners):
        if not isinstance(listener, dict):
            raise ValueError(f"listener {index} must be a JSON object")

        protocol = _listener_value(listener, "protocol", index)
        address = _listener_value(listener, "address", index)
        port = _listener_value(listener, "port", index)
        process = _listener_value(listener, "process", index)
        scope = _listener_value(listener, "scope", index)

        if not all(
            isinstance(value, str)
            for value in (protocol, address, process, scope)
        ):
            raise ValueError(f"listener {index} contains an invalid text field")
        if (
            isinstance(port, bool)
            or not isinstance(port, int)
            or not 0 <= port <= 65535
        ):
            raise ValueError(f"listener {index} contains an invalid port")

        # PIDs and report timestamps are intentionally excluded because they are
        # volatile and do not describe a change in network exposure.
        listeners.add((protocol, address, port, process, scope))

    firewall = report.get("firewall")
    if not isinstance(firewall, dict):
        raise ValueError("report firewall must be a JSON object")

    firewall_status = firewall.get("status")
    if not isinstance(firewall_status, str):
        raise ValueError("report firewall.status must be a string")

    return ReportSnapshot(frozenset(listeners), firewall_status)


def load_baseline(path: str) -> ReportSnapshot:
    """Read and validate a baseline report from disk."""
    with Path(path).open(encoding="utf-8-sig") as baseline_file:
        return normalize_report(json.load(baseline_file))


def compare_snapshots(
    baseline: ReportSnapshot,
    current: ReportSnapshot,
) -> ReportDrift:
    """Compare normalized snapshots with stable ordering."""
    firewall_change = None
    if baseline.firewall_status != current.firewall_status:
        firewall_change = (baseline.firewall_status, current.firewall_status)

    return ReportDrift(
        added_listeners=tuple(sorted(current.listeners - baseline.listeners)),
        removed_listeners=tuple(sorted(baseline.listeners - current.listeners)),
        firewall_change=firewall_change,
    )


def _format_listener(listener: Listener) -> str:
    """Format a listener consistently for terminal output."""
    protocol, address, port, process, scope = listener
    host = f"[{address}]" if ":" in address else address
    return f"{protocol} {host}:{port} process={process} scope={scope}"


def format_drift(drift: ReportDrift) -> str:
    """Format report drift for a human-readable terminal result."""
    lines = ["driftbox :: report drift", "-" * 32]

    if not drift.found:
        lines.append("No drift detected.")
        return "\n".join(lines)

    lines.append("Drift detected.")

    if drift.added_listeners:
        lines.append("")
        lines.append("Added listening services/endpoints:")
        lines.extend(f"+ {_format_listener(item)}" for item in drift.added_listeners)

    if drift.removed_listeners:
        lines.append("")
        lines.append("Removed listening services/endpoints:")
        lines.extend(f"- {_format_listener(item)}" for item in drift.removed_listeners)

    if drift.firewall_change:
        baseline_status, current_status = drift.firewall_change
        lines.append("")
        lines.append(
            f"Firewall status changed: {baseline_status} -> {current_status}"
        )

    return "\n".join(lines)
