"""Read-only security posture analysis for collected Driftbox data."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass

CHECK_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class PostureObservation:
    """One raw rule match awaiting unified classification."""

    id: str
    severity: str
    message: str
    evidence: dict[str, object]


@dataclass(frozen=True)
class SecurityPostureResult:
    """Deterministically ordered raw security posture observations."""

    observations: tuple[PostureObservation, ...]

    def as_dict(self) -> dict[str, object]:
        """Return a machine-readable, versioned check result."""
        high_count = sum(
            observation.severity == "high" for observation in self.observations
        )
        warning_count = sum(
            observation.severity == "warning" for observation in self.observations
        )
        return {
            "schema_version": CHECK_SCHEMA_VERSION,
            "summary": {
                "total": len(self.observations),
                "high": high_count,
                "warning": warning_count,
            },
            "findings": [asdict(item) for item in self.observations],
        }


def _firewall_finding(firewall: object) -> PostureObservation | None:
    """Return a finding for disabled or indeterminate firewall status."""
    if not isinstance(firewall, dict):
        raise ValueError("firewall inspection result must be an object")

    status = firewall.get("status")
    if not isinstance(status, str):
        raise ValueError("firewall inspection status must be a string")

    evidence = {
        "platform": firewall.get("platform", "unknown"),
        "provider": firewall.get("provider", "unknown"),
        "status": status,
    }

    if status == "disabled":
        return PostureObservation(
            id="firewall-disabled",
            severity="high",
            message="The local firewall is confirmed disabled.",
            evidence=evidence,
        )
    if status == "unknown":
        return PostureObservation(
            id="firewall-unknown",
            severity="warning",
            message=(
                "Firewall status could not be determined; do not assume the "
                "system is protected."
            ),
            evidence=evidence,
        )
    return None


def _listener_finding(listener: object, index: int) -> PostureObservation | None:
    """Return a finding for broadly exposed listener bindings."""
    if not isinstance(listener, dict):
        raise ValueError(f"listener {index} must be an object")

    required_fields = ("protocol", "address", "port", "process", "scope")
    if any(field not in listener for field in required_fields):
        raise ValueError(f"listener {index} is missing required evidence")

    protocol = listener["protocol"]
    address = listener["address"]
    port = listener["port"]
    process = listener["process"]
    scope = listener["scope"]
    text_values = (protocol, address, process, scope)
    if not all(isinstance(value, str) for value in text_values):
        raise ValueError(f"listener {index} contains invalid text evidence")
    if isinstance(port, bool) or not isinstance(port, int):
        raise ValueError(f"listener {index} contains an invalid port")

    evidence = {
        "protocol": protocol,
        "address": address,
        "port": port,
        "process": process,
        "scope": scope,
    }
    if scope == "all interfaces":
        return PostureObservation(
            id="listener-all-interfaces",
            severity="warning",
            message=(
                "A service listens on all interfaces. Firewall policy, routing, "
                "and NAT determine whether it is reachable from other networks."
            ),
            evidence=evidence,
        )
    if scope == "public address":
        return PostureObservation(
            id="listener-public-address",
            severity="warning",
            message=(
                "A service is bound to a public address. This binding alone does "
                "not prove internet accessibility because firewall policy, "
                "routing, and NAT may limit reachability."
            ),
            evidence=evidence,
        )
    return None


def analyze_security_posture(
    firewall: object,
    listening_ports: object,
) -> SecurityPostureResult:
    """Analyze existing inspection data without changing system configuration."""
    if not isinstance(listening_ports, list):
        raise ValueError("listening-port inspection result must be an array")

    observations: list[PostureObservation] = []
    firewall_finding = _firewall_finding(firewall)
    if firewall_finding is not None:
        observations.append(firewall_finding)

    for index, listener in enumerate(listening_ports):
        finding = _listener_finding(listener, index)
        if finding is not None:
            observations.append(finding)

    # Serialized evidence provides a stable secondary key for repeated rule IDs.
    observations.sort(
        key=lambda observation: (
            observation.id,
            json.dumps(observation.evidence, sort_keys=True),
        )
    )
    return SecurityPostureResult(tuple(observations))


def format_check_result(result: SecurityPostureResult) -> str:
    """Format security posture findings for terminal output."""
    data = result.as_dict()
    summary = data["summary"]
    if not isinstance(summary, dict):
        raise ValueError("invalid security check summary")

    lines = [
        "driftbox :: security posture",
        "-" * 32,
        (
            f"Summary: {summary['high']} high, "
            f"{summary['warning']} warning, {summary['total']} total"
        ),
    ]
    if not result.observations:
        lines.append("No warning or high-severity findings detected.")
        return "\n".join(lines)

    for finding in result.observations:
        evidence = ", ".join(
            f"{key}={value}" for key, value in sorted(finding.evidence.items())
        )
        lines.extend(
            [
                "",
                f"[{finding.severity.upper()}] {finding.id}",
                finding.message,
                f"Evidence: {evidence}",
            ]
        )
    return "\n".join(lines)
