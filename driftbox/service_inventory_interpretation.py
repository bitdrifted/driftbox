"""Deterministic explanations and safe next moves for service inventory.

The Nmap adapter owns collection and raw, bounded evidence.  This module is
pure: it neither invokes Nmap nor contacts a host.  Its separately versioned
``interpretation`` object deliberately describes evidence without turning a
service label into a vulnerability or exploit claim.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy

from driftbox.service_inventory import (
    ServiceTargetValidationError,
    validate_service_target,
    validate_top_ports,
)


SERVICE_INVENTORY_INTERPRETATION_SCHEMA_VERSION = 1
ACTIVITY_LEVELS = frozenset(
    {"PASSIVE", "LOCAL READ-ONLY", "ACTIVE AUTHORIZED SCAN", "LAB-ONLY"}
)


def _mapping(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"Service inventory {name} is malformed.")
    return value


def _list(value: object, name: str) -> list[object]:
    if not isinstance(value, list):
        raise ValueError(f"Service inventory {name} is malformed.")
    return value


def _target(report: Mapping[str, object]) -> str:
    raw_target = report.get("target")
    target = (
        raw_target.get("address")
        if isinstance(raw_target, Mapping)
        else raw_target
    )
    if not isinstance(target, str):
        raise ValueError("Service inventory target is malformed.")
    try:
        return validate_service_target(target)
    except ServiceTargetValidationError as error:
        raise ValueError("Service inventory target is unsafe.") from error


def _recommendation(
    *,
    identifier: str,
    rank: int,
    command: str,
    purpose: str,
    reason: str,
    target: str,
    activity_level: str,
    authorization_required: str,
    expected_result: str,
    available_now: bool,
    availability_status: str,
    availability_condition: str,
) -> dict[str, object]:
    if activity_level not in ACTIVITY_LEVELS:
        raise ValueError("Unsupported service recommendation activity level.")
    return {
        "id": identifier,
        "rank": rank,
        "command": command,
        "purpose": purpose,
        "reason": reason,
        "target": target,
        "activity_level": activity_level,
        "authorization_required": authorization_required,
        "expected_result": expected_result,
        "availability": {
            "available_now": available_now,
            "status": availability_status,
            "condition": availability_condition,
        },
    }


def _recommendations(
    target: str,
    service_count: int,
    top_ports: int,
) -> list[dict[str, object]]:
    reason = (
        f"The scan reported {service_count} open TCP service "
        f"{'endpoint' if service_count == 1 else 'endpoints'}; JSON retains "
        "the complete bounded evidence."
    )
    authorization = (
        f"Explicit authorization is required again immediately before scanning {target}; "
        "private addressing does not establish authorization."
    )
    return [
        _recommendation(
            identifier="review-service-ownership",
            rank=1,
            command=(
                "No automated command: review the evidence with the authorized "
                "asset owner."
            ),
            purpose=(
                "Confirm the expected role and ownership of each reported "
                "service before deciding on any change."
            ),
            reason=(
                "Nmap service and version labels are observations, not "
                "guaranteed identity or vulnerability findings."
            ),
            target=target,
            activity_level="PASSIVE",
            authorization_required=(
                "Use only the inventory evidence already collected; obtain the "
                "asset owner's approval before any additional network activity."
            ),
            expected_result=(
                "A documented owner-approved decision about whether each "
                "service is expected and how it should be maintained."
            ),
            available_now=True,
            availability_status="operator-action-required",
            availability_condition=(
                "This is a review step; Driftbox does not automatically contact "
                "the target or change it."
            ),
        ),
        _recommendation(
            identifier="repeat-authorized-service-inventory-json",
            rank=2,
            command=(
                f"driftbox services {target} --confirm-authorization "
                f"--top-ports {top_ports} --json"
            ),
            purpose=(
                "Collect a new, bounded JSON service-inventory record for the "
                "exact same device."
            ),
            reason=reason,
            target=target,
            activity_level="ACTIVE AUTHORIZED SCAN",
            authorization_required=authorization,
            expected_result=(
                "A new schema-versioned JSON record on standard output; no "
                "report is saved automatically."
            ),
            available_now=True,
            availability_status="available",
            availability_condition=(
                "Uses only the selected common TCP-port scope and the "
                "operator-installed Nmap executable."
            ),
        ),
        _recommendation(
            identifier="correlate-vulnerabilities",
            rank=3,
            command="Unavailable: vulnerability correlation is not implemented.",
            purpose=(
                "Correlate reviewed service evidence with authoritative "
                "vulnerability data without treating a label as proof."
            ),
            reason=(
                "Product, version, CPE, and detection-confidence evidence may "
                "support later correlation, but this milestone makes no "
                "vulnerability claim."
            ),
            target=target,
            activity_level="PASSIVE",
            authorization_required=(
                "Not available in this milestone; any later validation must "
                "retain explicit target authorization and evidence review."
            ),
            expected_result=(
                "A future evidence-correlated result with uncertainty and "
                "source provenance; no exploit command generation."
            ),
            available_now=False,
            availability_status="planned-next-milestone",
            availability_condition=(
                "Vulnerability correlation is the next unimplemented milestone; "
                "exploit guidance remains prohibited here."
            ),
        ),
    ]


def build_service_inventory_interpretation(report: Mapping[str, object]) -> dict[str, object]:
    """Return a pure, separately versioned explanation of bounded evidence."""
    target = _target(report)
    profile = _mapping(report.get("scan_profile"), "scan profile")
    services = _list(report.get("services"), "services")
    top_ports = profile.get("top_ports")
    if (
        isinstance(top_ports, bool)
        or not isinstance(top_ports, int)
        or not 1 <= top_ports <= 1000
    ):
        raise ValueError("Service inventory port scope is malformed.")
    incomplete = _mapping(report.get("evidence"), "evidence").get("incomplete")
    if not isinstance(incomplete, bool):
        raise ValueError("Service inventory evidence status is malformed.")
    meaning = [
        "An open port means a service accepted a connection during this scan.",
        "A service or version label is evidence reported by Nmap, not a guaranteed identity.",
        "An open service is not automatically vulnerable or malicious.",
        "No open result does not prove the host has no services.",
        "Only the selected common TCP ports were examined.",
        "Firewalls and filtering can affect results.",
        "This scan does not establish internet reachability.",
    ]
    if incomplete:
        meaning.append(
            "Some evidence was incomplete; interpret the listed observations "
            "with the recorded limitations."
        )
    return {
        "schema_version": SERVICE_INVENTORY_INTERPRETATION_SCHEMA_VERSION,
        "service_summary": {
            "target": target,
            "open_port_count": len(services),
            "tcp_ports_examined": top_ports,
            "evidence_incomplete": incomplete,
            "vulnerability_correlation": {
                "status": "not_implemented",
                "statement": (
                    "Driftbox does not infer vulnerabilities from service or "
                    "version evidence and does not generate exploit commands."
                ),
            },
        },
        "what_this_means": meaning,
        "recommendations": _recommendations(target, len(services), top_ports),
        "detailed_evidence": {
            "services": deepcopy(services),
            "limitations": deepcopy(
                _list(report.get("limitations", []), "limitations")
            ),
        },
    }


def with_service_inventory_interpretation(report: Mapping[str, object]) -> dict[str, object]:
    """Copy a service report and attach its deterministic interpretation."""
    result = dict(report)
    result["interpretation"] = build_service_inventory_interpretation(result)
    return result


def validate_service_recommendation_commands(
    recommendations: Sequence[object],
    parse_command: object,
) -> None:
    """Validate only executable Driftbox recommendations without running them."""
    import shlex

    if not callable(parse_command):
        raise ValueError("Recommendation parser is unavailable.")
    for item in recommendations:
        recommendation = _mapping(item, "recommendation")
        command = recommendation.get("command")
        if not isinstance(command, str):
            raise ValueError("Recommendation command is malformed.")
        if command.startswith(("No automated command:", "Unavailable:")):
            continue
        if not command.startswith("driftbox "):
            raise ValueError(f"Recommendation command is unsafe: {command}")
        try:
            argv = shlex.split(command)
            if argv[:1] != ["driftbox"] or len(argv) < 2:
                raise ValueError("Recommendation command is malformed.")
            parsed = parse_command(argv[1:])
            if getattr(parsed, "command", None) != "services":
                raise ValueError("Recommendation command is unsupported.")
            parsed_target = validate_service_target(
                getattr(parsed, "target", None)
            )
            if parsed_target != recommendation.get("target"):
                raise ValueError("Recommendation command target does not match.")
            if getattr(parsed, "authorization_confirmed", False) is not True:
                raise ValueError(
                    "Recommendation command must require fresh authorization."
                )
            if getattr(parsed, "json_output", False) is not True:
                raise ValueError("Recommendation command must preserve JSON evidence.")
            validate_top_ports(getattr(parsed, "top_ports", None))
        except (ValueError, SystemExit) as error:
            raise ValueError(
                f"Recommendation command is not supported: {command}"
            ) from error


__all__ = [
    "ACTIVITY_LEVELS",
    "SERVICE_INVENTORY_INTERPRETATION_SCHEMA_VERSION",
    "build_service_inventory_interpretation",
    "validate_service_recommendation_commands",
    "with_service_inventory_interpretation",
]
