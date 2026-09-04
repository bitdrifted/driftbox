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
_COMMON_SERVICE_EXPLANATIONS = {
    ("tcp", 135, "msrpc"): "Commonly associated with Microsoft Windows RPC.",
    ("tcp", 139, "netbios-ssn"): (
        "Commonly associated with legacy Windows file/printer networking."
    ),
    ("tcp", 445, "microsoft-ds"): (
        "Commonly associated with SMB and Windows file sharing."
    ),
}


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
            identifier="correlate-local-listeners",
            rank=1,
            command="driftbox ports",
            purpose=(
                "Correlate local listening ports with owning process IDs and "
                "names on the computer running Driftbox."
            ),
            reason=(
                "When the scanned target is this computer, process ownership "
                "can help confirm whether each listener is expected."
            ),
            target="this local machine",
            activity_level="LOCAL READ-ONLY",
            authorization_required=(
                "Permission to inspect this local machine; this command does "
                "not start an active network scan."
            ),
            expected_result=(
                "A local listener list with bind scope, PID, and process name "
                "when the operating system provides them."
            ),
            available_now=True,
            availability_status="available",
            availability_condition=(
                "Inspects only this local machine and correlates directly only "
                "when it is the scanned target."
            ),
        ),
        _recommendation(
            identifier="review-local-firewall",
            rank=2,
            command="driftbox firewall",
            purpose=(
                "Review local firewall status and available profile protection "
                "on the computer running Driftbox."
            ),
            reason=(
                "An open local listener and the firewall policy protecting it "
                "are separate evidence that should be reviewed together."
            ),
            target="this local machine",
            activity_level="LOCAL READ-ONLY",
            authorization_required=(
                "Permission to inspect this local machine; this command does "
                "not change firewall configuration."
            ),
            expected_result=(
                "A read-only local firewall status report with profile details "
                "when the operating system provides them."
            ),
            available_now=True,
            availability_status="available",
            availability_condition=(
                "Inspects only this local machine and does not prove policy on "
                "a different scanned target."
            ),
        ),
        _recommendation(
            identifier="evaluate-local-posture",
            rank=3,
            command="driftbox check",
            purpose=(
                "Evaluate local firewall and listener posture with Driftbox's "
                "existing deterministic checks."
            ),
            reason=(
                "Local posture findings can identify conditions that deserve "
                "review without treating Nmap labels as vulnerabilities."
            ),
            target="this local machine",
            activity_level="LOCAL READ-ONLY",
            authorization_required=(
                "Permission to inspect this local machine; this command does "
                "not change services or firewall rules."
            ),
            expected_result=(
                "A local posture summary with normal, suspicious, or critical "
                "findings and no automatic remediation."
            ),
            available_now=True,
            availability_status="available",
            availability_condition=(
                "Inspects only this local machine and does not evaluate a "
                "different scanned target."
            ),
        ),
        _recommendation(
            identifier="repeat-authorized-service-inventory-json",
            rank=4,
            command=(
                f"driftbox services {target} --confirm-authorization "
                f"--top-ports {top_ports} --json"
            ),
            purpose=(
                "Optionally collect a new bounded JSON service-inventory record "
                "for the exact same device."
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
                "This starts another active scan and must never run "
                "automatically; use it only after fresh authorization."
            ),
        ),
    ]


def _recognized_common_services(
    services: Sequence[object],
) -> list[dict[str, object]]:
    """Explain only exact protocol, port, and observed-name relationships."""
    recognized: list[dict[str, object]] = []
    for raw_item in services:
        item = _mapping(raw_item, "service")
        service = _mapping(item.get("service"), "service details")
        protocol = item.get("protocol")
        port = item.get("port")
        name = service.get("name")
        if (
            not isinstance(protocol, str)
            or isinstance(port, bool)
            or not isinstance(port, int)
            or not isinstance(name, str)
        ):
            continue
        normalized_name = name.casefold()
        explanation = _COMMON_SERVICE_EXPLANATIONS.get(
            (protocol.casefold(), port, normalized_name)
        )
        if explanation is None:
            continue
        recognized.append(
            {
                "protocol": protocol.casefold(),
                "port": port,
                "observed_name": name,
                "explanation": explanation,
            }
        )
    recognized.sort(
        key=lambda item: (
            str(item["protocol"]),
            int(item["port"]),
            str(item["observed_name"]),
        )
    )
    return recognized


def _bottom_line(
    services: Sequence[object],
    recognized: Sequence[Mapping[str, object]],
    incomplete: bool,
) -> str:
    service_count = len(services)
    if service_count:
        statements = [
            f"Nmap reported {service_count} open TCP service "
            f"{'endpoint' if service_count == 1 else 'endpoints'}."
        ]
    else:
        statements = [
            "Nmap reported no open TCP services in the selected common-port scope; "
            "that does not prove the target has no services."
        ]
    if recognized:
        statements.append(
            "The recognized service labels are commonly seen on Windows systems."
        )
    statements.append("Nothing in this evidence proves a vulnerability.")
    recognized_keys = {
        (
            item.get("protocol"),
            item.get("port"),
            item.get("observed_name").casefold()
            if isinstance(item.get("observed_name"), str)
            else None,
        )
        for item in recognized
    }
    has_netbios = ("tcp", 139, "netbios-ssn") in recognized_keys
    has_smb = ("tcp", 445, "microsoft-ds") in recognized_keys
    if has_netbios or has_smb:
        if has_netbios and has_smb:
            review_name = "SMB/NetBIOS"
        elif has_smb:
            review_name = "SMB"
        else:
            review_name = "NetBIOS"
        statements.append(
            f"Verify that {review_name} service exposure is intentional and "
            "restricted by firewall rules to only the networks that need it."
        )
    elif service_count:
        statements.append(
            "Verify that the reported services are intentional and appropriately "
            "restricted by firewall policy."
        )
    if incomplete:
        statements.append(
            "Some evidence was incomplete, so review the recorded reasons before "
            "drawing conclusions."
        )
    statements.append(
        "This scan does not establish internet reachability or reachability from "
        "another device."
    )
    return " ".join(statements)


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
    recognized = _recognized_common_services(services)
    meaning = [
        "An open port means a service accepted a connection during this scan.",
        "Nmap service and version labels are observations, not guaranteed identity.",
        "An open service is not automatically vulnerable or malicious.",
    ]
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
        "recognized_common_services": recognized,
        "bottom_line": _bottom_line(services, recognized, incomplete),
        "limitations": [
            "Only the selected common TCP ports were examined.",
            "Firewalls, filtering, and network conditions can affect observations.",
            "Vulnerability correlation and exploit guidance are not implemented.",
        ],
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
        if not command.startswith("driftbox "):
            raise ValueError(f"Recommendation command is unsafe: {command}")
        try:
            argv = shlex.split(command)
            if argv[:1] != ["driftbox"] or len(argv) < 2:
                raise ValueError("Recommendation command is malformed.")
            parsed = parse_command(argv[1:])
            parsed_command = getattr(parsed, "command", None)
            if parsed_command in {"ports", "firewall", "check"}:
                if argv != ["driftbox", parsed_command]:
                    raise ValueError("Local recommendation command is malformed.")
                if recommendation.get("target") != "this local machine":
                    raise ValueError("Local recommendation target is malformed.")
                if recommendation.get("activity_level") != "LOCAL READ-ONLY":
                    raise ValueError("Local recommendation activity is malformed.")
                continue
            if parsed_command != "services":
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
            if recommendation.get("activity_level") != "ACTIVE AUTHORIZED SCAN":
                raise ValueError("Service recommendation activity is malformed.")
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
