"""Deterministic interpretation and safe follow-up guidance for discovery.

The discovery transport schema remains owned by :mod:`network_discovery`.  This
module adds a separately versioned ``interpretation`` object to a completed
discovery report.  Keeping its schema version independent lets clients retain
the raw collection evidence while this learner-facing explanation evolves.

``interpretation.schema_version == 1`` has four stable sections:
``discovery_summary``, ``what_this_means``, ``recommendations``, and
``detailed_evidence``.  Recommendations are data, not executable actions;
callers must present them for human review and obtain any required permission.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
import ipaddress

from driftbox.network_discovery import TargetValidationError, validate_target


INTERPRETATION_SCHEMA_VERSION = 1
ACTIVITY_LEVELS = frozenset(
    {"PASSIVE", "LOCAL READ-ONLY", "ACTIVE AUTHORIZED SCAN", "LAB-ONLY"}
)

_CAUTIONS = (
    "Positive evidence records only what this bounded collection observed; it is not a complete device inventory.",
    "A silent address may still have a host. Do not treat no reply as proof of absence.",
    "Hostnames, ports, services, vulnerabilities, firewall reachability, NAT, and routing beyond any confirmed local default-route next hop were not established by discovery.",
    "Review private addresses, MAC addresses, and other inventory evidence before storing or sharing it.",
    "Discovery does not authorize port scanning or any other additional network activity.",
)


def _mapping(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"Discovery report {name} is malformed.")
    return value


def _list(value: object, name: str) -> list[object]:
    if not isinstance(value, list):
        raise ValueError(f"Discovery report {name} is malformed.")
    return value


def _integer(value: object, name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"Discovery report {name} is malformed.")
    try:
        return int(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"Discovery report {name} is malformed.") from error


def _validated_cidr(target: Mapping[str, object]) -> str:
    cidr = target.get("cidr")
    if not isinstance(cidr, str):
        raise ValueError("Discovery report target CIDR is malformed.")
    try:
        return str(validate_target(cidr))
    except TargetValidationError as error:
        # A recommendation must never turn report text into a command argument.
        raise ValueError("Discovery report target CIDR is unsafe for recommendations.") from error


def _validated_probe_outcomes(
    value: object,
    cidr: str,
) -> list[dict[str, object]]:
    """Normalize per-address outcomes without trusting report text as argv."""
    if value is None:
        # Reports written before discovery schema v2 lack address-level negative
        # outcomes.  Preserve that uncertainty instead of reconstructing names.
        return []
    raw_outcomes = _list(value, "probe_outcomes")
    network = ipaddress.IPv4Network(cidr)
    usable_addresses = set(network.hosts())
    allowed_statuses = {"responsive", "no_response", "timeout", "unavailable", "error"}
    normalized: list[dict[str, object]] = []
    seen: set[ipaddress.IPv4Address] = set()
    for item in raw_outcomes:
        outcome = _mapping(item, "probe_outcome")
        address_text = outcome.get("address")
        status = outcome.get("status")
        if not isinstance(address_text, str) or not isinstance(status, str):
            raise ValueError("Discovery report probe outcome is malformed.")
        try:
            address = ipaddress.IPv4Address(address_text)
        except ipaddress.AddressValueError as error:
            raise ValueError("Discovery report probe outcome address is malformed.") from error
        if (
            str(address) != address_text
            or address not in usable_addresses
            or address in seen
        ):
            raise ValueError("Discovery report probe outcome address is unsafe.")
        if status not in allowed_statuses:
            raise ValueError("Discovery report probe outcome status is malformed.")
        seen.add(address)
        record: dict[str, object] = {"address": str(address), "status": status}
        detail = outcome.get("detail")
        if isinstance(detail, str) and detail:
            record["detail"] = detail
        normalized.append(record)
    return sorted(normalized, key=lambda item: int(ipaddress.IPv4Address(str(item["address"]))))


def _incomplete_sources(sources: Mapping[str, object]) -> list[dict[str, object]]:
    """List source availability that prevents a fully complete collection."""
    incomplete: list[dict[str, object]] = []
    for name in sorted(sources):
        source = sources[name]
        if not isinstance(source, Mapping):
            incomplete.append({"source": name, "status": "malformed"})
            continue
        status = str(source.get("status", "unavailable"))
        if status in {"available", "not_needed"}:
            continue
        item: dict[str, object] = {"source": name, "status": status}
        detail = source.get("detail")
        if isinstance(detail, str) and detail:
            item["detail"] = detail
        incomplete.append(item)
    return incomplete


def _host_address_categories(
    hosts: Sequence[object],
    cidr: str,
) -> dict[str, list[str]]:
    """Return exact, in-scope categories without guessing device identity."""
    network = ipaddress.IPv4Network(cidr)
    usable_addresses = set(network.hosts())
    categories = {
        "local_computer_addresses": [],
        "responsive_devices": [],
        "cache_only_devices": [],
        "neighbor_cache_evidence_addresses": [],
        "confirmed_in_scope_gateways": [],
    }
    for item in hosts:
        host = _mapping(item, "host")
        address_text = host.get("address")
        status = host.get("status")
        if not isinstance(address_text, str) or not isinstance(status, str):
            raise ValueError("Discovery report host is malformed.")
        try:
            address = ipaddress.IPv4Address(address_text)
        except ipaddress.AddressValueError as error:
            raise ValueError("Discovery report host address is malformed.") from error
        if str(address) != address_text or address not in usable_addresses:
            raise ValueError("Discovery report host address is outside its target.")
        evidence = _list(host.get("evidence"), "host evidence")
        evidence_pairs = {
            (entry.get("kind"), entry.get("source"))
            for raw_entry in evidence
            for entry in (_mapping(raw_entry, "host evidence item"),)
        }
        has_neighbor_evidence = any(
            kind == "neighbor_cache" for kind, _source in evidence_pairs
        )
        has_gateway_evidence = (
            "default_gateway_route",
            "routing_table",
        ) in evidence_pairs
        text = str(address)
        if status == "local_machine":
            categories["local_computer_addresses"].append(text)
        elif status == "confirmed_responsive":
            categories["responsive_devices"].append(text)
        elif (
            status == "known_neighbor"
            and has_neighbor_evidence
            and not has_gateway_evidence
        ):
            categories["cache_only_devices"].append(text)
        if has_neighbor_evidence:
            categories["neighbor_cache_evidence_addresses"].append(text)
        # A status or role label alone is not enough.  The supporting local
        # default-route record is the sole evidence that confirms this role.
        if has_gateway_evidence:
            categories["confirmed_in_scope_gateways"].append(text)
    return {
        category: sorted(set(addresses), key=lambda text: int(ipaddress.IPv4Address(text)))
        for category, addresses in categories.items()
    }


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
        raise ValueError(f"Unsupported recommendation activity level: {activity_level}")
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


def _recommendations(cidr: str) -> list[dict[str, object]]:
    """Return the complete, ordered command catalogue for one safe CIDR."""
    return [
        _recommendation(
            identifier="inspect-local-ports",
            rank=1,
            command="driftbox ports",
            purpose="Inspect listening TCP and locally bound UDP ports on this machine.",
            reason="This can help compare the local machine's exposure with the discovery evidence without contacting discovered hosts.",
            target="this local machine",
            activity_level="LOCAL READ-ONLY",
            authorization_required="Permission to inspect this local machine; no additional network authorization is required.",
            expected_result="A local list of accessible listening ports, their bind scope, PID, and process name when available.",
            available_now=True,
            availability_status="available",
            availability_condition="Runs locally and does not probe discovered addresses.",
        ),
        _recommendation(
            identifier="inspect-local-firewall",
            rank=2,
            command="driftbox firewall",
            purpose="Inspect the local firewall status and available profile details.",
            reason="Firewall policy is separate local evidence and discovery cannot determine whether a host is reachable from another network.",
            target="this local machine",
            activity_level="LOCAL READ-ONLY",
            authorization_required="Permission to inspect this local machine; no additional network authorization is required.",
            expected_result="A read-only firewall status report; unavailable or unknown is reported rather than guessed.",
            available_now=True,
            availability_status="available",
            availability_condition="Runs locally and does not change firewall configuration.",
        ),
        _recommendation(
            identifier="capture-local-report",
            rank=3,
            command="driftbox report",
            purpose="Create a machine-readable local system, network, firewall, and listener report.",
            reason="A local report provides a separate baseline for review without expanding discovery to other hosts.",
            target="this local machine",
            activity_level="LOCAL READ-ONLY",
            authorization_required="Permission to inspect this local machine; no additional network authorization is required.",
            expected_result="Formatted JSON describing local system, network, firewall, and listener observations.",
            available_now=True,
            availability_status="available",
            availability_condition="Runs locally; review the report before sharing because it can contain sensitive local details.",
        ),
        _recommendation(
            identifier="repeat-authorized-discovery-json",
            rank=4,
            command=f"driftbox discover {cidr} --json",
            purpose="Display complete structured evidence from a new run of the same bounded host-evidence collection.",
            reason="The human view is summarized; JSON displays every per-address outcome in the same reviewed scope.",
            target=cidr,
            activity_level="ACTIVE AUTHORIZED SCAN",
            authorization_required=(
                f"Explicit authorization to inspect {cidr}; confirm ownership or permission immediately before running it."
            ),
            expected_result="Schema-versioned JSON is written to standard output; Driftbox does not save it automatically.",
            available_now=True,
            availability_status="available",
            availability_condition="The command exists now, but run it only with explicit authorization for the exact private CIDR shown above.",
        ),
    ]


def build_discovery_interpretation(report: Mapping[str, object]) -> dict[str, object]:
    """Build the versioned explanation and recommendations for a raw report.

    The function is deliberately pure: it performs no system inspection and no
    network activity.  It accepts only a validated numeric CIDR when constructing
    the one command that contains a target argument.
    """
    target = _mapping(report.get("target"), "target")
    settings = _mapping(report.get("settings"), "settings")
    summary = _mapping(report.get("summary"), "summary")
    authorization = _mapping(report.get("authorization"), "authorization")
    neighbor_cache = _mapping(report.get("neighbor_cache"), "neighbor_cache")
    raw_default_gateway = report.get("default_gateway")
    default_gateway = (
        {
            "status": "not_collected",
            "detail": "Discovery schema v1 did not collect routing-table evidence.",
            "records": [],
        }
        if raw_default_gateway is None
        else dict(_mapping(raw_default_gateway, "default_gateway"))
    )
    sources = _mapping(report.get("sources"), "sources")
    hosts = _list(report.get("hosts"), "hosts")
    limitations = _list(report.get("limitations"), "limitations")
    cidr = _validated_cidr(target)
    probe_outcomes = _validated_probe_outcomes(report.get("probe_outcomes"), cidr)
    host_categories = _host_address_categories(hosts, cidr)
    addresses_without_response = [
        outcome["address"]
        for outcome in probe_outcomes
        if outcome["status"] in {"no_response", "timeout"}
    ]
    addresses_with_probe_errors = [
        outcome["address"]
        for outcome in probe_outcomes
        if outcome["status"] in {"unavailable", "error"}
    ]
    no_reply_addresses = set(addresses_without_response)
    no_reply_with_neighbor_cache = [
        address
        for address in host_categories["neighbor_cache_evidence_addresses"]
        if address in no_reply_addresses
    ]
    incomplete_sources = _incomplete_sources(sources)

    host_count = sum(
        _integer(summary.get(key, 0), f"summary.{key}")
        for key in (
            "local_machine",
            "confirmed_responsive",
            "known_neighbor",
            "confirmed_gateway",
        )
    )
    responses = _integer(summary.get("responses_received", 0), "summary.responses_received")
    collection_status = str(report.get("collection_status", "unavailable"))

    meaning = [
        "A response proves only that the device answered at scan time.",
        "Cache evidence means this computer has seen the device, not necessarily that it is currently online.",
        "Silence does not prove an address is unused or offline.",
        "The discovered device count is a minimum supported by positive evidence.",
        "Unknown devices are not automatically suspicious or malicious.",
        "A confirmed gateway is only a local default-route next hop; it does not establish wider routing, identity, or reachability.",
    ]
    if collection_status != "completed":
        meaning.append(
            "Some collection sources were unavailable or incomplete, so interpret the positive evidence with the listed limitations."
        )

    return {
        "schema_version": INTERPRETATION_SCHEMA_VERSION,
        "discovery_summary": {
            "target_cidr": cidr,
            "collection_status": collection_status,
            "positive_host_evidence_count": host_count,
            "responses_received": responses,
            "addresses_probed": _integer(summary.get("addresses_probed", 0), "summary.addresses_probed"),
            **host_categories,
            "addresses_without_response": addresses_without_response,
            "addresses_with_probe_errors": addresses_with_probe_errors,
            "evidence_overlap": {
                "probe_no_reply_count": len(addresses_without_response),
                "no_reply_with_neighbor_cache_count": len(
                    no_reply_with_neighbor_cache
                ),
                "no_reply_with_neighbor_cache_addresses": (
                    no_reply_with_neighbor_cache
                ),
                "counts_are_additive": False,
                "outcomes_available": "probe_outcomes" in report,
            },
            "collection_errors_or_incomplete_evidence": {
                "sources": deepcopy(incomplete_sources),
                "addresses_with_probe_errors": addresses_with_probe_errors,
                "outcomes_available": "probe_outcomes" in report,
            },
            "authorization_scope": str(authorization.get("scope", "unavailable")),
        },
        "what_this_means": meaning,
        "recommendations": _recommendations(cidr),
        "detailed_evidence": {
            "target": deepcopy(dict(target)),
            "authorization": deepcopy(dict(authorization)),
            "collection": {
                "status": collection_status,
                "settings": deepcopy(dict(settings)),
                "sources": deepcopy(dict(sources)),
                "neighbor_cache": deepcopy(dict(neighbor_cache)),
                "default_gateway": deepcopy(default_gateway),
            },
            "probe_outcomes": probe_outcomes,
            "incomplete_evidence": {
                "sources": incomplete_sources,
                "addresses_with_probe_errors": addresses_with_probe_errors,
                "outcomes_available": "probe_outcomes" in report,
            },
            "hosts": deepcopy(hosts),
            "hostname_metadata": {
                "status": "not_collected",
                "reason": "Reverse DNS is intentionally disabled; hostnames are unavailable metadata.",
            },
            "limitations": deepcopy(limitations),
            "cautions": list(_CAUTIONS),
        },
    }


def with_discovery_interpretation(report: Mapping[str, object]) -> dict[str, object]:
    """Return a shallow copy of *report* with its deterministic interpretation."""
    result = dict(report)
    result["interpretation"] = build_discovery_interpretation(report)
    return result


def validate_recommendation_commands(
    recommendations: Sequence[object],
    parse_command: Callable[[list[str]], object],
) -> None:
    """Validate recommendation argv against the real CLI parser without running it."""
    import shlex

    for item in recommendations:
        recommendation = _mapping(item, "recommendation")
        command = recommendation.get("command")
        if not isinstance(command, str):
            raise ValueError("Recommendation command is malformed.")
        try:
            argv = shlex.split(command)
            # Commands are displayed as users run them, while argparse receives
            # only the arguments after the executable name.
            if argv[:1] != ["driftbox"]:
                raise ValueError("Recommendation command must invoke driftbox.")
            if len(argv) == 1:
                raise ValueError("Recommendation command has no CLI arguments.")
            parsed = parse_command(argv[1:])
            if getattr(parsed, "command", None) is None:
                raise ValueError("Recommendation command has no supported subcommand.")
        except (ValueError, SystemExit) as error:
            raise ValueError(f"Recommendation command is not supported: {command}") from error


__all__ = [
    "ACTIVITY_LEVELS",
    "INTERPRETATION_SCHEMA_VERSION",
    "build_discovery_interpretation",
    "validate_recommendation_commands",
    "with_discovery_interpretation",
]
