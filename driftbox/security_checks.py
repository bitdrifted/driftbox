"""Pure, deterministic posture triage for collected local evidence."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import re
import unicodedata

from driftbox.posture_listeners import build_listener_presentation

CHECK_SCHEMA_VERSION = 2
TRIAGE_LEVELS = ("informational", "review", "urgent")
TRIAGE_TO_UNIFIED = {
    "informational": "normal",
    "review": "suspicious",
    "urgent": "critical",
}
TERMINAL_GROUP_LIMIT = 10
MAX_FIREWALL_PROFILES = 32
MAX_FIREWALL_TEXT_LENGTH = 256

_ANSI_ESCAPE = re.compile(
    r"(?:\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\))"
)
_KNOWN_PLATFORMS = {
    "windows": "windows",
    "linux": "linux",
    "darwin": "macos",
    "macos": "macos",
    "mac os": "macos",
    "unknown": "unknown",
}
_FIREWALL_STATUSES = {"enabled", "disabled", "unknown", "mixed"}
_REMOTE_MANAGEMENT_PORTS = {
    22: "remote shell administration",
    23: "legacy remote terminal administration",
    3389: "Remote Desktop administration",
    5900: "remote desktop administration",
    5985: "Windows remote management",
    5986: "Windows remote management over TLS",
    8443: "alternate HTTPS or management interfaces",
}


@dataclass(frozen=True)
class PostureTriageItem:
    """One validated posture item with an explicit unified mapping."""

    id: str
    category: str
    triage_level: str
    unified_classification: str
    title: str
    explanation: str
    uncertainty: str
    evidence: dict[str, object]
    recommendation_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if TRIAGE_TO_UNIFIED.get(self.triage_level) != self.unified_classification:
            raise ValueError("invalid posture triage classification mapping")
        if self.category not in {"firewall", "listener_group"}:
            raise ValueError("invalid posture triage category")

    def as_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["recommendation_ids"] = list(self.recommendation_ids)
        return result


@dataclass(frozen=True)
class SecurityPostureResult:
    """Complete bounded evidence and presentation groups for local triage."""

    firewall: dict[str, object]
    raw_endpoints: tuple[dict[str, object], ...]
    presentation_groups: tuple[dict[str, object], ...]
    triage_items: tuple[PostureTriageItem, ...]
    recommendations: tuple[dict[str, object], ...]
    limitations: tuple[str, ...]
    provenance: dict[str, object]

    @property
    def actionable(self) -> bool:
        return any(
            item.triage_level in {"review", "urgent"}
            for item in self.triage_items
        )

    def as_dict(self) -> dict[str, object]:
        """Return the dedicated version-two posture-triage document."""
        triage_counts = {
            level: sum(item.triage_level == level for item in self.triage_items)
            for level in TRIAGE_LEVELS
        }
        unified_counts = {
            classification: sum(
                item.unified_classification == classification
                for item in self.triage_items
            )
            for classification in ("normal", "suspicious", "critical")
        }
        preview_count = min(len(self.presentation_groups), TERMINAL_GROUP_LIMIT)
        priority_items = [
            {
                "id": item.id,
                "category": item.category,
                "triage_level": item.triage_level,
                "unified_classification": item.unified_classification,
                "title": item.title,
                "explanation": item.explanation,
                "uncertainty": item.uncertainty,
            }
            for item in self.triage_items
            if item.triage_level in {"review", "urgent"}
        ]
        raw_count = len(self.raw_endpoints)
        group_count = len(self.presentation_groups)
        return {
            "schema_version": CHECK_SCHEMA_VERSION,
            "engine": "driftbox-posture-triage",
            "firewall": self.firewall,
            "summary": {
                "raw_endpoint_count": raw_count,
                "presentation_group_count": group_count,
                "endpoints_consolidated_for_presentation": max(0, raw_count - group_count),
                "triage": triage_counts,
                "unified": unified_counts,
                "priority_item_count": len(priority_items),
            },
            "terminal_preview": {
                "maximum_service_groups": TERMINAL_GROUP_LIMIT,
                "service_groups_shown": preview_count,
                "bounded": group_count > preview_count,
            },
            "priority_items": priority_items,
            "raw_endpoints": list(self.raw_endpoints),
            "presentation_groups": list(self.presentation_groups),
            "recommended_next_steps": list(self.recommendations),
            "limitations": list(self.limitations),
            "evidence_provenance": self.provenance,
        }


def _clean_text(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"firewall {field} must be text")
    cleaned = _ANSI_ESCAPE.sub("", value)
    cleaned = "".join(
        char for char in cleaned if not unicodedata.category(char).startswith("C")
    )
    cleaned = unicodedata.normalize("NFC", cleaned).strip()
    if not cleaned:
        raise ValueError(f"firewall {field} is empty after sanitization")
    if len(cleaned) > MAX_FIREWALL_TEXT_LENGTH:
        raise ValueError(f"firewall {field} exceeds the text bound")
    return cleaned


def _validate_profile(profile: object, index: int) -> dict[str, object]:
    if not isinstance(profile, dict):
        raise ValueError(f"firewall profile {index} must be an object")
    allowed = {"name", "enabled", "default_inbound", "default_outbound"}
    if not set(profile) <= allowed:
        raise ValueError(f"firewall profile {index} contains unsupported evidence")
    if "name" not in profile or "enabled" not in profile:
        raise ValueError(f"firewall profile {index} is missing required evidence")
    enabled = profile["enabled"]
    if enabled is not None and not isinstance(enabled, bool):
        raise ValueError(f"firewall profile {index} enabled must be boolean or null")
    result: dict[str, object] = {
        "name": _clean_text(profile["name"], "profile name"),
        "enabled": enabled,
    }
    for field in ("default_inbound", "default_outbound"):
        if field in profile:
            result[field] = _clean_text(profile[field], f"profile {field}")
    return result


def _validate_firewall(firewall: object) -> dict[str, object]:
    if not isinstance(firewall, dict):
        raise ValueError("firewall inspection result must be an object")
    required = {"status"}
    allowed = required | {"platform", "provider", "profiles"}
    if not required <= set(firewall):
        raise ValueError("firewall inspection result is missing required evidence")
    if not set(firewall) <= allowed:
        raise ValueError("firewall inspection result contains unsupported evidence")
    platform = _clean_text(firewall.get("platform", "unknown"), "platform")
    provider = _clean_text(firewall.get("provider", "unknown"), "provider")
    status = _clean_text(firewall["status"], "status").casefold()
    if status not in _FIREWALL_STATUSES:
        raise ValueError("firewall status is unsupported or ambiguous")
    profiles = firewall.get("profiles", [])
    if not isinstance(profiles, list):
        raise ValueError("firewall profiles must be an array")
    if len(profiles) > MAX_FIREWALL_PROFILES:
        raise ValueError("firewall profile count exceeds the collection bound")
    validated_profiles = [
        _validate_profile(profile, index)
        for index, profile in enumerate(profiles)
    ]
    enabled_values = [profile["enabled"] for profile in validated_profiles]
    if status == "enabled" and enabled_values and not all(
        value is True for value in enabled_values
    ):
        raise ValueError("firewall status conflicts with profile evidence")
    if status == "disabled" and enabled_values and not all(
        value is False for value in enabled_values
    ):
        raise ValueError("firewall status conflicts with profile evidence")
    return {
        "platform": platform,
        "provider": provider,
        "status": status,
        "profiles": validated_profiles,
    }


def _group_members(group: dict[str, object]) -> list[dict[str, object]]:
    members = group.get("members")
    if not isinstance(members, list) or not members:
        raise ValueError("listener presentation group must retain members")
    if not all(isinstance(member, dict) for member in members):
        raise ValueError("listener presentation group member is invalid")
    return members


def _group_ports(group: dict[str, object]) -> tuple[int, ...]:
    return tuple(sorted({int(member["port"]) for member in _group_members(group)}))


def _group_protocols(group: dict[str, object]) -> tuple[str, ...]:
    return tuple(
        sorted({str(member["protocol"]) for member in _group_members(group)})
    )


def _service_context(
    group: dict[str, object], platform: str
) -> tuple[str, str, bool]:
    """Return family, cautious context, and sensitive-review signal."""
    ports = _group_ports(group)
    protocols = _group_protocols(group)
    group_type = group.get("type")
    if group_type == "windows-dynamic-rpc-compatible":
        return (
            "windows-rpc-dynamic-range",
            "Windows commonly uses this range for dynamic RPC endpoints.",
            True,
        )
    if 135 in ports and "tcp" in protocols:
        return (
            "windows-rpc",
            "TCP port 135 is commonly associated with Windows RPC infrastructure.",
            True,
        )
    if set(ports) & {137, 138, 139, 445}:
        return (
            "netbios-smb",
            "Ports 137-139 and 445 are commonly associated with NetBIOS/SMB file and printer sharing.",
            True,
        )
    if 123 in ports:
        return (
            "time-synchronization",
            "Port 123 is commonly associated with time synchronization.",
            False,
        )
    if set(ports) & {500, 4500}:
        return (
            "ipsec-ike",
            "Ports 500 and 4500 are commonly associated with IPsec/IKE negotiation.",
            False,
        )
    if 5353 in ports:
        return (
            "mdns",
            "Port 5353 is commonly associated with multicast DNS discovery.",
            False,
        )
    if 5355 in ports:
        return (
            "llmnr",
            "Port 5355 is commonly associated with LLMNR name resolution.",
            False,
        )
    if 7680 in ports and platform == "windows":
        return (
            "windows-delivery-optimization",
            "Port 7680 is commonly associated with Windows Delivery Optimization.",
            False,
        )
    management = [
        _REMOTE_MANAGEMENT_PORTS[port]
        for port in ports
        if port in _REMOTE_MANAGEMENT_PORTS
    ]
    if management and "tcp" in protocols:
        return (
            "remote-administration-context",
            "The observed port is commonly used for " + management[0] + ".",
            True,
        )
    if group_type == "dynamic-udp-wildcard-observations":
        return (
            "dynamic-udp",
            "These are repeated high-numbered wildcard UDP observations.",
            False,
        )
    return (
        "unrecognized",
        "No specific service family is established by the collected port evidence.",
        False,
    )


def _decorate_group(
    group: dict[str, object], platform: str, firewall_status: str
) -> tuple[dict[str, object], PostureTriageItem]:
    ports = _group_ports(group)
    protocols = _group_protocols(group)
    family, context, sensitive = _service_context(group, platform)
    scopes = {str(member["scope"]) for member in _group_members(group)}
    public_binding = "public address" in scopes
    wildcard_binding = "all interfaces" in scopes
    if public_binding:
        level = "review"
        explanation = (
            "A listener is bound to a public address, so the binding warrants "
            "operator review. Binding does not prove internet reachability."
        )
    elif wildcard_binding and sensitive:
        level = "review"
        explanation = (
            f"{context} The broad binding warrants review to confirm the service "
            "is expected and appropriately controlled."
        )
    else:
        level = "informational"
        if wildcard_binding and firewall_status == "enabled":
            explanation = (
                f"{context} With no stronger deterministic signal, this generic "
                "wildcard observation is informational. The reported enabled "
                "firewall does not prove the listener is blocked or safe."
            )
        else:
            explanation = (
                f"{context} This observation remains visible as context but is "
                "not independently actionable from the collected evidence."
            )
    uncertainty = (
        "Port numbers and untrusted process labels do not prove service identity, "
        "reachability, vulnerability, compromise, or safety."
    )
    members = _group_members(group)
    decorated = {
        "id": group["id"],
        "type": group["type"],
        "grouping_reason": group["reason"],
        "service_family": family,
        "service_context": context,
        "triage_level": level,
        "unified_classification": TRIAGE_TO_UNIFIED[level],
        "explanation": explanation,
        "uncertainty": uncertainty,
        "raw_endpoint_count": len(members),
        "members": members,
    }
    port_label = ", ".join(str(port) for port in ports[:5])
    if len(ports) > 5:
        port_label += f", and {len(ports) - 5} more"
    protocol_label = "/".join(protocol.upper() for protocol in protocols)
    title = f"{family.replace('-', ' ').title()} - {protocol_label} {port_label}"
    item = PostureTriageItem(
        id=str(group["id"]),
        category="listener_group",
        triage_level=level,
        unified_classification=TRIAGE_TO_UNIFIED[level],
        title=title,
        explanation=explanation,
        uncertainty=uncertainty,
        evidence=decorated,
        recommendation_ids=("inspect-ports", "preserve-json-evidence"),
    )
    return decorated, item


def _firewall_item(firewall: dict[str, object]) -> PostureTriageItem:
    status = str(firewall["status"])
    if status == "disabled":
        level = "urgent"
        title = "Firewall is confirmed disabled"
        explanation = (
            "The collected firewall evidence confirms a disabled state, which is "
            "a high-priority posture problem for operator and asset-owner review."
        )
    elif status in {"unknown", "mixed"}:
        level = "review"
        title = "Firewall protection cannot be assumed"
        explanation = (
            "The collected firewall state is unknown or mixed, so consistent "
            "inbound protection cannot be assumed."
        )
    else:
        level = "informational"
        title = "Firewall is reported enabled"
        explanation = (
            "The collected provider status reports the firewall enabled. Driftbox "
            "did not collect enough rule evidence to prove any listener is blocked."
        )
    uncertainty = (
        "Firewall status alone does not establish inbound-rule behavior, network "
        "reachability, or system safety."
    )
    return PostureTriageItem(
        id="firewall-state",
        category="firewall",
        triage_level=level,
        unified_classification=TRIAGE_TO_UNIFIED[level],
        title=title,
        explanation=explanation,
        uncertainty=uncertainty,
        evidence=firewall,
        recommendation_ids=("inspect-firewall", "preserve-json-evidence"),
    )


def _group_sort_key(group: dict[str, object]) -> tuple[object, ...]:
    priority = {"urgent": 0, "review": 1, "informational": 2}
    members = _group_members(group)
    first = members[0]
    return (
        priority[str(group["triage_level"])],
        min(int(member["port"]) for member in members),
        str(first["protocol"]),
        str(first["normalized_process"]),
        str(group["id"]),
    )


def _recommendations() -> tuple[dict[str, object], ...]:
    return (
        {
            "id": "inspect-firewall",
            "command": "driftbox firewall",
            "kind": "local-read-only",
            "purpose": "Review reported firewall status and available profile evidence.",
        },
        {
            "id": "inspect-ports",
            "command": "driftbox ports",
            "kind": "local-read-only",
            "purpose": "Review complete local listener endpoints and observed process labels.",
        },
        {
            "id": "preserve-json-evidence",
            "command": "driftbox check --json",
            "kind": "local-read-only",
            "purpose": "Preserve complete posture-triage evidence for authorized review.",
        },
        {
            "id": "capture-local-report",
            "command": "driftbox report",
            "kind": "local-read-only",
            "purpose": "Create a complete local JSON report when comparison evidence is needed.",
        },
    )


def analyze_security_posture(
    firewall: object,
    listening_ports: object,
) -> SecurityPostureResult:
    """Triage already-collected evidence without subprocesses or network access."""
    validated_firewall = _validate_firewall(firewall)
    platform = _KNOWN_PLATFORMS.get(
        str(validated_firewall["platform"]).casefold(), "unknown"
    )
    presentation = build_listener_presentation(listening_ports, platform=platform)
    raw_groups = presentation.get("groups")
    if not isinstance(raw_groups, list) or not all(
        isinstance(group, dict) for group in raw_groups
    ):
        raise ValueError("invalid listener presentation result")
    pairs = [
        _decorate_group(group, platform, str(validated_firewall["status"]))
        for group in raw_groups
    ]
    groups = tuple(sorted((pair[0] for pair in pairs), key=_group_sort_key))
    item_by_id = {pair[1].id: pair[1] for pair in pairs}
    group_items = tuple(item_by_id[str(group["id"])] for group in groups)
    raw_endpoints = tuple(
        member for group in groups for member in _group_members(group)
    )
    if len(raw_endpoints) != presentation.get("listener_count"):
        raise ValueError("listener presentation did not retain every raw endpoint")
    return SecurityPostureResult(
        firewall=validated_firewall,
        raw_endpoints=raw_endpoints,
        presentation_groups=groups,
        triage_items=(_firewall_item(validated_firewall), *group_items),
        recommendations=_recommendations(),
        limitations=(
            "Presentation groups consolidate related observations for explanation; they do not assert that members are one socket.",
            "Process names are untrusted observations, and port numbers do not prove service identity.",
            "Firewall inbound-rule behavior, routing, NAT, internet reachability, vulnerability, compromise, and patch state were not established.",
            "No scan, discovery, vulnerability lookup, configuration change, process action, or recommendation execution occurs during triage.",
        ),
        provenance={
            "analysis": "pure deterministic rules over local firewall and listener collector output",
            "listener_presentation_schema_version": presentation.get("schema_version"),
            "network_requests": 0,
            "commands_executed_by_triage": 0,
        },
    )


def _ports_label(group: dict[str, object]) -> str:
    ports = _group_ports(group)
    preview = ", ".join(str(port) for port in ports[:5])
    if len(ports) > 5:
        preview += f", and {len(ports) - 5} more"
    return preview


def format_check_result(result: SecurityPostureResult) -> str:
    """Format a concise default preview while JSON retains complete evidence."""
    if not isinstance(result, SecurityPostureResult):
        raise ValueError("invalid posture triage result")
    data = result.as_dict()
    summary = data["summary"]
    if not isinstance(summary, dict) or not isinstance(summary.get("triage"), dict):
        raise ValueError("invalid posture triage summary")
    triage = summary["triage"]
    raw_count = int(summary["raw_endpoint_count"])
    group_count = int(summary["presentation_group_count"])
    consolidated = int(summary["endpoints_consolidated_for_presentation"])
    lines = [
        "POSTURE SUMMARY",
        f"Firewall: {result.firewall['status']} (observed provider: {result.firewall['provider']}).",
        f"{raw_count} raw endpoint(s) form {group_count} presentation group(s); {consolidated} endpoint(s) were consolidated for presentation.",
        f"Triage items: {triage['urgent']} urgent, {triage['review']} review, {triage['informational']} informational.",
        "Complete raw endpoints and all group members remain available in `driftbox check --json`.",
        "",
        "BOTTOM LINE",
    ]
    if triage["urgent"]:
        lines.append(
            "An urgent confirmed firewall posture problem requires prompt owner review; listener evidence is prioritized separately."
        )
    elif triage["review"]:
        lines.append(
            "One or more evidence-based posture items warrant review; no listener is declared reachable, vulnerable, compromised, or safe."
        )
    else:
        lines.append(
            "No urgent or review item was established. Informational evidence is not a claim of safety, protection, or absence of vulnerabilities."
        )
    lines.extend(["", "PRIORITY REVIEW"])
    priority = sorted(
        (
            item
            for item in result.triage_items
            if item.triage_level in {"urgent", "review"}
            and item.category == "firewall"
        ),
        key=lambda item: (
            {"urgent": 0, "review": 1}[item.triage_level],
            item.category,
            item.id,
        ),
    )
    priority_group_count = sum(
        item.triage_level in {"urgent", "review"}
        and item.category == "listener_group"
        for item in result.triage_items
    )
    if not priority and not priority_group_count:
        lines.append("No urgent or review item was established from the collected evidence.")
    else:
        for item in priority:
            lines.append(
                f"- [{item.triage_level.upper()}] {item.title}: {item.explanation}"
            )
        if priority_group_count:
            lines.append(
                f"- {priority_group_count} listener service group(s) warrant review and appear first below."
            )
    lines.extend(["", "SERVICE GROUPS"])
    if not result.presentation_groups:
        lines.append("No accessible listener endpoints were collected.")
    else:
        for group in result.presentation_groups[:TERMINAL_GROUP_LIMIT]:
            members = _group_members(group)
            processes = sorted({str(member["process"]) for member in members})
            process_label = ", ".join(processes[:2])
            if len(processes) > 2:
                process_label += f", and {len(processes) - 2} more"
            protocols = "/".join(
                protocol.upper() for protocol in _group_protocols(group)
            )
            lines.append(
                f"- [{str(group['triage_level']).upper()}] {protocols} port(s) {_ports_label(group)}; "
                f"{group['raw_endpoint_count']} raw endpoint(s); observed process={process_label}; "
                f"family={group['service_family']}"
            )
            lines.append(f"  {group['explanation']}")
        hidden = group_count - min(group_count, TERMINAL_GROUP_LIMIT)
        if hidden:
            lines.append(
                f"- and {hidden} more service group(s); use `driftbox check --json` for complete evidence"
            )
    lines.extend(["", "RECOMMENDED NEXT STEPS"])
    for step in result.recommendations:
        lines.append(
            f"- {step['command']} - {step['purpose']} This recommendation is not executed automatically."
        )
    lines.extend(
        [
            "",
            "SOURCES AND LIMITATIONS",
            "- Sources: local firewall status/profile evidence and local listener observations already collected by Driftbox.",
        ]
    )
    lines.extend(f"- {limitation}" for limitation in result.limitations)
    return "\n".join(lines)
