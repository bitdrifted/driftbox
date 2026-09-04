"""Pure, bounded normalization and presentation grouping for local listeners.

This module deliberately does not collect sockets or make exposure, service, or
vulnerability claims.  Its groups are display aids over complete local
observations: a group never means that its members are one socket.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import ipaddress
import json
import re
import unicodedata


LISTENER_PRESENTATION_SCHEMA_VERSION = 1
MAX_LISTENERS = 1_024
MAX_LISTENER_COUNT = MAX_LISTENERS
MAX_LISTENER_TEXT_LENGTH = 256
MAX_PROCESS_NAME_LENGTH = MAX_LISTENER_TEXT_LENGTH
MIN_PORT = 1
MAX_PORT = 65_535
MAX_PID = 2_147_483_647
DYNAMIC_PORT_MIN = 49_152
DYNAMIC_PORT_MAX = 65_535

_REQUIRED_FIELDS = frozenset({"protocol", "address", "port", "process", "scope"})
_ALLOWED_FIELDS = _REQUIRED_FIELDS | {"pid"}
_ANSI_ESCAPE = re.compile(
    r"(?:\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\))"
)
_SCOPE_ALIASES = {
    "all interfaces": "all interfaces",
    "all-interfaces": "all interfaces",
    "wildcard": "all interfaces",
    "local only": "local only",
    "local-only": "local only",
    "loopback": "local only",
    "link local": "link local",
    "link-local": "link local",
    "private network": "private network",
    "private-network": "private network",
    "public address": "public address",
    "public-address": "public address",
    "unknown": "unknown",
}
_PLATFORM_ALIASES = {
    "windows": "windows",
    "win32": "windows",
    "linux": "linux",
    "darwin": "macos",
    "macos": "macos",
    "mac os": "macos",
    "unknown": "unknown",
}


class ListenerValidationError(ValueError):
    """Raised when collected listener evidence is malformed or over bounds."""


def _clean_text(value: object, field: str, limit: int = MAX_LISTENER_TEXT_LENGTH) -> str:
    if not isinstance(value, str):
        raise ListenerValidationError(f"listener {field} must be text")
    # Remove complete ANSI sequences first so their parameters cannot leak into
    # a terminal.  Then remove every remaining control/format character.
    cleaned = _ANSI_ESCAPE.sub("", value)
    cleaned = "".join(
        char for char in cleaned if not unicodedata.category(char).startswith("C")
    )
    cleaned = unicodedata.normalize("NFC", cleaned).strip()
    if not cleaned:
        raise ListenerValidationError(f"listener {field} is empty after sanitization")
    if len(cleaned) > limit:
        raise ListenerValidationError(f"listener {field} exceeds the text bound")
    return cleaned


def normalize_platform(platform: object = "unknown") -> str:
    """Return a confirmed platform label; do not guess unknown platforms."""
    candidate = _clean_text(platform, "platform").casefold()
    normalized = _PLATFORM_ALIASES.get(candidate)
    if normalized is None:
        raise ListenerValidationError("listener platform is unsupported or ambiguous")
    return normalized


def _normalize_protocol(value: object) -> str:
    protocol = _clean_text(value, "protocol").casefold()
    if protocol not in {"tcp", "udp"}:
        raise ListenerValidationError("listener protocol must be TCP or UDP")
    return protocol


def _normalize_address(value: object) -> str:
    address = _clean_text(value, "address")
    # A zone identifier makes a specific IPv6 address interface-dependent.  It
    # is retained when syntactically safe, and wildcard addresses may not have
    # one because that would be contradictory evidence.
    host, separator, zone = address.partition("%")
    if separator and (not zone or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", zone)):
        raise ListenerValidationError("listener address has an ambiguous IPv6 zone")
    try:
        parsed = ipaddress.ip_address(host)
    except ValueError as error:
        raise ListenerValidationError("listener address is not an IP address") from error
    if separator and parsed.is_unspecified:
        raise ListenerValidationError("wildcard listener address cannot have an IPv6 zone")
    return f"{parsed.compressed}%{zone}" if separator else parsed.compressed


def _normalize_scope(value: object, address: str) -> str:
    scope_text = _clean_text(value, "scope").casefold()
    scope = _SCOPE_ALIASES.get(scope_text)
    if scope is None:
        raise ListenerValidationError("listener scope is unsupported or ambiguous")
    is_wildcard = address.split("%", 1)[0] in {"0.0.0.0", "::"}
    if is_wildcard != (scope == "all interfaces"):
        raise ListenerValidationError("listener scope contradicts its address")
    return scope


def _normalize_port(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ListenerValidationError("listener port must be an integer")
    if not MIN_PORT <= value <= MAX_PORT:
        raise ListenerValidationError("listener port is outside the valid range")
    return value


def _normalize_pid(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ListenerValidationError("listener pid must be an integer or null")
    if not 0 <= value <= MAX_PID:
        raise ListenerValidationError("listener pid is outside the valid range")
    return value


def _process_identity(process: str) -> str:
    """Return a display-independent process key; PID is intentionally absent."""
    return " ".join(process.casefold().split())


def normalize_listener(listener: object) -> dict[str, object]:
    """Validate one collected listener and return sanitized, canonical evidence."""
    if not isinstance(listener, Mapping):
        raise ListenerValidationError("listener must be an object")
    keys = set(listener)
    if not _REQUIRED_FIELDS <= keys:
        raise ListenerValidationError("listener is missing required evidence")
    if not keys <= _ALLOWED_FIELDS:
        raise ListenerValidationError("listener contains unsupported evidence fields")
    protocol_raw = _clean_text(listener["protocol"], "protocol")
    address_raw = _clean_text(listener["address"], "address")
    process_raw = _clean_text(listener["process"], "process", MAX_PROCESS_NAME_LENGTH)
    scope_raw = _clean_text(listener["scope"], "scope")
    port = _normalize_port(listener["port"])
    pid = _normalize_pid(listener.get("pid"))
    protocol = _normalize_protocol(protocol_raw)
    address = _normalize_address(address_raw)
    scope = _normalize_scope(scope_raw, address)
    raw: dict[str, object] = {
        "protocol": protocol_raw,
        "address": address_raw,
        "port": port,
        "process": process_raw,
        "scope": scope_raw,
    }
    if "pid" in listener:
        raw["pid"] = pid
    return {
        # Flat canonical fields make this useful to existing renderers.
        "protocol": protocol,
        "address": address,
        "port": port,
        "process": process_raw,
        "scope": scope,
        "pid": pid,
        "normalized_process": _process_identity(process_raw),
        # This is the complete, sanitized source endpoint (including PID when
        # it was supplied); it is intentionally not discarded during grouping.
        "raw": raw,
    }


def _member_sort_key(member: Mapping[str, object]) -> tuple[object, ...]:
    raw = member["raw"]
    return (
        str(member["protocol"]),
        int(member["port"]),
        str(member["normalized_process"]),
        str(member["address"]),
        -1 if member["pid"] is None else int(member["pid"]),
        json.dumps(raw, ensure_ascii=True, sort_keys=True, separators=(",", ":")),
    )


def normalize_listeners(listeners: object) -> list[dict[str, object]]:
    """Validate a bounded sequence and deterministically retain every endpoint."""
    if not isinstance(listeners, Sequence) or isinstance(listeners, (str, bytes, bytearray)):
        raise ListenerValidationError("listeners must be an array")
    if len(listeners) > MAX_LISTENERS:
        raise ListenerValidationError("listener count exceeds the collection bound")
    normalized = [normalize_listener(item) for item in listeners]
    return sorted(normalized, key=_member_sort_key)


def _is_wildcard(member: Mapping[str, object]) -> bool:
    return (
        member["scope"] == "all interfaces"
        and member["address"] in {"0.0.0.0", "::"}
    )


def _group_id(group_type: str, key: tuple[object, ...]) -> str:
    payload = json.dumps([group_type, *key], ensure_ascii=True, separators=(",", ":"))
    return f"listener-{group_type}-{hashlib.sha256(payload.encode()).hexdigest()[:16]}"


def _presentation_group(
    group_type: str, key: tuple[object, ...], reason: str, members: Sequence[dict[str, object]]
) -> dict[str, object]:
    return {
        "id": _group_id(group_type, key),
        "type": group_type,
        "reason": reason,
        "members": sorted(members, key=_member_sort_key),
    }


def group_listener_presentation(
    listeners: object, platform: object = "unknown"
) -> dict[str, object]:
    """Return deterministic, conservative display groups over all endpoints.

    A PID is preserved in every member but excluded from every group identity.
    Group descriptions are observations, never assertions of service identity,
    exploitability, safety, or reachability.
    """
    normalized = normalize_listeners(listeners)
    normalized_platform = normalize_platform(platform)
    remaining = set(range(len(normalized)))
    groups: list[dict[str, object]] = []

    def take_buckets(
        group_type: str,
        candidates: dict[tuple[object, ...], list[int]],
        reason: str,
        require_distinct_ports: bool = False,
    ) -> None:
        for key in sorted(candidates, key=lambda item: tuple(str(part) for part in item)):
            indexes = [index for index in candidates[key] if index in remaining]
            if len(indexes) < 2:
                continue
            if require_distinct_ports and len({normalized[index]["port"] for index in indexes}) < 2:
                continue
            for index in indexes:
                remaining.remove(index)
            groups.append(_presentation_group(group_type, key, reason, [normalized[index] for index in indexes]))

    # Windows dynamic-port grouping is deliberately gated on confirmed Windows,
    # matching TCP process identity, and wildcard bindings only.
    if normalized_platform == "windows":
        rpc: dict[tuple[object, ...], list[int]] = {}
        for index, member in enumerate(normalized):
            if (
                member["protocol"] == "tcp"
                and _is_wildcard(member)
                and DYNAMIC_PORT_MIN <= int(member["port"]) <= DYNAMIC_PORT_MAX
            ):
                rpc.setdefault(("windows", member["protocol"], member["normalized_process"]), []).append(index)
        take_buckets(
            "windows-dynamic-rpc-compatible",
            rpc,
            "Wildcard-bound TCP ports in the Windows dynamic RPC range are compatible observations for this same untrusted process label; they do not prove every port is RPC.",
            require_distinct_ports=True,
        )

    udp: dict[tuple[object, ...], list[int]] = {}
    for index, member in enumerate(normalized):
        if (
            member["protocol"] == "udp"
            and _is_wildcard(member)
            and DYNAMIC_PORT_MIN <= int(member["port"]) <= DYNAMIC_PORT_MAX
        ):
            udp.setdefault((member["protocol"], member["normalized_process"]), []).append(index)
    take_buckets(
        "dynamic-udp-wildcard-observations",
        udp,
        "Repeated high-numbered wildcard UDP bindings are presented as dynamic UDP observations for the same untrusted process label.",
        require_distinct_ports=True,
    )

    dual_stack: dict[tuple[object, ...], list[int]] = {}
    for index in sorted(remaining):
        member = normalized[index]
        if _is_wildcard(member):
            dual_stack.setdefault((member["protocol"], member["port"], member["normalized_process"]), []).append(index)
    for key, indexes in list(dual_stack.items()):
        families = {normalized[index]["address"] for index in indexes}
        if families != {"0.0.0.0", "::"}:
            del dual_stack[key]
    take_buckets(
        "dual-stack-wildcard-observations",
        dual_stack,
        "IPv4 and IPv6 wildcard bindings share protocol, port, and process identity; this presentation group does not claim they are one socket.",
    )

    # Collapse duplicate reports of exactly one endpoint, while ordinary
    # endpoints remain singleton groups.  PID deliberately does not split it.
    exact: dict[tuple[object, ...], list[int]] = {}
    for index in sorted(remaining):
        member = normalized[index]
        exact.setdefault((member["protocol"], member["address"], member["port"], member["normalized_process"], member["scope"]), []).append(index)
    take_buckets(
        "equivalent-endpoint-observations",
        exact,
        "Multiple collected records have the same normalized endpoint identity; PID remains preserved in each observation.",
    )

    for index in sorted(remaining):
        member = normalized[index]
        key = (member["protocol"], member["address"], member["port"], member["normalized_process"], member["scope"])
        groups.append(_presentation_group(
            "endpoint-observation",
            key,
            "A single normalized listener observation is retained without compatibility grouping.",
            [member],
        ))
    groups.sort(key=lambda group: (str(group["id"]), str(group["type"])))
    return {
        "schema_version": LISTENER_PRESENTATION_SCHEMA_VERSION,
        "platform": normalized_platform,
        "listener_count": len(normalized),
        "groups": groups,
    }


# A descriptive alias gives integration code a natural entry point.
build_listener_presentation = group_listener_presentation


__all__ = [
    "DYNAMIC_PORT_MAX",
    "DYNAMIC_PORT_MIN",
    "LISTENER_PRESENTATION_SCHEMA_VERSION",
    "ListenerValidationError",
    "MAX_LISTENER_COUNT",
    "MAX_LISTENER_TEXT_LENGTH",
    "MAX_LISTENERS",
    "MAX_PID",
    "MAX_PORT",
    "MAX_PROCESS_NAME_LENGTH",
    "MIN_PORT",
    "build_listener_presentation",
    "group_listener_presentation",
    "normalize_listener",
    "normalize_listeners",
    "normalize_platform",
]
