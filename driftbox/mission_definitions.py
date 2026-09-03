"""Deterministic synthetic definitions for Driftbox training missions."""

from __future__ import annotations

from copy import deepcopy

MISSION_DEFINITION_SCHEMA_VERSION = 2

_BASELINE_REPORT = {
    "schema_version": 1,
    "driftbox_version": "0.1.0-training",
    "generated_at": "2030-04-12T07:45:00+00:00",
    "system": {
        "hostname": "smmc-north-ops-04",
        "operating_system": "SyntheticOS",
    },
    "network": {"ipv4_addresses": ["10.24.8.44"]},
    "firewall": {
        "platform": "SyntheticOS",
        "provider": "Meridian Host Guard",
        "status": "enabled",
    },
    "exposure": {
        "listening_ports": [
            {
                "protocol": "TCP",
                "address": "127.0.0.1",
                "port": 631,
                "pid": 4100,
                "process": "print-helper",
                "scope": "local only",
            }
        ]
    },
}

_CURRENT_REPORT = {
    "schema_version": 1,
    "driftbox_version": "0.1.0-training",
    "generated_at": "2030-04-12T08:15:00+00:00",
    "system": {
        "hostname": "smmc-north-ops-04",
        "operating_system": "SyntheticOS",
    },
    "network": {"ipv4_addresses": ["10.24.8.44"]},
    "firewall": {
        "platform": "SyntheticOS",
        "provider": "Meridian Host Guard",
        "status": "disabled",
    },
    "exposure": {
        "listening_ports": [
            {
                "protocol": "TCP",
                "address": "127.0.0.1",
                "port": 631,
                "pid": 7822,
                "process": "print-helper",
                "scope": "local only",
            },
            {
                "protocol": "TCP",
                "address": "0.0.0.0",
                "port": 8443,
                "pid": 9130,
                "process": "med-records-sync",
                "scope": "all interfaces",
            },
        ]
    },
}

_BASELINE_INTEGRITY = {
    "schema_version": 1,
    "algorithm": "sha256",
    "root_type": "directory",
    "files": [
        {
            "path": "config/records-sync.conf",
            "size": 86,
            "sha256": "1" * 64,
        },
        {
            "path": "config/workstation-banner.txt",
            "size": 44,
            "sha256": "2" * 64,
        },
    ],
}

_CURRENT_INTEGRITY = {
    "schema_version": 1,
    "algorithm": "sha256",
    "root_type": "directory",
    "files": [
        {
            "path": "config/records-sync.conf",
            "size": 112,
            "sha256": "3" * 64,
        },
        {
            "path": "config/workstation-banner.txt",
            "size": 44,
            "sha256": "2" * 64,
        },
    ],
}

_FIRST_WATCH = {
    "schema_version": MISSION_DEFINITION_SCHEMA_VERSION,
    "id": "first-watch",
    "title": "First Watch",
    "organization": {
        "name": "St. Meridian Medical Center",
        "sector": "healthcare",
        "fictional": True,
    },
    "environment": {
        "name": "North Ward Operations",
        "type": "synthetic hospital security lab",
        "data_source": "synthetic",
    },
    "difficulty": "introductory",
    "learner_role": "Newly assigned security analyst",
    "objectives": [
        "Compare trusted and current evidence.",
        "Identify and classify meaningful security changes.",
        "Prioritize findings and select practical response actions.",
        "Avoid escalating harmless volatile changes.",
    ],
    "brief": (
        "Your shift begins with a workstation alert from North Ward Operations. "
        "Review the synthetic trusted and current evidence, decide what matters, "
        "and submit a prioritized response for the hospital security team."
    ),
    "evidence": {
        "baseline_report": _BASELINE_REPORT,
        "current_report": _CURRENT_REPORT,
        "baseline_integrity": _BASELINE_INTEGRITY,
        "current_integrity": _CURRENT_INTEGRITY,
        "items": [
            {
                "id": "EV-001",
                "title": "Firewall telemetry",
                "details": "Trusted status: enabled. Current status: disabled.",
            },
            {
                "id": "EV-002",
                "title": "Listener telemetry",
                "details": (
                    "A new TCP listener is present at 0.0.0.0:8443 for the "
                    "synthetic process med-records-sync."
                ),
            },
            {
                "id": "EV-003",
                "title": "Integrity telemetry",
                "details": (
                    "config/records-sync.conf has a different size and SHA-256 "
                    "value from the trusted manifest."
                ),
            },
            {
                "id": "EV-004",
                "title": "Routine process telemetry",
                "details": (
                    "The local-only print-helper endpoint is unchanged, but its "
                    "synthetic process ID changed from 4100 to 7822."
                ),
            },
        ],
        "action_choices": [
            {
                "id": "restore-firewall",
                "description": (
                    "Validate the change and restore the intended firewall policy."
                ),
            },
            {
                "id": "validate-service-controls",
                "description": (
                    "Confirm the service is authorized and review binding, firewall, "
                    "routing, and NAT controls."
                ),
            },
            {
                "id": "investigate-restore",
                "description": (
                    "Investigate authorization and restore a trusted configuration "
                    "if the change is not approved."
                ),
            },
            {
                "id": "verify-expected",
                "description": (
                    "Confirm the routine change is expected and continue monitoring."
                ),
            },
            {
                "id": "no-action",
                "description": "Take no follow-up action.",
            },
        ],
    },
    "expected_findings": [
        {
            "id": "first-watch-firewall-disabled",
            "evidence_id": "EV-001",
            "classification": "critical",
            "priority_tier": 1,
            "preferred_action": "restore-firewall",
            "acceptable_actions": ["restore-firewall"],
            "source_finding_ids": [
                "firewall-currently-disabled",
                "firewall-regressed-to-disabled",
            ],
        },
        {
            "id": "first-watch-new-listener",
            "evidence_id": "EV-002",
            "classification": "suspicious",
            "priority_tier": 2,
            "preferred_action": "validate-service-controls",
            "acceptable_actions": ["validate-service-controls"],
            "source_finding_ids": [
                "listener-all-interfaces",
                "listener-newly-detected",
            ],
        },
        {
            "id": "first-watch-integrity-modified",
            "evidence_id": "EV-003",
            "classification": "suspicious",
            "priority_tier": 2,
            "preferred_action": "investigate-restore",
            "acceptable_actions": ["investigate-restore"],
            "source_finding_ids": ["integrity-file-modified"],
        },
        {
            "id": "first-watch-routine-pid-change",
            "evidence_id": "EV-004",
            "classification": "normal",
            "priority_tier": 3,
            "preferred_action": "verify-expected",
            "acceptable_actions": ["verify-expected", "no-action"],
            "source_finding_ids": [],
        },
    ],
    "scoring_rules": {
        "identification_points_each": 7,
        "classification_points_each": 7,
        "priority_points_each": 5,
        "response_points_each": 6,
        "hint_penalty_each": 3,
        "maximum_hint_penalty": 9,
    },
    "coaching": {
        "hints": [
            (
                "Start with controls whose trusted and current states differ. "
                "One host protection control deserves immediate attention."
            ),
            (
                "Compare listener address scopes. A 0.0.0.0 binding may be "
                "reachable from other networks, but firewall, routing, and NAT "
                "still determine actual reachability."
            ),
            (
                "Check the integrity record, then separate stable endpoint identity "
                "from volatile values such as timestamps and process IDs."
            ),
        ],
        "method": "deterministic rule-based coaching",
    },
}

_DEFINITIONS = {_FIRST_WATCH["id"]: _FIRST_WATCH}


def mission_ids() -> tuple[str, ...]:
    """Return available mission identifiers in deterministic order."""
    return tuple(sorted(_DEFINITIONS))


def get_mission_definition(identifier: str) -> dict[str, object]:
    """Return an independent mission definition or raise a clear error."""
    try:
        definition = _DEFINITIONS[identifier]
    except KeyError as error:
        raise ValueError(f"unknown mission: {identifier}") from error
    return deepcopy(definition)
