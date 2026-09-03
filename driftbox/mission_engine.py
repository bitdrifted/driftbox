"""Synthetic mission validation and reuse of Driftbox analysis engines."""

from __future__ import annotations

from dataclasses import dataclass

from driftbox.findings import (
    FindingsResult,
    combine_findings,
    drift_findings,
    integrity_findings,
    posture_findings,
)
from driftbox.integrity import compare_integrity, integrity_snapshot_from_data
from driftbox.mission_definitions import (
    MISSION_DEFINITION_SCHEMA_VERSION,
    get_mission_definition,
    mission_ids,
)
from driftbox.report_diff import compare_snapshots, normalize_report
from driftbox.security_checks import analyze_security_posture

MISSION_LIST_SCHEMA_VERSION = 1
TRAINING_DATA_SOURCE = "synthetic"
SUPPORTED_MISSION_DEFINITION_SCHEMA_VERSIONS = (1, MISSION_DEFINITION_SCHEMA_VERSION)


@dataclass(frozen=True)
class MissionAnalysis:
    """Core findings produced solely from a mission's synthetic evidence."""

    findings: FindingsResult


def _require_mapping(value: object, field: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"mission {field} must be an object")
    return value


def _require_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"mission {field} must be non-empty text")
    return value


def validate_mission_definition(definition: object) -> dict[str, object]:
    """Validate the complete private mission model and its synthetic evidence."""
    mission = _require_mapping(definition, "definition")
    if mission.get("schema_version") not in (
        SUPPORTED_MISSION_DEFINITION_SCHEMA_VERSIONS
    ):
        raise ValueError("unsupported mission definition schema version")
    for field in ("id", "title", "difficulty", "learner_role", "brief"):
        _require_text(mission.get(field), field)
    organization = _require_mapping(mission.get("organization"), "organization")
    _require_text(organization.get("name"), "organization.name")
    if organization.get("fictional") is not True:
        raise ValueError("mission organization must be explicitly fictional")
    environment = _require_mapping(mission.get("environment"), "environment")
    if environment.get("data_source") != TRAINING_DATA_SOURCE:
        raise ValueError("mission environment must use synthetic data")
    objectives = mission.get("objectives")
    if not isinstance(objectives, list) or not objectives:
        raise ValueError("mission objectives must be a non-empty array")
    for objective in objectives:
        _require_text(objective, "objective")

    evidence = _require_mapping(mission.get("evidence"), "evidence")
    for field in (
        "baseline_report",
        "current_report",
        "baseline_integrity",
        "current_integrity",
    ):
        _require_mapping(evidence.get(field), f"evidence.{field}")
    items = evidence.get("items")
    if not isinstance(items, list) or not items:
        raise ValueError("mission evidence items must be a non-empty array")
    item_ids = []
    for item in items:
        item_data = _require_mapping(item, "evidence item")
        item_ids.append(_require_text(item_data.get("id"), "evidence item id"))
        _require_text(item_data.get("title"), "evidence item title")
        _require_text(item_data.get("details"), "evidence item details")
    if len(item_ids) != len(set(item_ids)):
        raise ValueError("mission evidence item IDs must be unique")
    if item_ids != sorted(item_ids):
        raise ValueError("mission evidence items must be in deterministic order")
    action_choices = evidence.get("action_choices")
    if not isinstance(action_choices, list) or not action_choices:
        raise ValueError("mission action choices must be a non-empty array")
    action_ids = []
    for action in action_choices:
        action_data = _require_mapping(action, "action choice")
        action_ids.append(_require_text(action_data.get("id"), "action choice id"))
        _require_text(action_data.get("description"), "action choice description")
    if len(action_ids) != len(set(action_ids)):
        raise ValueError("mission action choice IDs must be unique")

    expected = mission.get("expected_findings")
    if not isinstance(expected, list) or not expected:
        raise ValueError("mission expected_findings must be a non-empty array")
    expected_evidence_ids = []
    expected_ids = []
    priority_tiers = []
    for finding in expected:
        finding_data = _require_mapping(finding, "expected finding")
        expected_ids.append(
            _require_text(finding_data.get("id"), "expected finding id")
        )
        evidence_id = _require_text(
            finding_data.get("evidence_id"), "expected finding evidence_id"
        )
        expected_evidence_ids.append(evidence_id)
        if finding_data.get("classification") not in (
            "normal",
            "suspicious",
            "critical",
        ):
            raise ValueError("expected finding has an invalid classification")
        # Version 1 definitions used one rigid priority and action. Continue to
        # accept that shape so older mission definitions remain loadable.
        priority_tier = finding_data.get(
            "priority_tier", finding_data.get("priority")
        )
        if (
            isinstance(priority_tier, bool)
            or not isinstance(priority_tier, int)
            or priority_tier < 1
        ):
            raise ValueError(
                "expected finding priority tier must be a positive integer"
            )
        priority_tiers.append(priority_tier)
        preferred_action = _require_text(
            finding_data.get("preferred_action", finding_data.get("action")),
            "expected finding preferred action",
        )
        acceptable_actions = finding_data.get(
            "acceptable_actions", [preferred_action]
        )
        if (
            not isinstance(acceptable_actions, list)
            or not acceptable_actions
            or not all(isinstance(action, str) for action in acceptable_actions)
        ):
            raise ValueError("acceptable_actions must be a non-empty array of strings")
        if preferred_action not in acceptable_actions:
            raise ValueError("preferred action must also be acceptable")
        unknown_actions = sorted(set(acceptable_actions) - set(action_ids))
        if unknown_actions:
            raise ValueError("expected finding uses an unknown action")
        source_ids = finding_data.get("source_finding_ids")
        if not isinstance(source_ids, list) or not all(
            isinstance(source_id, str) for source_id in source_ids
        ):
            raise ValueError("source_finding_ids must be an array of strings")
    if sorted(expected_evidence_ids) != sorted(item_ids):
        raise ValueError("every evidence item must have one expected finding")
    if len(expected_ids) != len(set(expected_ids)):
        raise ValueError("expected finding IDs must be unique")
    if priority_tiers != sorted(priority_tiers):
        raise ValueError("expected finding priority tiers must be ordered")
    if sorted(set(priority_tiers)) != list(range(1, max(priority_tiers) + 1)):
        raise ValueError("expected finding priority tiers must be consecutive")

    rules = _require_mapping(mission.get("scoring_rules"), "scoring_rules")
    point_keys = (
        "identification_points_each",
        "classification_points_each",
        "priority_points_each",
        "response_points_each",
        "hint_penalty_each",
        "maximum_hint_penalty",
    )
    for key in point_keys:
        value = rules.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"mission scoring rule {key} must be non-negative")
    maximum_score = len(expected) * sum(
        rules[key]
        for key in (
            "identification_points_each",
            "classification_points_each",
            "priority_points_each",
            "response_points_each",
        )
    )
    if maximum_score != 100:
        raise ValueError("mission scoring rules must produce a 100-point maximum")
    coaching = _require_mapping(mission.get("coaching"), "coaching")
    hints = coaching.get("hints")
    if not isinstance(hints, list) or not hints:
        raise ValueError("mission coaching hints must be a non-empty array")
    for hint in hints:
        _require_text(hint, "coaching hint")
    if coaching.get("method") != "deterministic rule-based coaching":
        raise ValueError(
            "mission coaching method must be deterministic and rule-based"
        )
    return mission


def analyze_mission_evidence(definition: object) -> MissionAnalysis:
    """Run existing analyzers against synthetic mission evidence only."""
    mission = validate_mission_definition(definition)
    evidence = _require_mapping(mission["evidence"], "evidence")
    baseline_report = evidence["baseline_report"]
    current_report = evidence["current_report"]
    current_data = _require_mapping(current_report, "current report")
    exposure = _require_mapping(current_data.get("exposure"), "current exposure")

    drift = compare_snapshots(
        normalize_report(baseline_report),
        normalize_report(current_report),
    )
    posture = analyze_security_posture(
        current_data.get("firewall"), exposure.get("listening_ports")
    )
    integrity = compare_integrity(
        integrity_snapshot_from_data(evidence["baseline_integrity"]),
        integrity_snapshot_from_data(evidence["current_integrity"]),
    )
    findings = combine_findings(
        drift_findings(drift),
        posture_findings(posture),
        integrity_findings(integrity),
    )

    produced_ids = {finding.id for finding in findings.findings}
    expected = mission["expected_findings"]
    if not isinstance(expected, list):
        raise ValueError("mission expected findings must be an array")
    required_ids = {
        source_id
        for finding in expected
        for source_id in finding["source_finding_ids"]
    }
    missing = sorted(required_ids - produced_ids)
    if missing:
        raise ValueError(
            f"mission evidence did not produce expected core finding: {missing[0]}"
        )
    return MissionAnalysis(findings)


def load_mission(identifier: str) -> dict[str, object]:
    """Load and fully validate one mission definition."""
    mission = get_mission_definition(identifier)
    analyze_mission_evidence(mission)
    return mission


def public_mission_metadata(mission: dict[str, object]) -> dict[str, object]:
    """Return learner-visible metadata without private scoring material."""
    return {
        key: mission[key]
        for key in (
            "id",
            "title",
            "organization",
            "environment",
            "difficulty",
            "learner_role",
            "objectives",
        )
    }


def list_missions_data() -> dict[str, object]:
    """Return deterministic learner-visible mission discovery data."""
    missions = [public_mission_metadata(load_mission(item)) for item in mission_ids()]
    return {
        "schema_version": MISSION_LIST_SCHEMA_VERSION,
        "training_environment": True,
        "data_source": TRAINING_DATA_SOURCE,
        "missions": missions,
    }
