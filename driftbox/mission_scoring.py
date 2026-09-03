"""Deterministic scoring and coaching for Driftbox training submissions."""

from __future__ import annotations

from dataclasses import asdict, dataclass

CLASSIFICATION_RANK = {"normal": 0, "suspicious": 1, "critical": 2}
SCORE_SCHEMA_VERSION = 2


@dataclass(frozen=True)
class MissionSubmission:
    """Learner decisions collected by terminal or future platform clients."""

    selected_evidence: tuple[str, ...]
    classifications: dict[str, str]
    actions: dict[str, str]
    priority: tuple[str, ...]


@dataclass(frozen=True)
class CoachingItem:
    """One deterministic explanation about a submitted decision."""

    category: str
    evidence_id: str
    message: str


@dataclass(frozen=True)
class MissionScore:
    """Component scores, total, and rule-based coaching for one attempt."""

    components: dict[str, int]
    maximums: dict[str, int]
    hint_penalty: int
    total: int
    coaching: tuple[CoachingItem, ...]

    def as_dict(self) -> dict[str, object]:
        """Return a versioned machine-readable score record."""
        return {
            "schema_version": SCORE_SCHEMA_VERSION,
            "components": dict(self.components),
            "maximums": dict(self.maximums),
            "points_lost": {
                key: self.maximums[key] - value
                for key, value in self.components.items()
            },
            "hint_penalty": self.hint_penalty,
            "total": self.total,
            "coaching": [asdict(item) for item in self.coaching],
        }


def _priority_tier(item: dict[str, object]) -> int:
    """Return a flexible priority tier, including legacy definitions."""
    value = item.get("priority_tier", item.get("priority"))
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("mission priority tier is invalid")
    return value


def _preferred_action(item: dict[str, object]) -> str:
    """Return the preferred action from current or legacy mission schema."""
    value = item.get("preferred_action", item.get("action"))
    if not isinstance(value, str) or not value:
        raise ValueError("mission preferred action is invalid")
    return value


def _acceptable_actions(item: dict[str, object]) -> tuple[str, ...]:
    """Return all full-credit actions, falling back to the legacy action."""
    preferred = _preferred_action(item)
    values = item.get("acceptable_actions", [preferred])
    if not isinstance(values, list) or not all(
        isinstance(value, str) for value in values
    ):
        raise ValueError("mission acceptable actions are invalid")
    return tuple(values)


def _validate_submission(
    mission: dict[str, object], submission: MissionSubmission
) -> tuple[list[dict[str, object]], dict[str, object]]:
    expected = mission.get("expected_findings")
    evidence = mission.get("evidence")
    if not isinstance(expected, list) or not all(
        isinstance(item, dict) for item in expected
    ):
        raise ValueError("mission expected findings are invalid")
    if not isinstance(evidence, dict):
        raise ValueError("mission evidence is invalid")
    evidence_ids = {item["evidence_id"] for item in expected}
    selected = submission.selected_evidence
    if len(selected) != len(set(selected)):
        raise ValueError("submitted evidence IDs must not contain duplicates")
    unknown = sorted(set(selected) - evidence_ids)
    if unknown:
        raise ValueError(f"unknown evidence ID: {unknown[0]}")
    if set(submission.classifications) != set(selected):
        raise ValueError("every selected evidence item needs one classification")
    if set(submission.actions) != set(selected):
        raise ValueError("every selected evidence item needs one action")
    for classification in submission.classifications.values():
        if classification not in CLASSIFICATION_RANK:
            raise ValueError(f"invalid classification: {classification}")
    action_choices = evidence.get("action_choices")
    if not isinstance(action_choices, list):
        raise ValueError("mission action choices are invalid")
    valid_actions = {item["id"] for item in action_choices}
    invalid_actions = sorted(set(submission.actions.values()) - valid_actions)
    if invalid_actions:
        raise ValueError(f"invalid recommended action: {invalid_actions[0]}")
    if len(submission.priority) != len(set(submission.priority)):
        raise ValueError("priority order must not contain duplicates")
    if set(submission.priority) != set(selected):
        raise ValueError("priority order must contain every selected evidence ID")
    rules = mission.get("scoring_rules")
    if not isinstance(rules, dict):
        raise ValueError("mission scoring rules are invalid")
    return expected, rules


def _classification_coaching(
    evidence_id: str,
    expected: str,
    submitted: str,
) -> list[CoachingItem]:
    if submitted == expected:
        if evidence_id == "EV-002":
            message = (
                "Correct: the new all-interface listener is suspicious. It may "
                "be reachable from other networks, but its binding does not prove "
                "internet accessibility; firewall, routing, and NAT also matter."
            )
        elif evidence_id == "EV-001":
            message = "Correct: the confirmed disabled firewall is critical."
        elif evidence_id == "EV-003":
            message = (
                "Correct: the monitored configuration change is suspicious until "
                "its authorization is verified."
            )
        else:
            message = (
                "Correct: a changing process ID is volatile background evidence "
                "and is normal when the endpoint identity is unchanged."
            )
        return [CoachingItem("correct", evidence_id, message)]

    submitted_rank = CLASSIFICATION_RANK[submitted]
    expected_rank = CLASSIFICATION_RANK[expected]
    if expected == "normal" and submitted_rank > 0:
        return [
            CoachingItem(
                "false-positive",
                evidence_id,
                (
                    "This overclassifies harmless background change as a security "
                    "finding; process IDs are volatile and the endpoint is unchanged."
                ),
            ),
            CoachingItem(
                "overclassification",
                evidence_id,
                f"The expected classification is normal, not {submitted}.",
            ),
        ]
    if submitted_rank < expected_rank:
        return [
            CoachingItem(
                "underclassification",
                evidence_id,
                f"This was underclassified as {submitted}; it should be {expected}.",
            )
        ]
    return [
        CoachingItem(
            "overclassification",
            evidence_id,
            f"This was overclassified as {submitted}; it should be {expected}.",
        )
    ]


def score_submission(
    mission: dict[str, object],
    submission: MissionSubmission,
    hint_count: int,
) -> MissionScore:
    """Score identification, classification, priority, and response separately."""
    expected, rules = _validate_submission(mission, submission)
    if (
        isinstance(hint_count, bool)
        or not isinstance(hint_count, int)
        or hint_count < 0
    ):
        raise ValueError("hint count must be a non-negative integer")
    selected = set(submission.selected_evidence)
    ordered_expected = sorted(
        expected,
        key=lambda item: (_priority_tier(item), item["evidence_id"]),
    )
    components = {
        "identification": 0,
        "classification": 0,
        "prioritization": 0,
        "response": 0,
    }
    maximums = {
        "identification": len(expected) * rules["identification_points_each"],
        "classification": len(expected) * rules["classification_points_each"],
        "prioritization": len(expected) * rules["priority_points_each"],
        "response": len(expected) * rules["response_points_each"],
    }
    coaching = []
    for item in ordered_expected:
        evidence_id = item["evidence_id"]
        if evidence_id not in selected:
            coaching.append(
                CoachingItem(
                    "missed-finding",
                    evidence_id,
                    "This evidence was not included in the submission.",
                )
            )
            continue
        components["identification"] += rules["identification_points_each"]
        submitted_classification = submission.classifications[evidence_id]
        if submitted_classification == item["classification"]:
            components["classification"] += rules["classification_points_each"]
        coaching.extend(
            _classification_coaching(
                evidence_id,
                item["classification"],
                submitted_classification,
            )
        )
        submitted_action = submission.actions[evidence_id]
        preferred_action = _preferred_action(item)
        acceptable_actions = _acceptable_actions(item)
        if submitted_action in acceptable_actions:
            components["response"] += rules["response_points_each"]
            if submitted_action == preferred_action:
                coaching.append(
                    CoachingItem(
                        "preferred-action",
                        evidence_id,
                        f"Preferred response selected: {preferred_action}.",
                    )
                )
            else:
                coaching.append(
                    CoachingItem(
                        "acceptable-alternative",
                        evidence_id,
                        (
                            f"{submitted_action} is an acceptable full-credit "
                            f"alternative. {preferred_action} is the more cautious "
                            "operational choice."
                        ),
                    )
                )
        else:
            coaching.append(
                CoachingItem(
                    "response-decision",
                    evidence_id,
                    (
                        f"No response points were awarded: {submitted_action} is "
                        f"not an accepted action. The preferred action is "
                        f"{preferred_action}."
                    ),
                )
            )

    expected_by_id = {item["evidence_id"]: item for item in expected}
    expected_tiers = sorted(
        _priority_tier(expected_by_id[evidence_id])
        for evidence_id in submission.priority
    )
    for index, evidence_id in enumerate(submission.priority):
        submitted_tier = _priority_tier(expected_by_id[evidence_id])
        if submitted_tier == expected_tiers[index]:
            components["prioritization"] += rules["priority_points_each"]
        else:
            coaching.append(
                CoachingItem(
                    "prioritization",
                    evidence_id,
                    (
                        "No prioritization points were awarded for this position: "
                        f"this item belongs in priority tier {submitted_tier}."
                    ),
                )
            )

    hint_penalty = min(
        hint_count * rules["hint_penalty_each"],
        rules["maximum_hint_penalty"],
    )
    total = max(0, sum(components.values()) - hint_penalty)
    coaching.sort(key=lambda item: (item.evidence_id, item.category, item.message))
    return MissionScore(components, maximums, hint_penalty, total, tuple(coaching))
