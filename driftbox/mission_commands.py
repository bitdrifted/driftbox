"""Learner-facing presentation and terminal flow for training missions."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from driftbox.mission_engine import (
    list_missions_data,
    load_mission,
    public_mission_metadata,
)
from driftbox.mission_scoring import MissionScore, MissionSubmission, score_submission
from driftbox.mission_storage import (
    active_mission_id,
    load_active_evidence,
    load_active_session,
    reset_active_session,
    save_session,
    start_session,
)

TRAINING_BANNER = "*** TRAINING ENVIRONMENT - SYNTHETIC EVIDENCE ONLY ***"


def _print_banner() -> None:
    print(TRAINING_BANNER)


def show_mission_list(json_output: bool = False) -> None:
    """List deterministic learner-visible mission metadata."""
    data = list_missions_data()
    if json_output:
        print(json.dumps(data, indent=2, sort_keys=True))
        return
    _print_banner()
    print("driftbox :: training missions")
    print("-" * 32)
    missions = data["missions"]
    if not isinstance(missions, list):
        raise ValueError("mission listing is invalid")
    for mission in missions:
        organization = mission["organization"]
        print(
            f"{mission['id']}: {mission['title']} "
            f"({mission['difficulty']}, {organization['name']})"
        )


def start_mission(identifier: str) -> None:
    """Create or resume an isolated synthetic mission session."""
    mission = load_mission(identifier)
    session, resumed = start_session(mission)
    _print_banner()
    verb = "Resumed" if resumed else "Started"
    print(f"{verb} mission: {mission['title']} ({mission['id']})")
    print(f"Session: {session['session_id']}")
    print("Use 'driftbox mission brief' to review the evidence packet.")


def show_mission_brief() -> None:
    """Display the active mission brief and raw synthetic evidence."""
    session = load_active_session()
    evidence_document = load_active_evidence()
    mission = load_mission(session["mission_id"])
    metadata = public_mission_metadata(mission)
    evidence = evidence_document["evidence"]
    if not isinstance(evidence, dict):
        raise ValueError("mission evidence is invalid")
    _print_banner()
    print(f"driftbox :: {metadata['title']}")
    print("-" * 32)
    print(f"Organization: {metadata['organization']['name']} (fictional)")
    print(f"Environment: {metadata['environment']['name']}")
    print(f"Learner role: {metadata['learner_role']}")
    print(f"Difficulty: {metadata['difficulty']}")
    print()
    print(evidence_document["brief"])
    print()
    print("Objectives:")
    for objective in evidence_document["objectives"]:
        print(f"- {objective}")
    print()
    print("Synthetic evidence packet:")
    for item in evidence["items"]:
        print(f"- [{item['id']}] {item['title']}: {item['details']}")
    print()
    print("Available recommended actions:")
    for action in evidence["action_choices"]:
        print(f"- {action['id']}: {action['description']}")


def show_mission_status() -> None:
    """Show resumable progress without revealing private scoring rules."""
    session = load_active_session()
    mission = load_mission(session["mission_id"])
    _print_banner()
    print(f"Mission: {mission['title']} ({mission['id']})")
    print(f"Session: {session['session_id']}")
    print(f"Hints used: {session['hint_count']}")
    print(f"Attempts: {len(session['attempts'])}")
    best = session["best_score"]
    print(f"Best score: {best if best is not None else 'not submitted'}")


def show_next_hint() -> None:
    """Display one progressive hint and persist unique hint usage."""
    session = load_active_session()
    mission = load_mission(session["mission_id"])
    coaching = mission["coaching"]
    hints = coaching["hints"]
    hint_count = session["hint_count"]
    _print_banner()
    if hint_count >= len(hints):
        print("No additional hints are available.")
        print(f"Hints used: {hint_count}")
        return
    print(f"Hint {hint_count + 1} of {len(hints)}: {hints[hint_count]}")
    session["hint_count"] = hint_count + 1
    save_session(session)
    print(f"Hints used: {session['hint_count']}")


CLASSIFICATION_CHOICES = (
    ("normal", "Expected or harmless activity that does not require escalation."),
    ("suspicious", "Activity that warrants investigation or validation."),
    ("critical", "A confirmed serious security condition requiring priority action."),
)


def _show_numbered_menu(
    heading: str,
    choices: list[tuple[str, str]],
    output_func,
) -> None:
    """Display portable numbered choices with their stable textual IDs."""
    output_func(heading)
    for number, (identifier, description) in enumerate(choices, start=1):
        output_func(f"  {number}. {identifier} - {description}")


def _resolve_menu_entry(text: str, choices: list[str]) -> str | None:
    token = text.strip()
    if token.isdigit():
        number = int(token)
        if 1 <= number <= len(choices):
            return choices[number - 1]
        return None
    aliases = {choice.casefold(): choice for choice in choices}
    return aliases.get(token.casefold())


def _prompt_choice(prompt: str, choices: list[str], input_func, output_func) -> str:
    """Read one numbered or textual choice, re-prompting invalid input."""
    while True:
        resolved = _resolve_menu_entry(input_func(prompt), choices)
        if resolved is not None:
            return resolved
        output_func(
            f"Invalid choice. Enter a number from 1 to {len(choices)} "
            "or one of the displayed IDs."
        )


def _prompt_order(
    prompt: str,
    choices: list[str],
    input_func,
    output_func,
    *,
    allow_empty: bool = False,
) -> tuple[str, ...]:
    """Read a complete comma-separated menu order without terminal assumptions."""
    while True:
        text = input_func(prompt)
        if allow_empty and not text.strip():
            return ()
        tokens = [token.strip() for token in text.split(",") if token.strip()]
        resolved = [_resolve_menu_entry(token, choices) for token in tokens]
        if (
            len(tokens) == len(choices)
            and all(item is not None for item in resolved)
            and len(set(resolved)) == len(choices)
        ):
            return tuple(item for item in resolved if item is not None)
        output_func(
            "Invalid entry. Include each displayed item exactly once, separated "
            "by commas; use menu numbers or IDs."
        )


def _prompt_selection(
    prompt: str, choices: list[str], input_func, output_func
) -> tuple[str, ...]:
    """Read any unique subset of a menu, including an intentionally empty set."""
    while True:
        text = input_func(prompt)
        if not text.strip():
            return ()
        tokens = [token.strip() for token in text.split(",") if token.strip()]
        resolved = [_resolve_menu_entry(token, choices) for token in tokens]
        if (
            tokens
            and all(item is not None for item in resolved)
            and len(set(resolved)) == len(resolved)
        ):
            return tuple(item for item in resolved if item is not None)
        output_func(
            "Invalid entry. Use each desired menu number or evidence ID at most "
            "once, separated by commas."
        )


def collect_submission(
    mission: dict[str, object] | None = None,
    input_func=None,
    output_func=None,
) -> MissionSubmission:
    """Collect an interactive submission while preserving the data interface."""
    if input_func is None:
        input_func = input
    if output_func is None:
        output_func = print
    if mission is None:
        mission = load_mission(active_mission_id())
    evidence = mission["evidence"]
    if not isinstance(evidence, dict):
        raise ValueError("mission evidence is invalid")
    evidence_items = evidence["items"]
    action_items = evidence["action_choices"]
    if not isinstance(evidence_items, list) or not isinstance(action_items, list):
        raise ValueError("mission choices are invalid")
    evidence_choices = [
        (item["id"], f"{item['title']}: {item['details']}")
        for item in evidence_items
    ]
    _show_numbered_menu(
        "Evidence available for submission:", evidence_choices, output_func
    )
    selected = _prompt_selection(
        "Evidence to submit (comma-separated numbers or IDs; blank for none): ",
        [identifier for identifier, _ in evidence_choices],
        input_func,
        output_func,
    )
    classifications = {}
    actions = {}
    classification_choices = list(CLASSIFICATION_CHOICES)
    action_choices = [
        (item["id"], item["description"])
        for item in action_items
    ]
    for evidence_id in selected:
        _show_numbered_menu(
            f"Classification choices for {evidence_id}:",
            classification_choices,
            output_func,
        )
        classifications[evidence_id] = _prompt_choice(
            f"Classification for {evidence_id}: ",
            [identifier for identifier, _ in classification_choices],
            input_func,
            output_func,
        )
        _show_numbered_menu(
            f"Recommended actions for {evidence_id}:", action_choices, output_func
        )
        actions[evidence_id] = _prompt_choice(
            f"Recommended action for {evidence_id}: ",
            [identifier for identifier, _ in action_choices],
            input_func,
            output_func,
        )
    selected_details = [
        choice for choice in evidence_choices if choice[0] in set(selected)
    ]
    _show_numbered_menu(
        "Priority choices (highest priority first):",
        selected_details,
        output_func,
    )
    priority = _prompt_order(
        "Priority order (comma-separated numbers or evidence IDs): ",
        [identifier for identifier, _ in selected_details],
        input_func,
        output_func,
        allow_empty=not selected,
    )
    return MissionSubmission(selected, classifications, actions, priority)


def record_submission(
    submission: MissionSubmission,
    now: datetime | None = None,
) -> tuple[MissionScore, int, int]:
    """Score and persist an attempt, returning score, attempt number, and best."""
    session = load_active_session()
    mission = load_mission(session["mission_id"])
    score = score_submission(mission, submission, session["hint_count"])
    timestamp = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    attempt = {
        "attempt": len(session["attempts"]) + 1,
        "submitted_at": timestamp.isoformat(),
        "submission": {
            "selected_evidence": list(submission.selected_evidence),
            "classifications": dict(submission.classifications),
            "actions": dict(submission.actions),
            "priority": list(submission.priority),
        },
        "score": score.as_dict(),
    }
    session["attempts"].append(attempt)
    prior_best = session["best_score"]
    session["best_score"] = max(
        score.total,
        prior_best if isinstance(prior_best, int) else 0,
    )
    save_session(session)
    return score, attempt["attempt"], session["best_score"]


def submit_mission() -> None:
    """Run the interactive submission, scoring, and coaching loop."""
    mission = load_mission(active_mission_id())
    _print_banner()
    print("Submit evidence, classifications, actions, and a priority order.")
    print("Choices are shown as they are needed; enter a menu number or its ID.")
    print("Coaching is deterministic and rule-based, not AI-generated.")
    submission = collect_submission(mission)
    score, attempt_number, best_score = record_submission(submission)
    print()
    print(f"Attempt: {attempt_number}")
    labels = (
        ("identification", "Identification"),
        ("classification", "Classification"),
        ("prioritization", "Prioritization"),
        ("response", "Response decisions"),
    )
    for key, label in labels:
        earned = score.components[key]
        maximum = score.maximums[key]
        print(f"{label}: {earned}/{maximum} ({maximum - earned} points lost)")
    print(f"Hint penalty: -{score.hint_penalty}")
    print(f"Total score: {score.total}/100")
    print(f"Best score: {best_score}/100")
    print()
    print("Rule-based coaching:")
    for item in score.coaching:
        print(f"- [{item.category}] {item.evidence_id}: {item.message}")


def reset_mission() -> None:
    """Reset only the active synthetic mission workspace."""
    mission_id = reset_active_session()
    _print_banner()
    print(f"Reset mission session: {mission_id}")
    print("Live Driftbox configuration, history, and system state were not changed.")
