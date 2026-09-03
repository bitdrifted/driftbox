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


def _parse_ids(text: str) -> tuple[str, ...]:
    if not text.strip():
        return ()
    return tuple(item.strip().upper() for item in text.split(",") if item.strip())


def collect_submission() -> MissionSubmission:
    """Collect one clear interactive finding and response submission."""
    selected = _parse_ids(
        input("Evidence IDs to submit (comma-separated, blank for none): ")
    )
    classifications = {}
    actions = {}
    for evidence_id in selected:
        classifications[evidence_id] = input(
            f"Classification for {evidence_id} "
            "[normal/suspicious/critical]: "
        ).strip().lower()
        actions[evidence_id] = input(
            f"Recommended action ID for {evidence_id}: "
        ).strip().lower()
    priority = _parse_ids(
        input("Priority order, highest first (comma-separated): ")
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
    active_mission_id()
    _print_banner()
    print("Submit evidence, classifications, actions, and a priority order.")
    print(
        "Action IDs are listed by 'driftbox mission brief'. "
        "Coaching is deterministic and rule-based, not AI-generated."
    )
    submission = collect_submission()
    score, attempt_number, best_score = record_submission(submission)
    print()
    print(f"Attempt: {attempt_number}")
    print(f"Identification: {score.components['identification']}/28")
    print(f"Classification: {score.components['classification']}/28")
    print(f"Prioritization: {score.components['prioritization']}/20")
    print(f"Response decisions: {score.components['response']}/24")
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
