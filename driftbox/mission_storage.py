"""Isolated, persistent session storage for synthetic training missions."""

from __future__ import annotations

import json
import os
import platform
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path

MISSION_SESSION_SCHEMA_VERSION = 1
MISSION_EVIDENCE_SCHEMA_VERSION = 1
MISSION_ID_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def mission_directory() -> Path:
    """Return the platform-appropriate mission-only state directory."""
    override = os.environ.get("DRIFTBOX_MISSION_DIR")
    if override:
        return Path(override).expanduser()
    operating_system = platform.system()
    if operating_system == "Windows":
        local_app_data = os.environ.get("LOCALAPPDATA")
        if not local_app_data:
            raise ValueError("LOCALAPPDATA is not set")
        return Path(local_app_data) / "Driftbox" / "missions"
    if operating_system == "Darwin":
        return (
            Path.home()
            / "Library"
            / "Application Support"
            / "Driftbox"
            / "missions"
        )
    state_home = os.environ.get("XDG_STATE_HOME")
    if state_home:
        return Path(state_home).expanduser() / "driftbox" / "missions"
    return Path.home() / ".local" / "state" / "driftbox" / "missions"


def _workspace(identifier: str) -> Path:
    if not MISSION_ID_PATTERN.fullmatch(identifier):
        raise ValueError("invalid mission identifier")
    workspace = mission_directory() / identifier
    if workspace.is_symlink():
        raise ValueError("mission workspace must not be a symbolic link")
    return workspace


def _atomic_write(path: Path, data: object) -> None:
    """Write one JSON state document atomically in its destination directory."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)
            json.dump(data, temporary_file, indent=2, sort_keys=True)
            temporary_file.write("\n")
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _read_json(path: Path, label: str) -> object:
    try:
        with path.open(encoding="utf-8") as input_file:
            return json.load(input_file)
    except FileNotFoundError as error:
        raise FileNotFoundError(f"{label} does not exist") from error


def _validate_session(session: object) -> dict[str, object]:
    if not isinstance(session, dict):
        raise ValueError("mission session must be a JSON object")
    if session.get("schema_version") != MISSION_SESSION_SCHEMA_VERSION:
        raise ValueError("unsupported mission session schema version")
    mission_id = session.get("mission_id")
    if not isinstance(mission_id, str) or not MISSION_ID_PATTERN.fullmatch(
        mission_id
    ):
        raise ValueError("mission session has an invalid mission identifier")
    for field in ("session_id", "started_at"):
        if not isinstance(session.get(field), str) or not session[field]:
            raise ValueError(f"mission session has an invalid {field}")
    hint_count = session.get("hint_count")
    if isinstance(hint_count, bool) or not isinstance(hint_count, int):
        raise ValueError("mission session has an invalid hint count")
    if hint_count < 0:
        raise ValueError("mission session has an invalid hint count")
    attempts = session.get("attempts")
    if not isinstance(attempts, list):
        raise ValueError("mission session attempts must be an array")
    attempt_scores = []
    for index, attempt in enumerate(attempts, start=1):
        if not isinstance(attempt, dict) or attempt.get("attempt") != index:
            raise ValueError("mission session has an invalid attempt record")
        if not isinstance(attempt.get("submitted_at"), str):
            raise ValueError("mission attempt has an invalid submission time")
        if not isinstance(attempt.get("submission"), dict):
            raise ValueError("mission attempt has an invalid submission")
        score = attempt.get("score")
        if not isinstance(score, dict):
            raise ValueError("mission attempt has an invalid score")
        total = score.get("total")
        if isinstance(total, bool) or not isinstance(total, int):
            raise ValueError("mission attempt has an invalid total score")
        if not 0 <= total <= 100:
            raise ValueError("mission attempt score is outside 0-100")
        attempt_scores.append(total)
    best_score = session.get("best_score")
    if best_score is not None and (
        isinstance(best_score, bool)
        or not isinstance(best_score, int)
        or not 0 <= best_score <= 100
    ):
        raise ValueError("mission session has an invalid best score")
    if attempt_scores and best_score != max(attempt_scores):
        raise ValueError("mission session best score does not match its attempts")
    if not attempt_scores and best_score is not None:
        raise ValueError("mission session has a best score without attempts")
    return session


def _validate_evidence(evidence: object, mission_id: str) -> dict[str, object]:
    if not isinstance(evidence, dict):
        raise ValueError("mission evidence must be a JSON object")
    if evidence.get("schema_version") != MISSION_EVIDENCE_SCHEMA_VERSION:
        raise ValueError("unsupported mission evidence schema version")
    if evidence.get("training_environment") is not True:
        raise ValueError("mission evidence lacks its training indicator")
    if evidence.get("data_source") != "synthetic":
        raise ValueError("mission evidence must be synthetic")
    if evidence.get("mission_id") != mission_id:
        raise ValueError("mission evidence does not match the active mission")
    if not isinstance(evidence.get("evidence"), dict):
        raise ValueError("mission evidence payload must be an object")
    return evidence


def start_session(
    mission: dict[str, object],
    now: datetime | None = None,
) -> tuple[dict[str, object], bool]:
    """Create or resume one isolated mission session."""
    mission_id = mission.get("id")
    if not isinstance(mission_id, str):
        raise ValueError("mission has an invalid identifier")
    workspace = _workspace(mission_id)
    session_path = workspace / "session.json"
    evidence_path = workspace / "evidence.json"
    resumed = session_path.exists()
    if resumed:
        session = _validate_session(_read_json(session_path, "mission session"))
        _validate_evidence(
            _read_json(evidence_path, "mission evidence"), mission_id
        )
    else:
        timestamp = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        session = {
            "schema_version": MISSION_SESSION_SCHEMA_VERSION,
            "mission_id": mission_id,
            "session_id": timestamp.strftime("%Y%m%dT%H%M%S.%fZ"),
            "started_at": timestamp.isoformat(),
            "hint_count": 0,
            "attempts": [],
            "best_score": None,
        }
        evidence = {
            "schema_version": MISSION_EVIDENCE_SCHEMA_VERSION,
            "training_environment": True,
            "data_source": "synthetic",
            "mission_id": mission_id,
            "brief": mission["brief"],
            "objectives": mission["objectives"],
            "evidence": mission["evidence"],
        }
        _atomic_write(evidence_path, evidence)
        _atomic_write(session_path, session)

    active = {
        "schema_version": MISSION_SESSION_SCHEMA_VERSION,
        "mission_id": mission_id,
    }
    _atomic_write(mission_directory() / "active.json", active)
    return session, resumed


def active_mission_id() -> str:
    """Return the active mission identifier."""
    active = _read_json(mission_directory() / "active.json", "active mission")
    if not isinstance(active, dict):
        raise ValueError("active mission state must be a JSON object")
    if active.get("schema_version") != MISSION_SESSION_SCHEMA_VERSION:
        raise ValueError("unsupported active mission schema version")
    mission_id = active.get("mission_id")
    if not isinstance(mission_id, str) or not MISSION_ID_PATTERN.fullmatch(
        mission_id
    ):
        raise ValueError("active mission has an invalid identifier")
    return mission_id


def load_active_session() -> dict[str, object]:
    """Load and validate the active persisted session."""
    mission_id = active_mission_id()
    session = _validate_session(
        _read_json(_workspace(mission_id) / "session.json", "mission session")
    )
    _validate_evidence(
        _read_json(_workspace(mission_id) / "evidence.json", "mission evidence"),
        mission_id,
    )
    return session


def load_active_evidence() -> dict[str, object]:
    """Load the learner-visible synthetic evidence packet."""
    mission_id = active_mission_id()
    return _validate_evidence(
        _read_json(_workspace(mission_id) / "evidence.json", "mission evidence"),
        mission_id,
    )


def save_session(session: dict[str, object]) -> None:
    """Validate and atomically persist a mission session update."""
    validated = _validate_session(session)
    mission_id = validated["mission_id"]
    if not isinstance(mission_id, str):
        raise ValueError("mission session has an invalid identifier")
    if active_mission_id() != mission_id:
        raise ValueError("mission session is not active")
    _atomic_write(_workspace(mission_id) / "session.json", validated)


def reset_active_session() -> str:
    """Remove only the active mission's known workspace files."""
    mission_id = active_mission_id()
    workspace = _workspace(mission_id)
    allowed_names = {"evidence.json", "session.json"}
    unexpected = sorted(
        path.name for path in workspace.iterdir() if path.name not in allowed_names
    )
    if unexpected:
        raise ValueError(
            f"refusing to reset mission workspace with unknown file: {unexpected[0]}"
        )
    for name in sorted(allowed_names):
        path = workspace / name
        if path.exists():
            path.unlink()
    workspace.rmdir()
    (mission_directory() / "active.json").unlink()
    return mission_id
