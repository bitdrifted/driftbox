"""Persistent per-user storage for Driftbox system reports."""

from __future__ import annotations

import json
import os
import platform
import re
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from driftbox.report_diff import normalize_report

HISTORY_SCHEMA_VERSION = 1
SNAPSHOT_PATTERN = re.compile(r"^\d{8}T\d{6}\.\d{6}Z(?:-\d{2})?$")


@dataclass(frozen=True)
class SnapshotInfo:
    """Metadata displayed by history list."""

    identifier: str
    created_at: str
    size: int


def history_directory() -> Path:
    """Return the platform-appropriate per-user history directory."""
    override = os.environ.get("DRIFTBOX_STATE_DIR")
    if override:
        return Path(override).expanduser()

    operating_system = platform.system()
    if operating_system == "Windows":
        local_app_data = os.environ.get("LOCALAPPDATA")
        if not local_app_data:
            raise ValueError("LOCALAPPDATA is not set")
        return Path(local_app_data) / "Driftbox" / "history"
    if operating_system == "Darwin":
        return Path.home() / "Library" / "Application Support" / "Driftbox" / "history"

    state_home = os.environ.get("XDG_STATE_HOME")
    if state_home:
        return Path(state_home).expanduser() / "driftbox" / "history"
    return Path.home() / ".local" / "state" / "driftbox" / "history"


def _snapshot_identifier(now: datetime) -> str:
    """Format a UTC timestamp as a portable snapshot identifier."""
    return now.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")


def _validate_report(report: object) -> dict[str, object]:
    """Validate fields required from a complete stored Driftbox report."""
    if not isinstance(report, dict):
        raise ValueError("snapshot must contain a JSON object")
    schema_version = report.get("schema_version")
    if type(schema_version) is not int or schema_version != 1:
        raise ValueError("snapshot has an unsupported report schema version")
    if not isinstance(report.get("generated_at"), str):
        raise ValueError("snapshot generated_at must be a string")
    if not isinstance(report.get("system"), dict):
        raise ValueError("snapshot system must be an object")
    if not isinstance(report.get("network"), dict):
        raise ValueError("snapshot network must be an object")
    normalize_report(report)
    return report


def _read_snapshot(path: Path) -> tuple[str, dict[str, object]]:
    """Read snapshot text and validate its complete report structure."""
    text = path.read_text(encoding="utf-8")
    return text, _validate_report(json.loads(text))


def capture_snapshot(
    report: dict[str, object],
    now: datetime | None = None,
) -> SnapshotInfo:
    """Atomically save a complete report without overwriting history."""
    validated_report = _validate_report(report)
    directory = history_directory()
    directory.mkdir(parents=True, exist_ok=True)
    base_identifier = _snapshot_identifier(now or datetime.now(timezone.utc))
    snapshot_bytes = (
        json.dumps(validated_report, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")

    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "wb",
            dir=directory,
            prefix=".capture-",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)
            temporary_file.write(snapshot_bytes)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())

        for collision in range(100):
            suffix = "" if collision == 0 else f"-{collision:02d}"
            identifier = f"{base_identifier}{suffix}"
            snapshot_path = directory / f"{identifier}.json"
            try:
                # A hard link publishes complete bytes atomically and fails if
                # another process already claimed this identifier.
                os.link(temporary_path, snapshot_path)
                break
            except FileExistsError:
                continue
        else:
            raise FileExistsError("could not allocate a unique snapshot identifier")
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)

    return SnapshotInfo(identifier, validated_report["generated_at"], len(snapshot_bytes))


def _history_files() -> list[Path]:
    """Return snapshot files and reject unexpected JSON filenames."""
    directory = history_directory()
    directory.mkdir(parents=True, exist_ok=True)
    files = []
    for path in directory.glob("*.json"):
        if not SNAPSHOT_PATTERN.fullmatch(path.stem):
            raise ValueError(f"invalid history filename: {path.name}")
        files.append(path)
    return files


def list_snapshots() -> tuple[SnapshotInfo, ...]:
    """Return validated snapshots newest first without skipping corruption."""
    snapshots = []
    for path in _history_files():
        _, report = _read_snapshot(path)
        snapshots.append(
            SnapshotInfo(path.stem, report["generated_at"], path.stat().st_size)
        )
    return tuple(sorted(snapshots, key=lambda item: item.identifier, reverse=True))


def resolve_snapshot(identifier: str) -> Path:
    """Resolve a snapshot identifier or the special latest alias."""
    if identifier == "latest":
        snapshots = list_snapshots()
        if not snapshots:
            raise FileNotFoundError("history contains no snapshots")
        identifier = snapshots[0].identifier
    elif not SNAPSHOT_PATTERN.fullmatch(identifier):
        raise ValueError("invalid snapshot identifier")

    path = history_directory() / f"{identifier}.json"
    if not path.is_file():
        raise FileNotFoundError(f"snapshot not found: {identifier}")
    return path


def read_snapshot(identifier: str) -> tuple[str, dict[str, object]]:
    """Return stored snapshot text unchanged after validation."""
    return _read_snapshot(resolve_snapshot(identifier))


def snapshot_listing_data(snapshots: tuple[SnapshotInfo, ...]) -> dict[str, object]:
    """Return a versioned machine-readable history listing."""
    return {
        "schema_version": HISTORY_SCHEMA_VERSION,
        "snapshots": [asdict(snapshot) for snapshot in snapshots],
    }
