"""Cross-platform file-integrity manifests using SHA-256."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath

MANIFEST_SCHEMA_VERSION = 1
HASH_ALGORITHM = "sha256"
HASH_CHUNK_SIZE = 1024 * 1024


@dataclass(frozen=True, order=True)
class FileRecord:
    """Stable integrity information for one regular file."""

    path: str
    size: int
    sha256: str


@dataclass(frozen=True)
class IntegritySnapshot:
    """Normalized contents of a file or directory tree."""

    root_type: str
    files: tuple[FileRecord, ...]


@dataclass(frozen=True)
class IntegrityChanges:
    """Differences between a manifest and the current filesystem."""

    added: tuple[str, ...]
    missing: tuple[str, ...]
    modified: tuple[str, ...]
    unchanged_count: int

    @property
    def found(self) -> bool:
        """Return True when any file was added, removed, or modified."""
        return bool(self.added or self.missing or self.modified)


def _hash_file(path: Path) -> tuple[int, str]:
    """Return a file's size and SHA-256 digest, failing on any read error."""
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as file_handle:
        while chunk := file_handle.read(HASH_CHUNK_SIZE):
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


def _same_path(first: Path, second: Path | None) -> bool:
    """Compare normalized absolute paths without requiring them to exist."""
    if second is None:
        return False
    return os.path.normcase(str(first.absolute())) == os.path.normcase(
        str(second.absolute())
    )


def _scan_directory(
    root: Path,
    directory: Path,
    excluded_path: Path | None,
) -> list[FileRecord]:
    """Recursively scan regular files without following symbolic links."""
    records: list[FileRecord] = []
    with os.scandir(directory) as entries:
        sorted_entries = sorted(entries, key=lambda entry: entry.name)

    for entry in sorted_entries:
        entry_path = Path(entry.path)
        if entry.is_symlink() or _same_path(entry_path, excluded_path):
            continue
        if entry.is_dir(follow_symlinks=False):
            records.extend(_scan_directory(root, entry_path, excluded_path))
        elif entry.is_file(follow_symlinks=False):
            size, sha256 = _hash_file(entry_path)
            records.append(
                FileRecord(entry_path.relative_to(root).as_posix(), size, sha256)
            )
    return records


def scan_path(path: str, excluded_path: str | None = None) -> IntegritySnapshot:
    """Create a complete normalized snapshot of a regular file or directory."""
    root = Path(path)
    excluded = Path(excluded_path) if excluded_path is not None else None

    if root.is_symlink():
        raise ValueError("symbolic-link scan paths are not supported")
    if root.is_file():
        if _same_path(root, excluded):
            raise ValueError("the manifest output cannot replace the scanned file")
        size, sha256 = _hash_file(root)
        return IntegritySnapshot("file", (FileRecord(root.name, size, sha256),))
    if root.is_dir():
        return IntegritySnapshot(
            "directory",
            tuple(sorted(_scan_directory(root, root, excluded))),
        )
    raise ValueError(f"path is missing or is not a regular file or directory: {path}")


def _manifest_data(snapshot: IntegritySnapshot) -> dict[str, object]:
    """Convert a snapshot to the public manifest structure."""
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "algorithm": HASH_ALGORITHM,
        "root_type": snapshot.root_type,
        "files": [asdict(record) for record in snapshot.files],
    }


def create_manifest(path: str, output_path: str) -> int:
    """Scan a path completely, then atomically write its manifest."""
    snapshot = scan_path(path, excluded_path=output_path)
    output = Path(output_path)
    manifest_json = json.dumps(_manifest_data(snapshot), indent=2, sort_keys=True)
    temporary_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=output.parent,
            prefix=f".{output.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_path = temporary_file.name
            temporary_file.write(manifest_json)
            temporary_file.write("\n")
        os.replace(temporary_path, output)
    except BaseException:
        if temporary_path is not None:
            try:
                Path(temporary_path).unlink()
            except OSError:
                pass
        raise
    return len(snapshot.files)


def _validate_manifest_path(value: object, index: int) -> str:
    """Validate a normalized, relative manifest path."""
    if not isinstance(value, str) or not value:
        raise ValueError(f"manifest file {index} has an invalid path")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or ".." in path.parts
        or str(path) != value
        or "\\" in value
    ):
        raise ValueError(f"manifest file {index} path is not normalized")
    return value


def load_manifest(path: str) -> IntegritySnapshot:
    """Read and validate an integrity manifest."""
    with Path(path).open(encoding="utf-8-sig") as manifest_file:
        manifest = json.load(manifest_file)

    if not isinstance(manifest, dict):
        raise ValueError("manifest must be a JSON object")
    schema_version = manifest.get("schema_version")
    if (
        type(schema_version) is not int
        or schema_version != MANIFEST_SCHEMA_VERSION
    ):
        raise ValueError("unsupported manifest schema version")
    if manifest.get("algorithm") != HASH_ALGORITHM:
        raise ValueError("unsupported manifest hashing algorithm")
    root_type = manifest.get("root_type")
    if root_type not in ("file", "directory"):
        raise ValueError("manifest root_type must be 'file' or 'directory'")
    raw_files = manifest.get("files")
    if not isinstance(raw_files, list):
        raise ValueError("manifest files must be a JSON array")

    records: list[FileRecord] = []
    seen_paths: set[str] = set()
    for index, raw_file in enumerate(raw_files):
        if not isinstance(raw_file, dict):
            raise ValueError(f"manifest file {index} must be a JSON object")
        relative_path = _validate_manifest_path(raw_file.get("path"), index)
        size = raw_file.get("size")
        sha256 = raw_file.get("sha256")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise ValueError(f"manifest file {index} has an invalid size")
        if (
            not isinstance(sha256, str)
            or len(sha256) != 64
            or any(character not in "0123456789abcdef" for character in sha256)
        ):
            raise ValueError(f"manifest file {index} has an invalid SHA-256 hash")
        if relative_path in seen_paths:
            raise ValueError(f"manifest contains duplicate path: {relative_path}")
        seen_paths.add(relative_path)
        records.append(FileRecord(relative_path, size, sha256))

    if records != sorted(records):
        raise ValueError("manifest files are not in deterministic path order")
    return IntegritySnapshot(root_type, tuple(records))


def compare_integrity(
    baseline: IntegritySnapshot,
    current: IntegritySnapshot,
) -> IntegrityChanges:
    """Compare manifest records with a current filesystem snapshot."""
    if baseline.root_type != current.root_type:
        raise ValueError("scanned path type does not match the manifest")
    baseline_files = {record.path: record for record in baseline.files}
    current_files = {record.path: record for record in current.files}
    baseline_paths = set(baseline_files)
    current_paths = set(current_files)
    common_paths = baseline_paths & current_paths
    modified = tuple(
        sorted(
            path
            for path in common_paths
            if baseline_files[path] != current_files[path]
        )
    )
    return IntegrityChanges(
        added=tuple(sorted(current_paths - baseline_paths)),
        missing=tuple(sorted(baseline_paths - current_paths)),
        modified=modified,
        unchanged_count=len(common_paths) - len(modified),
    )


def format_integrity_changes(changes: IntegrityChanges) -> str:
    """Format verification results in deterministic order."""
    lines = [
        "driftbox :: file integrity",
        "-" * 32,
        f"Unchanged files: {changes.unchanged_count}",
    ]
    for heading, marker, paths in (
        ("Added files:", "+", changes.added),
        ("Missing files:", "-", changes.missing),
        ("Modified files:", "*", changes.modified),
    ):
        if paths:
            lines.append("")
            lines.append(heading)
            lines.extend(f"{marker} {path}" for path in paths)
    if not changes.found:
        lines.append("Integrity intact.")
    return "\n".join(lines)
