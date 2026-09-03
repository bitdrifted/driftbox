"""Tests for Driftbox file-integrity verification."""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from driftbox.cli import create_integrity_manifest, verify_integrity
from driftbox.integrity import create_manifest


class IntegrityTests(unittest.TestCase):
    """Verify manifest creation and filesystem comparisons."""

    @staticmethod
    def create_test_manifest(root: Path, manifest: Path) -> dict[str, object]:
        """Create and return a manifest for a temporary test path."""
        create_manifest(str(root), str(manifest))
        return json.loads(manifest.read_text(encoding="utf-8"))

    @staticmethod
    def run_verify(root: Path, manifest: Path) -> tuple[int, str, str]:
        """Capture verification exit code and terminal streams."""
        output = io.StringIO()
        errors = io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            exit_code = verify_integrity(str(root), str(manifest))
        return exit_code, output.getvalue(), errors.getvalue()

    def test_intact_regular_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "important.txt"
            manifest = Path(directory) / "manifest.json"
            root.write_text("trusted content", encoding="utf-8")
            data = self.create_test_manifest(root, manifest)
            exit_code, output, errors = self.run_verify(root, manifest)

        self.assertEqual(data["schema_version"], 1)
        self.assertEqual(data["algorithm"], "sha256")
        self.assertEqual(data["root_type"], "file")
        self.assertEqual(exit_code, 0)
        self.assertIn("Unchanged files: 1", output)
        self.assertIn("Integrity intact.", output)
        self.assertEqual(errors, "")

    def test_modified_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            target = root / "settings.ini"
            target.write_text("secure=true", encoding="utf-8")
            self.create_test_manifest(root, manifest)
            target.write_text("secure=false", encoding="utf-8")
            exit_code, output, _ = self.run_verify(root, manifest)

        self.assertEqual(exit_code, 1)
        self.assertIn("Modified files:", output)
        self.assertIn("* settings.ini", output)

    def test_added_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            self.create_test_manifest(root, manifest)
            (root / "new.txt").write_text("new", encoding="utf-8")
            exit_code, output, _ = self.run_verify(root, manifest)

        self.assertEqual(exit_code, 1)
        self.assertIn("Added files:", output)
        self.assertIn("+ new.txt", output)

    def test_missing_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            target = root / "removed.txt"
            target.write_text("remove me", encoding="utf-8")
            self.create_test_manifest(root, manifest)
            target.unlink()
            exit_code, output, _ = self.run_verify(root, manifest)

        self.assertEqual(exit_code, 1)
        self.assertIn("Missing files:", output)
        self.assertIn("- removed.txt", output)

    def test_directory_manifest_has_deterministic_normalized_order(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root.parent / f"{root.name}-manifest.json"
            (root / "z.txt").write_text("z", encoding="utf-8")
            nested = root / "folder"
            nested.mkdir()
            (nested / "a.txt").write_text("a", encoding="utf-8")
            try:
                data = self.create_test_manifest(root, manifest)
            finally:
                manifest.unlink(missing_ok=True)

        paths = [record["path"] for record in data["files"]]
        self.assertEqual(paths, ["folder/a.txt", "z.txt"])

    def test_symlinks_are_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            target = root / "target.txt"
            link = root / "link.txt"
            target.write_text("target", encoding="utf-8")
            try:
                os.symlink(target, link)
            except OSError as error:
                # Windows may reserve symlink creation for elevated users. A
                # mocked directory entry still verifies the non-following path.
                link_entry = SimpleNamespace(
                    name="link.txt",
                    path=str(link),
                    is_symlink=lambda: True,
                )
                scan_context = MagicMock()
                scan_context.__enter__.return_value = [link_entry]
                with patch(
                    "driftbox.integrity.os.scandir",
                    return_value=scan_context,
                ):
                    data = self.create_test_manifest(root, manifest)
                self.assertIsInstance(error, OSError)
                expected_paths = []
            else:
                data = self.create_test_manifest(root, manifest)
                expected_paths = ["target.txt"]

        paths = [record["path"] for record in data["files"]]
        self.assertEqual(paths, expected_paths)

    def test_manifest_inside_directory_is_excluded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            (root / "tracked.txt").write_text("tracked", encoding="utf-8")
            data = self.create_test_manifest(root, manifest)
            exit_code, output, _ = self.run_verify(root, manifest)

        paths = [record["path"] for record in data["files"]]
        self.assertNotIn("manifest.json", paths)
        self.assertEqual(exit_code, 0)
        self.assertIn("Unchanged files: 1", output)

    def test_malformed_manifest_returns_exit_code_two(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            manifest.write_text("{invalid", encoding="utf-8")
            exit_code, output, errors = self.run_verify(root, manifest)

        self.assertEqual(exit_code, 2)
        self.assertEqual(output, "")
        self.assertIn("integrity verify failed", errors)

    def test_unsupported_schema_version_returns_exit_code_two(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema_version": 999,
                        "algorithm": "sha256",
                        "root_type": "directory",
                        "files": [],
                    }
                ),
                encoding="utf-8",
            )
            exit_code, output, errors = self.run_verify(root, manifest)

        self.assertEqual(exit_code, 2)
        self.assertEqual(output, "")
        self.assertIn("unsupported manifest schema version", errors)

    def test_missing_path_returns_exit_code_two(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing"
            manifest = Path(directory) / "manifest.json"
            output = io.StringIO()
            errors = io.StringIO()
            with redirect_stdout(output), redirect_stderr(errors):
                exit_code = create_integrity_manifest(str(missing), str(manifest))

        self.assertEqual(exit_code, 2)
        self.assertEqual(output.getvalue(), "")
        self.assertIn("integrity create failed", errors.getvalue())

    def test_read_error_does_not_write_partial_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            (root / "unreadable.txt").write_text("secret", encoding="utf-8")
            output = io.StringIO()
            errors = io.StringIO()
            with (
                patch(
                    "driftbox.integrity._hash_file",
                    side_effect=PermissionError("access denied"),
                ),
                redirect_stdout(output),
                redirect_stderr(errors),
            ):
                exit_code = create_integrity_manifest(str(root), str(manifest))

            self.assertFalse(manifest.exists())

        self.assertEqual(exit_code, 2)
        self.assertEqual(output.getvalue(), "")
        self.assertIn("access denied", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
