"""Tests for the isolated synthetic Driftbox training mission engine."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from driftbox.cli import main
from driftbox.mission_commands import (
    TRAINING_BANNER,
    record_submission,
    show_mission_brief,
    show_mission_list,
    show_mission_status,
    show_next_hint,
    start_mission,
)
from driftbox.mission_definitions import get_mission_definition
from driftbox.mission_engine import (
    analyze_mission_evidence,
    list_missions_data,
    load_mission,
    validate_mission_definition,
)
from driftbox.mission_scoring import MissionSubmission, score_submission
from driftbox.mission_storage import (
    active_mission_id,
    load_active_evidence,
    load_active_session,
    mission_directory,
    reset_active_session,
    save_session,
    start_session,
)


def perfect_submission() -> MissionSubmission:
    """Return the complete correct First Watch decision set."""
    evidence_ids = ("EV-001", "EV-002", "EV-003", "EV-004")
    return MissionSubmission(
        evidence_ids,
        {
            "EV-001": "critical",
            "EV-002": "suspicious",
            "EV-003": "suspicious",
            "EV-004": "normal",
        },
        {
            "EV-001": "restore-firewall",
            "EV-002": "validate-service-controls",
            "EV-003": "investigate-restore",
            "EV-004": "verify-expected",
        },
        evidence_ids,
    )


class MissionDefinitionTests(unittest.TestCase):
    """Verify deterministic definitions and synthetic core analysis."""

    def test_discovery_is_versioned_deterministic_and_private(self) -> None:
        first = list_missions_data()
        second = list_missions_data()
        encoded = json.dumps(first, sort_keys=True)
        self.assertEqual(first, second)
        self.assertEqual(first["schema_version"], 1)
        self.assertTrue(first["training_environment"])
        self.assertEqual(first["data_source"], "synthetic")
        self.assertEqual([item["id"] for item in first["missions"]], ["first-watch"])
        self.assertNotIn("expected_findings", encoded)
        self.assertNotIn("scoring_rules", encoded)
        self.assertNotIn("source_finding_ids", encoded)

    def test_first_watch_reuses_all_existing_analysis_engines(self) -> None:
        analysis = analyze_mission_evidence(get_mission_definition("first-watch"))
        finding_ids = [finding.id for finding in analysis.findings.findings]
        self.assertIn("firewall-currently-disabled", finding_ids)
        self.assertIn("firewall-regressed-to-disabled", finding_ids)
        self.assertIn("listener-all-interfaces", finding_ids)
        self.assertIn("listener-newly-detected", finding_ids)
        self.assertIn("integrity-file-modified", finding_ids)
        self.assertNotIn("listener-removed", finding_ids)
        self.assertFalse(
            any(
                finding.evidence.get("process") == "print-helper"
                for finding in analysis.findings.findings
            )
        )
        self.assertEqual(finding_ids, sorted(finding_ids))

    def test_definition_has_future_platform_fields(self) -> None:
        mission = load_mission("first-watch")
        for field in (
            "organization",
            "environment",
            "difficulty",
            "learner_role",
            "objectives",
            "evidence",
            "expected_findings",
            "scoring_rules",
            "coaching",
        ):
            self.assertIn(field, mission)
        self.assertEqual(mission["organization"]["name"], "St. Meridian Medical Center")
        self.assertTrue(mission["organization"]["fictional"])

    def test_malformed_and_unsupported_definitions_are_rejected(self) -> None:
        unsupported = get_mission_definition("first-watch")
        unsupported["schema_version"] = 99
        with self.assertRaisesRegex(ValueError, "unsupported"):
            validate_mission_definition(unsupported)

        malformed = get_mission_definition("first-watch")
        malformed["expected_findings"][0]["classification"] = "high"
        with self.assertRaisesRegex(ValueError, "classification"):
            validate_mission_definition(malformed)

        live = get_mission_definition("first-watch")
        live["environment"]["data_source"] = "live"
        with self.assertRaisesRegex(ValueError, "synthetic"):
            validate_mission_definition(live)

    def test_unknown_mission_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown mission"):
            load_mission("not-a-mission")


class MissionStorageTests(unittest.TestCase):
    """Verify isolated session creation, persistence, paths, and reset."""

    def test_environment_override_and_platform_defaults(self) -> None:
        with patch.dict("os.environ", {"DRIFTBOX_MISSION_DIR": "C:/Lab/Missions"}):
            self.assertEqual(mission_directory(), Path("C:/Lab/Missions"))
        with patch.dict(
            "os.environ", {"LOCALAPPDATA": "C:/Users/Test/AppData/Local"}, clear=True
        ):
            with patch(
                "driftbox.mission_storage.platform.system", return_value="Windows"
            ):
                self.assertEqual(
                    mission_directory(),
                    Path("C:/Users/Test/AppData/Local/Driftbox/missions"),
                )
        with patch.dict("os.environ", {"XDG_STATE_HOME": "/state"}, clear=True):
            with patch(
                "driftbox.mission_storage.platform.system", return_value="Linux"
            ):
                self.assertEqual(mission_directory(), Path("/state/driftbox/missions"))
        with patch.dict("os.environ", {}, clear=True):
            with (
                patch(
                    "driftbox.mission_storage.platform.system",
                    return_value="Darwin",
                ),
                patch(
                    "driftbox.mission_storage.Path.home",
                    return_value=Path("/Users/test"),
                ),
            ):
                self.assertEqual(
                    mission_directory(),
                    Path("/Users/test/Library/Application Support/Driftbox/missions"),
                )

    def test_start_creates_isolated_workspace_and_resume_persists(self) -> None:
        fixed = datetime(2030, 4, 12, 8, 30, tzinfo=timezone.utc)
        mission = load_mission("first-watch")
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict("os.environ", {"DRIFTBOX_MISSION_DIR": directory}):
                created, resumed = start_session(mission, now=fixed)
                created["hint_count"] = 1
                save_session(created)
                loaded, was_resumed = start_session(mission)
                files = sorted(
                    path.relative_to(directory).as_posix()
                    for path in Path(directory).rglob("*.json")
                )

        self.assertFalse(resumed)
        self.assertTrue(was_resumed)
        self.assertEqual(loaded["hint_count"], 1)
        self.assertEqual(loaded["session_id"], "20300412T083000.000000Z")
        self.assertEqual(
            files,
            ["active.json", "first-watch/evidence.json", "first-watch/session.json"],
        )

    def test_workspace_evidence_is_synthetic_and_has_no_answer_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict("os.environ", {"DRIFTBOX_MISSION_DIR": directory}):
                start_session(load_mission("first-watch"))
                evidence = load_active_evidence()
                encoded = json.dumps(evidence, sort_keys=True)

        self.assertTrue(evidence["training_environment"])
        self.assertEqual(evidence["data_source"], "synthetic")
        self.assertNotIn("expected_findings", encoded)
        self.assertNotIn("scoring_rules", encoded)
        self.assertNotIn("source_finding_ids", encoded)

    def test_reset_removes_only_mission_data(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            mission_root = Path(parent) / "missions"
            non_mission = Path(parent) / "keep.txt"
            non_mission.write_text("preserve", encoding="utf-8")
            with patch.dict(
                "os.environ", {"DRIFTBOX_MISSION_DIR": str(mission_root)}
            ):
                start_session(load_mission("first-watch"))
                reset_identifier = reset_active_session()
                preserved_content = non_mission.read_text(encoding="utf-8")
                workspace_exists = (mission_root / "first-watch").exists()

        self.assertEqual(reset_identifier, "first-watch")
        self.assertEqual(preserved_content, "preserve")
        self.assertFalse(workspace_exists)

    def test_reset_refuses_unknown_workspace_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict("os.environ", {"DRIFTBOX_MISSION_DIR": directory}):
                start_session(load_mission("first-watch"))
                unexpected = Path(directory) / "first-watch" / "keep.txt"
                unexpected.write_text("unknown", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "refusing"):
                    reset_active_session()
                session_still_exists = (
                    Path(directory) / "first-watch" / "session.json"
                ).is_file()

        self.assertTrue(session_still_exists)

    def test_corrupt_session_is_not_silently_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict("os.environ", {"DRIFTBOX_MISSION_DIR": directory}):
                start_session(load_mission("first-watch"))
                session_path = Path(directory) / "first-watch" / "session.json"
                session_path.write_text("{invalid", encoding="utf-8")
                with self.assertRaises(json.JSONDecodeError):
                    load_active_session()
                stored = session_path.read_text(encoding="utf-8")

        self.assertEqual(stored, "{invalid")


class MissionScoringTests(unittest.TestCase):
    """Verify component scoring and specific deterministic coaching."""

    def setUp(self) -> None:
        self.mission = load_mission("first-watch")

    def test_perfect_submission_scores_one_hundred(self) -> None:
        score = score_submission(self.mission, perfect_submission(), hint_count=0)
        self.assertEqual(
            score.components,
            {
                "identification": 28,
                "classification": 28,
                "prioritization": 20,
                "response": 24,
            },
        )
        self.assertEqual(score.total, 100)
        self.assertEqual(score.hint_penalty, 0)
        messages = " ".join(item.message for item in score.coaching)
        self.assertIn("does not prove internet accessibility", messages)
        self.assertIn("disabled firewall is critical", messages)

    def test_hints_apply_a_modest_capped_penalty(self) -> None:
        one_hint = score_submission(self.mission, perfect_submission(), hint_count=1)
        many_hints = score_submission(self.mission, perfect_submission(), hint_count=20)
        self.assertEqual(one_hint.total, 97)
        self.assertEqual(many_hints.total, 91)

    def test_missed_findings_and_response_decisions_are_coached(self) -> None:
        submission = MissionSubmission(
            ("EV-001",),
            {"EV-001": "critical"},
            {"EV-001": "no-action"},
            ("EV-001",),
        )
        score = score_submission(self.mission, submission, hint_count=0)
        categories = [item.category for item in score.coaching]
        self.assertIn("missed-finding", categories)
        self.assertIn("response-decision", categories)
        self.assertLess(score.total, 100)

    def test_false_positive_underclassification_and_overclassification(self) -> None:
        submission = perfect_submission()
        altered = MissionSubmission(
            submission.selected_evidence,
            {
                "EV-001": "suspicious",
                "EV-002": "critical",
                "EV-003": "suspicious",
                "EV-004": "critical",
            },
            submission.actions,
            submission.priority,
        )
        score = score_submission(self.mission, altered, hint_count=0)
        categories = {item.category for item in score.coaching}
        self.assertIn("false-positive", categories)
        self.assertIn("underclassification", categories)
        self.assertIn("overclassification", categories)

    def test_invalid_submission_returns_a_validation_error(self) -> None:
        submission = MissionSubmission(
            ("EV-999",),
            {"EV-999": "critical"},
            {"EV-999": "no-action"},
            ("EV-999",),
        )
        with self.assertRaisesRegex(ValueError, "unknown evidence"):
            score_submission(self.mission, submission, hint_count=0)

    def test_coaching_order_is_deterministic(self) -> None:
        empty = MissionSubmission((), {}, {}, ())
        first = score_submission(self.mission, empty, hint_count=0).as_dict()
        second = score_submission(self.mission, empty, hint_count=0).as_dict()
        self.assertEqual(first, second)
        coaching = first["coaching"]
        keys = [(item["evidence_id"], item["category"]) for item in coaching]
        self.assertEqual(keys, sorted(keys))


class MissionCommandTests(unittest.TestCase):
    """Verify learner-visible commands, persistence, isolation, and exits."""

    def test_list_json_and_human_outputs_have_training_indicators(self) -> None:
        json_output = io.StringIO()
        human_output = io.StringIO()
        with redirect_stdout(json_output):
            show_mission_list(json_output=True)
        with redirect_stdout(human_output):
            show_mission_list()
        data = json.loads(json_output.getvalue())
        self.assertTrue(data["training_environment"])
        self.assertIn(TRAINING_BANNER, human_output.getvalue())

    def test_brief_status_and_hints_persist_without_answer_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = io.StringIO()
            with (
                patch.dict("os.environ", {"DRIFTBOX_MISSION_DIR": directory}),
                redirect_stdout(output),
            ):
                start_mission("first-watch")
                show_mission_brief()
                show_next_hint()
                show_mission_status()
                persisted = load_active_session()
                visible = output.getvalue()

        self.assertEqual(persisted["hint_count"], 1)
        self.assertGreaterEqual(visible.count(TRAINING_BANNER), 4)
        self.assertIn("St. Meridian Medical Center", visible)
        self.assertNotIn("expected_findings", visible)
        self.assertNotIn("scoring_rules", visible)
        self.assertNotIn("source_finding_ids", visible)

    def test_progressive_hints_stop_after_last_hint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = io.StringIO()
            with (
                patch.dict("os.environ", {"DRIFTBOX_MISSION_DIR": directory}),
                redirect_stdout(output),
            ):
                start_mission("first-watch")
                for _ in range(4):
                    show_next_hint()
                session = load_active_session()

        self.assertEqual(session["hint_count"], 3)
        self.assertIn("No additional hints", output.getvalue())

    def test_attempts_and_best_score_persist(self) -> None:
        empty = MissionSubmission((), {}, {}, ())
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch.dict("os.environ", {"DRIFTBOX_MISSION_DIR": directory}),
                redirect_stdout(io.StringIO()),
            ):
                start_mission("first-watch")
                low, first_attempt, first_best = record_submission(empty)
                high, second_attempt, second_best = record_submission(
                    perfect_submission()
                )
                session = load_active_session()

        self.assertEqual(low.total, 0)
        self.assertEqual(first_attempt, 1)
        self.assertEqual(first_best, 0)
        self.assertEqual(high.total, 100)
        self.assertEqual(second_attempt, 2)
        self.assertEqual(second_best, 100)
        self.assertEqual(session["best_score"], 100)
        self.assertEqual(len(session["attempts"]), 2)

    def test_interactive_submission_exits_zero_regardless_of_score(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = io.StringIO()
            with (
                patch.dict("os.environ", {"DRIFTBOX_MISSION_DIR": directory}),
                patch("sys.argv", ["driftbox", "mission", "start", "first-watch"]),
                redirect_stdout(output),
            ):
                self.assertEqual(main(), 0)
            with (
                patch.dict("os.environ", {"DRIFTBOX_MISSION_DIR": directory}),
                patch("sys.argv", ["driftbox", "mission", "submit"]),
                patch("builtins.input", side_effect=["", ""]),
                redirect_stdout(output),
            ):
                exit_code = main()

        self.assertEqual(exit_code, 0)
        self.assertIn("Total score: 0/100", output.getvalue())

    def test_invalid_input_and_missing_session_exit_two(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            errors = io.StringIO()
            with (
                patch.dict("os.environ", {"DRIFTBOX_MISSION_DIR": directory}),
                patch("sys.argv", ["driftbox", "mission", "brief"]),
                redirect_stderr(errors),
            ):
                missing_exit = main()
            with (
                patch.dict("os.environ", {"DRIFTBOX_MISSION_DIR": directory}),
                patch("sys.argv", ["driftbox", "mission", "start", "first-watch"]),
                redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(main(), 0)
            with (
                patch.dict("os.environ", {"DRIFTBOX_MISSION_DIR": directory}),
                patch("sys.argv", ["driftbox", "mission", "submit"]),
                patch(
                    "builtins.input",
                    side_effect=["EV-999", "critical", "no-action", "EV-999"],
                ),
                redirect_stdout(io.StringIO()),
                redirect_stderr(errors),
            ):
                invalid_exit = main()

        self.assertEqual(missing_exit, 2)
        self.assertEqual(invalid_exit, 2)
        self.assertIn("mission failed", errors.getvalue())

    def test_commands_never_call_live_collectors_or_integrity_scanner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch.dict("os.environ", {"DRIFTBOX_MISSION_DIR": directory}),
                patch("driftbox.cli.build_report", side_effect=AssertionError("live")),
                patch(
                    "driftbox.cli.collect_firewall_info",
                    side_effect=AssertionError("live"),
                ),
                patch(
                    "driftbox.cli.collect_listening_ports",
                    side_effect=AssertionError("live"),
                ),
                patch(
                    "driftbox.integrity.scan_path",
                    side_effect=AssertionError("live"),
                ),
                redirect_stdout(io.StringIO()),
            ):
                start_mission("first-watch")
                show_mission_brief()
                record_submission(perfect_submission())
                self.assertEqual(active_mission_id(), "first-watch")


if __name__ == "__main__":
    unittest.main()
