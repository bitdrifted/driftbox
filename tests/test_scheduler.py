"""Tests for safe, owned platform scheduler adapters."""

import io
import subprocess
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import Mock, patch

from driftbox.cli import install_schedule, remove_schedule, show_schedule_status
from driftbox.scheduler import (
    CRON_MARKER,
    TASK_NAME,
    PosixScheduler,
    ScheduleResult,
    UnsupportedScheduler,
    WindowsScheduler,
    scheduler_for_platform,
)


def process(
    returncode: int = 0,
    stdout: str = "",
    stderr: str = "",
) -> subprocess.CompletedProcess[str]:
    """Build a small subprocess result for scheduler mocks."""
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


def task_xml(command: str, arguments: str = "scan") -> str:
    """Return representative Task Scheduler XML."""
    return (
        '<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
        "<Triggers><CalendarTrigger><ScheduleByDay><DaysInterval>1"
        "</DaysInterval></ScheduleByDay></CalendarTrigger></Triggers>"
        f"<Actions><Exec><Command>{command}</Command>"
        f"<Arguments>{arguments}</Arguments></Exec></Actions></Task>"
    )


class WindowsSchedulerTests(unittest.TestCase):
    """Verify Windows ownership, escaping, state, and removal behavior."""

    @patch(
        "driftbox.scheduler.shutil.which",
        return_value=r"C:\Program Files\Drift Box\driftbox.exe",
    )
    @patch("driftbox.scheduler.subprocess.run")
    def test_dry_run_escapes_path_without_subprocess(self, run: Mock, _: Mock) -> None:
        result = WindowsScheduler().install("02:30", dry_run=True)
        self.assertEqual(result.state, "dry-run")
        self.assertIn(
            r'\"C:\Program Files\Drift Box\driftbox.exe\" scan', result.message
        )
        run.assert_not_called()

    @patch("driftbox.scheduler.shutil.which", return_value=r"C:\Tools\driftbox.exe")
    @patch("driftbox.scheduler.subprocess.run")
    def test_status_distinguishes_states(self, run: Mock, _: Mock) -> None:
        run.return_value = process(stdout=task_xml(r"C:\Tools\driftbox.exe"))
        self.assertEqual(WindowsScheduler().status().state, "installed")
        run.return_value = process(
            1, stderr="ERROR: The system cannot find the file specified."
        )
        self.assertEqual(WindowsScheduler().status().state, "absent")
        run.return_value = process(stdout=task_xml(r"C:\Tools\other.exe"))
        self.assertEqual(WindowsScheduler().status().state, "malformed")

    @patch(
        "driftbox.scheduler.shutil.which", return_value=r"C:\Tools\driftbox.exe"
    )
    @patch("driftbox.scheduler.subprocess.run")
    def test_install_creates_limited_owned_task(self, run: Mock, _: Mock) -> None:
        run.side_effect = [
            process(
                1,
                stderr="ERROR: The system cannot find the file specified.",
            ),
            process(),
        ]
        result = WindowsScheduler().install("02:30", dry_run=False)
        command = run.call_args_list[1].args[0]
        self.assertEqual(result.state, "installed")
        self.assertEqual(command[command.index("/RL") + 1], "LIMITED")
        self.assertEqual(
            command[command.index("/TR") + 1],
            r"C:\Tools\driftbox.exe scan",
        )

    @patch("driftbox.scheduler.shutil.which", return_value=r"C:\Tools\driftbox.exe")
    @patch("driftbox.scheduler.subprocess.run")
    def test_remove_only_deletes_owned_task(self, run: Mock, _: Mock) -> None:
        run.side_effect = [
            process(stdout=task_xml(r"C:\Tools\driftbox.exe")),
            process(),
        ]
        result = WindowsScheduler().remove()
        self.assertEqual(result.state, "absent")
        self.assertEqual(
            run.call_args_list[1].args[0],
            ["schtasks", "/Delete", "/TN", TASK_NAME, "/F"],
        )

        run.reset_mock()
        run.side_effect = None
        run.return_value = process(stdout=task_xml(r"C:\Tools\other.exe"))
        with self.assertRaisesRegex(ValueError, "refusing"):
            WindowsScheduler().remove()
        self.assertEqual(run.call_count, 1)


class PosixSchedulerTests(unittest.TestCase):
    """Verify cron ownership, exact preservation, and command quoting."""

    @patch("driftbox.scheduler.shutil.which", return_value="/opt/Drift Box/driftbox")
    @patch("driftbox.scheduler.subprocess.run")
    def test_dry_run_quotes_path_without_subprocess(self, run: Mock, _: Mock) -> None:
        result = PosixScheduler().install("02:30", dry_run=True)
        self.assertEqual(result.state, "dry-run")
        self.assertIn("'/opt/Drift Box/driftbox' scan", result.message)
        run.assert_not_called()

    @patch("driftbox.scheduler.shutil.which", return_value="/usr/bin/driftbox")
    @patch("driftbox.scheduler.subprocess.run")
    def test_install_and_remove_preserve_unrelated_entries(
        self, run: Mock, _: Mock
    ) -> None:
        unrelated = "# backup\n15 1 * * * /usr/bin/backup\n"
        run.side_effect = [process(stdout=unrelated), process()]
        installed = PosixScheduler().install("02:30", dry_run=False)
        written = run.call_args_list[1].kwargs["input"]
        self.assertEqual(installed.state, "installed")
        self.assertTrue(written.startswith(unrelated))
        self.assertIn(f"30 02 * * * /usr/bin/driftbox scan {CRON_MARKER}\n", written)

        run.reset_mock()
        owned = f"30 02 * * * /usr/bin/driftbox scan {CRON_MARKER}\n"
        run.side_effect = [process(stdout=unrelated + owned), process()]
        removed = PosixScheduler().remove()
        self.assertEqual(removed.state, "absent")
        self.assertEqual(run.call_args_list[1].kwargs["input"], unrelated)

    @patch("driftbox.scheduler.shutil.which", return_value="/usr/bin/driftbox")
    @patch("driftbox.scheduler.subprocess.run")
    def test_status_and_malformed_ownership(self, run: Mock, _: Mock) -> None:
        run.return_value = process(1, stderr="no crontab for test")
        self.assertEqual(PosixScheduler().status().state, "absent")
        run.return_value = process(
            stdout=f"not a cron line {CRON_MARKER}\n"
        )
        self.assertEqual(PosixScheduler().status().state, "malformed")
        with self.assertRaisesRegex(ValueError, "refusing"):
            PosixScheduler().remove()

    @patch("driftbox.scheduler.shutil.which", return_value="/usr/bin/driftbox")
    def test_invalid_time_and_control_characters_are_rejected(
        self, which: Mock
    ) -> None:
        with self.assertRaisesRegex(ValueError, "HH:MM"):
            PosixScheduler().install("2:30", dry_run=True)
        which.return_value = "/tmp/driftbox\ninjected"
        with self.assertRaisesRegex(ValueError, "invalid characters"):
            PosixScheduler().install("02:30", dry_run=True)

    @patch(
        "driftbox.scheduler.shutil.which", return_value="/opt/100%/driftbox"
    )
    def test_cron_percent_is_escaped(self, _: Mock) -> None:
        result = PosixScheduler().install("02:30", dry_run=True)
        self.assertIn(r"/opt/100\%/driftbox scan", result.message)


class SchedulerCommandTests(unittest.TestCase):
    """Verify adapter selection and CLI exit semantics without real scheduling."""

    def test_platform_selection_includes_unsupported(self) -> None:
        with patch("driftbox.scheduler.platform.system", return_value="Windows"):
            self.assertIsInstance(scheduler_for_platform(), WindowsScheduler)
        with patch("driftbox.scheduler.platform.system", return_value="Linux"):
            self.assertIsInstance(scheduler_for_platform(), PosixScheduler)
        with patch("driftbox.scheduler.platform.system", return_value="Plan9"):
            self.assertIsInstance(scheduler_for_platform(), UnsupportedScheduler)

    def test_cli_states_and_errors(self) -> None:
        adapter = Mock()
        output = io.StringIO()
        errors = io.StringIO()
        with (
            patch("driftbox.cli.scheduler_for_platform", return_value=adapter),
            redirect_stdout(output),
            redirect_stderr(errors),
        ):
            adapter.install.return_value = ScheduleResult("dry-run", "proposed")
            self.assertEqual(install_schedule("02:30", True), 0)
            adapter.status.return_value = ScheduleResult("malformed", "bad")
            self.assertEqual(show_schedule_status(), 2)
            adapter.remove.side_effect = OSError("denied")
            self.assertEqual(remove_schedule(), 2)
        self.assertIn("Schedule state: dry-run", output.getvalue())
        self.assertIn("Schedule state: malformed", output.getvalue())
        self.assertIn("schedule remove failed", errors.getvalue())

    def test_unsupported_status_returns_two(self) -> None:
        output = io.StringIO()
        with (
            patch(
                "driftbox.cli.scheduler_for_platform",
                return_value=UnsupportedScheduler(),
            ),
            redirect_stdout(output),
        ):
            exit_code = show_schedule_status()
        self.assertEqual(exit_code, 2)
        self.assertIn("Schedule state: unsupported", output.getvalue())


if __name__ == "__main__":
    unittest.main()
