"""Small, safe platform adapters for Driftbox scheduled scans."""

from __future__ import annotations

import platform
import re
import shlex
import shutil
import subprocess
import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass

TASK_NAME = "Driftbox Daily Scan"
CRON_MARKER = "# driftbox-owned:daily-scan"
TIME_PATTERN = re.compile(r"^(?:[01]\d|2[0-3]):[0-5]\d$")


@dataclass(frozen=True)
class ScheduleResult:
    """Scheduler state or proposed/completed action."""

    state: str
    message: str


def _driftbox_executable() -> str:
    executable = shutil.which("driftbox")
    if not executable:
        raise ValueError("driftbox executable was not found on PATH")
    if any(character in executable for character in ("\0", "\r", "\n")):
        raise ValueError("driftbox executable path contains invalid characters")
    return executable


def _validate_time(daily_time: str) -> None:
    if not TIME_PATTERN.fullmatch(daily_time):
        raise ValueError("daily time must use 24-hour HH:MM format")


class WindowsScheduler:
    """Per-user Windows Task Scheduler adapter."""

    def _task_command(self) -> str:
        return subprocess.list2cmdline([_driftbox_executable(), "scan"])

    def status(self) -> ScheduleResult:
        result = subprocess.run(
            ["schtasks", "/Query", "/TN", TASK_NAME, "/XML"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            details = f"{result.stdout}\n{result.stderr}".lower()
            if "cannot find" in details or "does not exist" in details:
                return ScheduleResult("absent", "Driftbox scheduled scan is absent.")
            raise OSError(result.stderr.strip() or "Task Scheduler query failed")
        try:
            root = ElementTree.fromstring(result.stdout)
        except ElementTree.ParseError:
            return ScheduleResult("malformed", "Driftbox task exists but is malformed.")
        command = next(
            (
                element.text
                for element in root.iter()
                if element.tag.endswith("Command")
            ),
            None,
        )
        arguments = next(
            (
                element.text
                for element in root.iter()
                if element.tag.endswith("Arguments")
            ),
            None,
        )
        daily_interval = next(
            (
                element.text
                for element in root.iter()
                if element.tag.endswith("DaysInterval")
            ),
            None,
        )
        expected = _driftbox_executable()
        if (
            command is None
            or arguments != "scan"
            or daily_interval != "1"
            or str(command).casefold() != expected.casefold()
        ):
            return ScheduleResult("malformed", "Driftbox task exists but is malformed.")
        return ScheduleResult("installed", "Driftbox scheduled scan is installed.")

    def install(self, daily_time: str, dry_run: bool) -> ScheduleResult:
        _validate_time(daily_time)
        command = [
            "schtasks",
            "/Create",
            "/TN",
            TASK_NAME,
            "/SC",
            "DAILY",
            "/ST",
            daily_time,
            "/TR",
            self._task_command(),
            "/RL",
            "LIMITED",
            "/F",
        ]
        if dry_run:
            return ScheduleResult("dry-run", subprocess.list2cmdline(command))
        existing = self.status()
        if existing.state == "malformed":
            raise ValueError("refusing to replace a malformed task")
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            raise OSError(result.stderr.strip() or "Task Scheduler installation failed")
        return ScheduleResult("installed", "Driftbox scheduled scan installed.")

    def remove(self) -> ScheduleResult:
        existing = self.status()
        if existing.state == "absent":
            return existing
        if existing.state != "installed":
            raise ValueError("refusing to remove a malformed task")
        result = subprocess.run(
            ["schtasks", "/Delete", "/TN", TASK_NAME, "/F"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise OSError(result.stderr.strip() or "Task Scheduler removal failed")
        return ScheduleResult("absent", "Driftbox scheduled scan removed.")


class PosixScheduler:
    """Per-user crontab adapter that owns exactly one marked line."""

    def _command(self) -> str:
        # Cron treats unescaped percent signs specially even inside shell quotes.
        quoted_executable = shlex.quote(_driftbox_executable())
        escaped_executable = quoted_executable.replace("%", "\\%")
        return f"{escaped_executable} scan"

    def _line(self, daily_time: str) -> str:
        _validate_time(daily_time)
        hour, minute = daily_time.split(":")
        return f"{minute} {hour} * * * {self._command()} {CRON_MARKER}"

    def _read(self) -> str:
        result = subprocess.run(
            ["crontab", "-l"], capture_output=True, text=True, check=False
        )
        if result.returncode != 0:
            details = f"{result.stdout}\n{result.stderr}".lower()
            if "no crontab" in details:
                return ""
            raise OSError(result.stderr.strip() or "crontab query failed")
        return result.stdout

    def _owned_lines(self, crontab: str) -> list[str]:
        return [line for line in crontab.splitlines() if CRON_MARKER in line]

    def _status_for(self, crontab: str) -> ScheduleResult:
        owned = self._owned_lines(crontab)
        if not owned:
            return ScheduleResult("absent", "Driftbox scheduled scan is absent.")
        expected_command = self._command()
        if len(owned) != 1 or not re.fullmatch(
            r"[0-5]\d (?:[01]\d|2[0-3]) \* \* \* "
            + re.escape(expected_command)
            + " "
            + re.escape(CRON_MARKER),
            owned[0],
        ):
            return ScheduleResult("malformed", "Driftbox cron entry is malformed.")
        return ScheduleResult("installed", "Driftbox scheduled scan is installed.")

    def status(self) -> ScheduleResult:
        return self._status_for(self._read())

    def install(self, daily_time: str, dry_run: bool) -> ScheduleResult:
        line = self._line(daily_time)
        if dry_run:
            return ScheduleResult("dry-run", f"Install cron entry: {line}")
        current = self._read()
        state = self._status_for(current)
        if state.state == "malformed":
            raise ValueError("refusing to replace a malformed cron entry")
        kept = "".join(
            item
            for item in current.splitlines(keepends=True)
            if CRON_MARKER not in item
        )
        separator = "" if not kept or kept.endswith(("\n", "\r")) else "\n"
        updated = f"{kept}{separator}{line}\n"
        result = subprocess.run(
            ["crontab", "-"], input=updated, capture_output=True, text=True, check=False
        )
        if result.returncode != 0:
            raise OSError(result.stderr.strip() or "crontab installation failed")
        return ScheduleResult("installed", "Driftbox scheduled scan installed.")

    def remove(self) -> ScheduleResult:
        current = self._read()
        state = self._status_for(current)
        if state.state == "absent":
            return state
        if state.state != "installed":
            raise ValueError("refusing to remove a malformed cron entry")
        updated = "".join(
            item
            for item in current.splitlines(keepends=True)
            if CRON_MARKER not in item
        )
        result = subprocess.run(
            ["crontab", "-"], input=updated, capture_output=True, text=True, check=False
        )
        if result.returncode != 0:
            raise OSError(result.stderr.strip() or "crontab removal failed")
        return ScheduleResult("absent", "Driftbox scheduled scan removed.")


class UnsupportedScheduler:
    """Adapter for platforms without a configured scheduler backend."""

    def status(self) -> ScheduleResult:
        return ScheduleResult(
            "unsupported", "Scheduling is unsupported on this platform."
        )

    def install(self, daily_time: str, dry_run: bool) -> ScheduleResult:
        _validate_time(daily_time)
        return self.status()

    def remove(self) -> ScheduleResult:
        return self.status()


SchedulerAdapter = WindowsScheduler | PosixScheduler | UnsupportedScheduler


def scheduler_for_platform() -> SchedulerAdapter:
    """Return the scheduler adapter for the current platform."""
    operating_system = platform.system()
    if operating_system == "Windows":
        return WindowsScheduler()
    if operating_system in ("Linux", "Darwin"):
        return PosixScheduler()
    return UnsupportedScheduler()
