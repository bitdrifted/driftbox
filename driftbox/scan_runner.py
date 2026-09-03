"""Reusable orchestration for complete, headless Driftbox scans."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from driftbox.configuration import load_configuration, validate_configuration
from driftbox.findings import (
    Finding,
    FindingsResult,
    build_findings,
    combine_findings,
    drift_findings,
    integrity_findings,
    posture_findings,
)
from driftbox.history import (
    SnapshotInfo,
    capture_snapshot,
    list_snapshots,
    read_snapshot,
)
from driftbox.integrity import compare_integrity, load_manifest, scan_path
from driftbox.report_diff import compare_snapshots, normalize_report
from driftbox.security_checks import analyze_security_posture

SCAN_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class ScanResult:
    """Complete scan result suitable for terminals and automation."""

    previous_snapshot: str | None
    captured_snapshot: SnapshotInfo
    findings: FindingsResult

    def as_dict(self) -> dict[str, object]:
        data = self.findings.as_dict()
        return {
            "schema_version": SCAN_SCHEMA_VERSION,
            "previous_snapshot": self.previous_snapshot,
            "captured_snapshot": self.captured_snapshot.identifier,
            "summary": data["summary"],
            "findings": data["findings"],
        }


def _integrity_results(settings: dict[str, object]) -> list[FindingsResult]:
    targets = settings["integrity_targets"]
    if not isinstance(targets, list):
        raise ValueError("integrity_targets must be an array")
    results = []
    for target in targets:
        if not isinstance(target, dict):
            raise ValueError("integrity target must be an object")
        baseline = load_manifest(target["manifest"])
        current = scan_path(target["path"], excluded_path=target["manifest"])
        results.append(integrity_findings(compare_integrity(baseline, current)))
    return results


def _posture_result(current_report: dict[str, object]) -> FindingsResult:
    exposure = current_report.get("exposure")
    if not isinstance(exposure, dict):
        raise ValueError("current report exposure must be an object")
    return posture_findings(
        analyze_security_posture(
            current_report.get("firewall"),
            exposure.get("listening_ports"),
        )
    )


def run_scan(
    report_collector: Callable[[], dict[str, object]],
    configuration: dict[str, object] | None = None,
) -> ScanResult:
    """Compare, analyze, verify, then capture a report in that order."""
    if configuration is None:
        configuration = load_configuration()
    else:
        configuration = validate_configuration(configuration)
    settings = configuration["settings"]
    if not isinstance(settings, dict):
        raise ValueError("configuration settings must be an object")
    snapshots = list_snapshots()
    previous_identifier = snapshots[0].identifier if snapshots else None
    current_report = report_collector()
    results = [_posture_result(current_report), *_integrity_results(settings)]

    if previous_identifier is None:
        results.append(
            build_findings(
                [
                    Finding(
                        "scan-baseline-initialized",
                        "normal",
                        "Initial history baseline created",
                        "No earlier snapshot existed, so this scan establishes "
                        "the comparison baseline.",
                        {},
                        "Review the captured report and use later scans to "
                        "detect drift.",
                    )
                ]
            )
        )
    else:
        _, previous_report = read_snapshot(previous_identifier)
        drift = compare_snapshots(
            normalize_report(previous_report),
            normalize_report(current_report),
        )
        results.append(drift_findings(drift))

    # Capture happens only after configuration, comparison, posture analysis,
    # and every configured integrity target have completed successfully.
    combined = combine_findings(*results)
    captured = capture_snapshot(current_report)
    return ScanResult(previous_identifier, captured, combined)
