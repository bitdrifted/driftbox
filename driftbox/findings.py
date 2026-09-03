"""Unified, deterministic findings for Driftbox analysis features."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Iterable

from driftbox.integrity import IntegrityChanges
from driftbox.report_diff import Listener, ReportDrift

FINDINGS_SCHEMA_VERSION = 1
CLASSIFICATIONS = ("normal", "suspicious", "critical")


@dataclass(frozen=True)
class Finding:
    """One explained observation with evidence and a recommended action."""

    id: str
    classification: str
    title: str
    explanation: str
    evidence: dict[str, object]
    recommended_action: str

    def __post_init__(self) -> None:
        if self.classification not in CLASSIFICATIONS:
            raise ValueError(f"invalid finding classification: {self.classification}")


@dataclass(frozen=True)
class FindingsResult:
    """A schema-versioned, deterministically ordered findings collection."""

    findings: tuple[Finding, ...]

    @property
    def actionable(self) -> bool:
        """Return True when suspicious or critical findings exist."""
        return any(
            finding.classification in ("suspicious", "critical")
            for finding in self.findings
        )

    def as_dict(self) -> dict[str, object]:
        """Return a machine-readable findings document."""
        summary = {
            classification: sum(
                finding.classification == classification
                for finding in self.findings
            )
            for classification in CLASSIFICATIONS
        }
        summary["total"] = len(self.findings)
        return {
            "schema_version": FINDINGS_SCHEMA_VERSION,
            "summary": summary,
            "findings": [asdict(finding) for finding in self.findings],
        }


def build_findings(findings: Iterable[Finding]) -> FindingsResult:
    """Sort findings by stable identity and evidence."""
    return FindingsResult(
        tuple(
            sorted(
                findings,
                key=lambda finding: (
                    finding.id,
                    json.dumps(finding.evidence, sort_keys=True),
                ),
            )
        )
    )


def posture_findings(posture_result: object) -> FindingsResult:
    """Convert existing security-posture observations to unified findings."""
    observations = getattr(posture_result, "observations", None)
    if not isinstance(observations, tuple):
        raise ValueError("invalid security posture result")

    findings = []
    for observation in observations:
        observation_id = getattr(observation, "id", None)
        evidence = getattr(observation, "evidence", None)
        if not isinstance(observation_id, str) or not isinstance(evidence, dict):
            raise ValueError("invalid security posture observation")

        if observation_id == "firewall-disabled":
            findings.append(
                Finding(
                    "firewall-currently-disabled",
                    "critical",
                    "Firewall is disabled",
                    (
                        "The local firewall is confirmed disabled, reducing a "
                        "layer of network protection."
                    ),
                    evidence,
                    (
                        "Confirm this is intentional and enable an appropriate "
                        "firewall policy if it is not."
                    ),
                )
            )
        elif observation_id == "firewall-unknown":
            findings.append(
                Finding(
                    "firewall-state-unknown",
                    "suspicious",
                    "Firewall state is unknown",
                    (
                        "Driftbox could not determine firewall state, so "
                        "protection must not be assumed."
                    ),
                    evidence,
                    (
                        "Inspect the platform firewall with an authorized local "
                        "tool and confirm its policy."
                    ),
                )
            )
        elif observation_id in (
            "listener-all-interfaces",
            "listener-public-address",
        ):
            scope = evidence.get("scope", "unknown")
            findings.append(
                Finding(
                    observation_id,
                    "suspicious",
                    f"Service has a {scope} binding",
                    (
                        "The service has a broad network binding. This does not "
                        "prove internet accessibility because firewall policy, "
                        "routing, and NAT affect reachability."
                    ),
                    evidence,
                    (
                        "Confirm the binding is required and review firewall, "
                        "routing, and NAT controls."
                    ),
                )
            )
        else:
            raise ValueError(
                f"unsupported security posture observation: {observation_id}"
            )

    if not findings:
        findings.append(
            Finding(
                "posture-no-actionable-findings",
                "normal",
                "No actionable posture findings",
                (
                    "Current firewall and listener observations did not trigger "
                    "a suspicious or critical rule."
                ),
                {},
                "Continue routine monitoring and compare future reports for drift.",
            )
        )
    return build_findings(findings)


def _listener_evidence(listener: Listener) -> dict[str, object]:
    protocol, address, port, process, scope = listener
    return {
        "protocol": protocol,
        "address": address,
        "port": port,
        "process": process,
        "scope": scope,
    }


def drift_findings(drift: ReportDrift) -> FindingsResult:
    """Classify normalized report drift."""
    findings = []
    for listener in drift.added_listeners:
        findings.append(
            Finding(
                "listener-newly-detected",
                "suspicious",
                "New listening service detected",
                (
                    "A listener not present in the snapshot is now bound locally. "
                    "Its binding alone does not prove internet accessibility; "
                    "firewall policy, routing, and NAT matter."
                ),
                _listener_evidence(listener),
                (
                    "Verify the service is expected and review its binding and "
                    "network controls."
                ),
            )
        )
    for listener in drift.removed_listeners:
        findings.append(
            Finding(
                "listener-removed",
                "normal",
                "Listening service was removed",
                "A listener recorded in the snapshot is no longer present.",
                _listener_evidence(listener),
                "Confirm the service removal or outage was expected.",
            )
        )

    if drift.firewall_change is not None:
        previous, current = drift.firewall_change
        evidence = {"previous_status": previous, "current_status": current}
        if previous == "enabled" and current == "disabled":
            findings.append(
                Finding(
                    "firewall-regressed-to-disabled",
                    "critical",
                    "Firewall changed from enabled to disabled",
                    "The firewall lost confirmed protection since the stored snapshot.",
                    evidence,
                    (
                        "Confirm the change immediately and restore the intended "
                        "firewall policy."
                    ),
                )
            )
        elif current == "enabled" and previous != "enabled":
            findings.append(
                Finding(
                    "firewall-status-improved",
                    "normal",
                    "Firewall status improved",
                    (
                        "The firewall is now confirmed enabled after a less "
                        "protective or unknown state."
                    ),
                    evidence,
                    (
                        "Verify the enabled policy is the expected policy and "
                        "keep monitoring it."
                    ),
                )
            )

    if not findings:
        findings.append(
            Finding(
                "report-no-actionable-drift",
                "normal",
                "No actionable report drift",
                "No listener or firewall change requiring action was detected.",
                {},
                "Continue periodic captures and comparisons.",
            )
        )
    return build_findings(findings)


def integrity_findings(changes: IntegrityChanges) -> FindingsResult:
    """Classify file-integrity changes using the unified model."""
    findings = []
    for change_type, paths in (
        ("added", changes.added),
        ("missing", changes.missing),
        ("modified", changes.modified),
    ):
        for path in paths:
            findings.append(
                Finding(
                    f"integrity-file-{change_type}",
                    "suspicious",
                    f"Monitored file {change_type}",
                    (
                        f"A monitored file is {change_type} compared with the "
                        "trusted manifest."
                    ),
                    {"path": path, "change": change_type},
                    (
                        "Confirm the change is authorized; otherwise investigate "
                        "and restore a trusted copy."
                    ),
                )
            )
    if not findings:
        findings.append(
            Finding(
                "integrity-intact",
                "normal",
                "File integrity is intact",
                "All monitored files match the manifest.",
                {"unchanged_files": changes.unchanged_count},
                "Retain the manifest securely and continue periodic verification.",
            )
        )
    return build_findings(findings)


def combine_findings(*results: FindingsResult) -> FindingsResult:
    """Combine multiple finding sources into one deterministic result."""
    return build_findings(
        finding for result in results for finding in result.findings
    )


def format_findings(result: FindingsResult, heading: str) -> str:
    """Format unified findings for readable terminal output."""
    summary = result.as_dict()["summary"]
    if not isinstance(summary, dict):
        raise ValueError("invalid findings summary")
    lines = [
        f"driftbox :: {heading}",
        "-" * 32,
        (
            f"Summary: {summary['normal']} normal, {summary['suspicious']} suspicious, "
            f"{summary['critical']} critical"
        ),
    ]
    for finding in result.findings:
        evidence = ", ".join(
            f"{key}={value}" for key, value in sorted(finding.evidence.items())
        ) or "none"
        lines.extend(
            [
                "",
                f"[{finding.classification.upper()}] {finding.id}: {finding.title}",
                finding.explanation,
                f"Evidence: {evidence}",
                f"Recommended action: {finding.recommended_action}",
            ]
        )
    return "\n".join(lines)
