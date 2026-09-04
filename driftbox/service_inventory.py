"""Safe adapter and evidence parser for one authorized Nmap service inventory.

This module deliberately has no command-line entry point.  Callers must obtain
an explicit authorization confirmation before calling :meth:`NmapAdapter.scan`.
It accepts exactly one canonical numeric address and constructs Nmap arguments
without a shell.  The adapter never resolves names or broadens the target.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import re
import shutil
import subprocess
from typing import Callable, Sequence
import unicodedata
from xml.etree import ElementTree


SERVICE_INVENTORY_SCHEMA_VERSION = 1
DEFAULT_TOP_PORTS = 100
MIN_TOP_PORTS = 1
MAX_TOP_PORTS = 1_000
NMAP_HOST_TIMEOUT = "60s"
NMAP_PROCESS_TIMEOUT_SECONDS = 75
NMAP_VERSION_TIMEOUT_SECONDS = 5
MAX_XML_BYTES = 1_000_000
MAX_XML_SERVICES = MAX_TOP_PORTS
MAX_EVIDENCE_FIELD_LENGTH = 2_048
DEFAULT_DISPLAY_FIELD_LENGTH = 120

_ALLOWED_ADDRESS_RANGES = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),
)
_XML_ENTITY_DECLARATION = re.compile(br"<!\s*ENTITY\b", re.IGNORECASE)
# Nmap itself emits this harmless declaration in normal ``-oX`` output.  It is
# removed before parsing so neither a DTD nor any external resource is used.
_NMAP_DOCTYPE = re.compile(br"<!DOCTYPE\s+nmaprun\s*>", re.IGNORECASE)
_ANY_DOCTYPE = re.compile(br"<!\s*DOCTYPE\b", re.IGNORECASE)
_TERMINAL_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_NMAP_VERSION = re.compile(r"\bNmap version\s+([^\s]+)", re.IGNORECASE)
_SAFE_SERVICE_CONFIDENCE = re.compile(r"^\d{1,2}$")


class ServiceInventoryError(Exception):
    """Base class for expected service-inventory failures."""


class AuthorizationRequiredError(ServiceInventoryError):
    """The required explicit authorization confirmation was not supplied."""


class ServiceTargetValidationError(ServiceInventoryError, ValueError):
    """The requested target is not one approved canonical IPv4 address."""


class TopPortsValidationError(ServiceInventoryError, ValueError):
    """The common TCP-port scope was outside the small bounded range."""


class NmapUnavailableError(ServiceInventoryError):
    """Nmap was absent from PATH or did not provide a usable version response."""


class NmapExecutionTimeoutError(ServiceInventoryError):
    """The overall bounded Nmap process timeout elapsed."""


class NmapExecutionError(ServiceInventoryError):
    """Nmap started but returned a nonzero exit status."""

    def __init__(self, returncode: int, detail: str | bytes | None = None) -> None:
        self.returncode = returncode
        self.detail = _process_output_text(detail) if detail else None
        message = f"Nmap exited with status {returncode}."
        if self.detail:
            message += f" {sanitize_display(self.detail, 240)}"
        super().__init__(message)


class NmapXMLSecurityError(ServiceInventoryError):
    """Nmap XML exceeded bounds or contained an unsafe XML declaration."""


class NmapXMLParseError(ServiceInventoryError):
    """Nmap XML was incomplete, malformed, or structurally unusable."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _process_output_text(value: str | bytes | None) -> str | None:
    """Decode bounded subprocess diagnostics independently of the host locale."""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return sanitize_evidence_text(value)


def _is_allowed_address(address: ipaddress.IPv4Address) -> bool:
    return any(address in allowed for allowed in _ALLOWED_ADDRESS_RANGES)


def validate_service_target(target: str) -> str:
    """Return one canonical local IPv4 address or refuse the request.

    ``ipaddress`` does not resolve names.  Comparing its rendered value to the
    input rejects whitespace, leading-zero forms, CIDRs, URLs, ranges, and
    other alternate spellings before the value can reach a subprocess.
    """
    if not isinstance(target, str) or not target or target != target.strip():
        raise ServiceTargetValidationError(
            "Target must be exactly one canonical numeric IPv4 address."
        )
    try:
        address = ipaddress.ip_address(target)
    except ValueError as exc:
        raise ServiceTargetValidationError(
            "Target must be exactly one canonical numeric IPv4 address; names, URLs, "
            "ranges, and CIDRs are refused."
        ) from exc
    if not isinstance(address, ipaddress.IPv4Address) or str(address) != target:
        raise ServiceTargetValidationError(
            "Target must be exactly one canonical numeric IPv4 address; IPv6 and "
            "alternate forms are refused."
        )
    if not _is_allowed_address(address):
        raise ServiceTargetValidationError(
            "Target must be in RFC1918 private, IPv4 loopback, or IPv4 link-local "
            "address space. Private addressing does not prove authorization."
        )
    return str(address)


def validate_top_ports(value: object = DEFAULT_TOP_PORTS) -> int:
    """Validate the deliberately narrow selected TCP-port scope."""
    if isinstance(value, bool):
        raise TopPortsValidationError("--top-ports must be an integer from 1 through 1000.")
    if isinstance(value, str):
        if not value.isdecimal() or (len(value) > 1 and value.startswith("0")):
            raise TopPortsValidationError("--top-ports must be an integer from 1 through 1000.")
        parsed = int(value)
    elif isinstance(value, int):
        parsed = value
    else:
        raise TopPortsValidationError("--top-ports must be an integer from 1 through 1000.")
    if not MIN_TOP_PORTS <= parsed <= MAX_TOP_PORTS:
        raise TopPortsValidationError("--top-ports must be an integer from 1 through 1000.")
    return parsed


def build_nmap_command(
    executable: str,
    target: str,
    top_ports: object = DEFAULT_TOP_PORTS,
) -> list[str]:
    """Build the fixed, unprivileged, single-host Nmap profile as an argv list."""
    if not isinstance(executable, str) or not executable:
        raise NmapUnavailableError("A usable Nmap executable was not detected on PATH.")
    safe_target = validate_service_target(target)
    safe_top_ports = validate_top_ports(top_ports)
    return [
        executable,
        "-n",                 # never resolve DNS
        "-Pn",                # no host-discovery dependency
        "--disable-arp-ping", # do not substitute local-Ethernet ARP discovery
        "--unprivileged",     # force Nmap's non-raw-socket behavior
        "-sT",                # unprivileged TCP connect scan
        "--top-ports",
        str(safe_top_ports),  # bounded common TCP ports only
        "-sV",
        "--version-light",
        "--reason",
        "--open",
        "--host-timeout",
        NMAP_HOST_TIMEOUT,
        "-oX",
        "-",                  # XML only on stdout
        safe_target,           # exactly one independently validated target
    ]


def sanitize_evidence_text(value: object | None, *, maximum: int = MAX_EVIDENCE_FIELD_LENGTH) -> str | None:
    """Remove terminal controls and bound retained evidence for JSON safety."""
    if value is None:
        return None
    if not isinstance(value, str):
        value = str(value)
    # A space avoids joining two words separated by a line/escape control.
    cleaned = _TERMINAL_CONTROL.sub(" ", value)
    # Unicode format/bidi controls can alter the perceived terminal order even
    # though they are outside C0/C1.  Drop all Unicode "Other" characters.
    cleaned = "".join(
        " " if unicodedata.category(character).startswith("C") else character
        for character in cleaned
    )
    cleaned = " ".join(cleaned.split())
    if maximum < 1:
        raise ValueError("maximum must be positive")
    return cleaned[:maximum]


def sanitize_display(value: object | None, maximum: int = DEFAULT_DISPLAY_FIELD_LENGTH) -> str:
    """Return safe terminal text without truncating the separately stored JSON value."""
    if maximum < 1:
        raise ValueError("maximum must be positive")
    cleaned = sanitize_evidence_text(value, maximum=MAX_EVIDENCE_FIELD_LENGTH) or "unavailable"
    return cleaned if len(cleaned) <= maximum else f"{cleaned[: maximum - 1]}…"


@dataclass(frozen=True)
class NmapInstallation:
    executable: str
    version: str


@dataclass(frozen=True)
class ParsedNmapEvidence:
    """Strict, bounded evidence extracted only for the requested address."""

    host: dict[str, object]
    services: tuple[dict[str, object], ...]
    evidence_incomplete: bool
    incomplete_reasons: tuple[str, ...]
    nmap_xml_version: str | None


@dataclass(frozen=True)
class NmapScanResult:
    installation: NmapInstallation
    command: tuple[str, ...]
    started_at: str
    completed_at: str
    exit_code: int
    parsed: ParsedNmapEvidence


CommandRunner = Callable[..., subprocess.CompletedProcess[bytes]]
ExecutableFinder = Callable[[str], str | None]


class NmapAdapter:
    """Testable process boundary for an operator-installed Nmap executable."""

    def __init__(
        self,
        *,
        runner: CommandRunner = subprocess.run,
        finder: ExecutableFinder = shutil.which,
    ) -> None:
        self._runner = runner
        self._finder = finder

    def find_installation(self) -> NmapInstallation:
        """Find Nmap dynamically through PATH and obtain its reported version."""
        executable = self._finder("nmap")
        if not executable:
            raise NmapUnavailableError(
                "Nmap was not found on PATH. Install it separately and make `nmap` "
                "available to Driftbox; Driftbox does not download or bundle Nmap."
            )
        try:
            completed = self._runner(
                [executable, "--version"],
                capture_output=True,
                text=False,
                timeout=NMAP_VERSION_TIMEOUT_SECONDS,
                check=False,
                shell=False,
            )
        except (FileNotFoundError, PermissionError, OSError, subprocess.TimeoutExpired) as exc:
            raise NmapUnavailableError("Nmap could not be executed from the detected PATH entry.") from exc
        if completed.returncode != 0:
            raise NmapUnavailableError("Nmap did not return a usable version response.")
        version_output = _process_output_text(completed.stdout) or ""
        version_match = _NMAP_VERSION.search(version_output)
        version = sanitize_evidence_text(version_match.group(1) if version_match else None, maximum=80)
        if not version:
            raise NmapUnavailableError("The detected executable did not identify itself as Nmap.")
        return NmapInstallation(executable=executable, version=version)

    def scan(self, target: str, *, top_ports: object = DEFAULT_TOP_PORTS) -> NmapScanResult:
        """Execute the fixed profile once and parse only its bounded XML evidence."""
        safe_target = validate_service_target(target)
        safe_top_ports = validate_top_ports(top_ports)
        installation = self.find_installation()
        command = build_nmap_command(installation.executable, safe_target, safe_top_ports)
        started_at = _utc_now()
        try:
            completed = self._runner(
                command,
                capture_output=True,
                text=False,
                timeout=NMAP_PROCESS_TIMEOUT_SECONDS,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise NmapExecutionTimeoutError(
                "Nmap did not finish within Driftbox's bounded process timeout."
            ) from exc
        except (FileNotFoundError, PermissionError, OSError) as exc:
            raise NmapUnavailableError("Nmap became unavailable before the scan could start.") from exc
        completed_at = _utc_now()
        if completed.returncode != 0:
            raise NmapExecutionError(completed.returncode, completed.stderr)
        parsed = parse_nmap_xml(
            completed.stdout or "",
            target=safe_target,
            maximum_services=safe_top_ports,
        )
        return NmapScanResult(
            installation=installation,
            command=tuple(command),
            started_at=started_at,
            completed_at=completed_at,
            exit_code=completed.returncode,
            parsed=parsed,
        )


def _validated_xml_bytes(xml: str | bytes) -> bytes:
    if isinstance(xml, str):
        try:
            payload = xml.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise NmapXMLParseError("Nmap XML was not valid text.") from exc
    elif isinstance(xml, bytes):
        payload = xml
    else:
        raise NmapXMLParseError("Nmap XML was not text.")
    if not payload:
        raise NmapXMLParseError("Nmap did not produce XML evidence.")
    if len(payload) > MAX_XML_BYTES:
        raise NmapXMLSecurityError(
            f"Nmap XML exceeded the {MAX_XML_BYTES}-byte evidence limit."
        )
    if b"\x00" in payload or _XML_ENTITY_DECLARATION.search(payload):
        raise NmapXMLSecurityError(
            "Nmap XML included a prohibited ENTITY or NUL declaration."
        )
    # Normal Nmap XML contains ``<!DOCTYPE nmaprun>``.  Permit only that exact
    # form and remove it; reject external DTDs and internal subsets outright.
    payload = _NMAP_DOCTYPE.sub(b"", payload)
    if _ANY_DOCTYPE.search(payload):
        raise NmapXMLSecurityError("Nmap XML included an unsupported DOCTYPE declaration.")
    return payload


def _attribute(element: ElementTree.Element, name: str, *, maximum: int = MAX_EVIDENCE_FIELD_LENGTH) -> str | None:
    return sanitize_evidence_text(element.get(name), maximum=maximum)


def _safe_port_number(value: str | None) -> int | None:
    if value is None or not value.isdecimal():
        return None
    port = int(value)
    return port if 1 <= port <= 65535 else None


def _parse_service(port: ElementTree.Element) -> dict[str, object] | None:
    if port.get("protocol") != "tcp":
        return None
    number = _safe_port_number(port.get("portid"))
    state_element = port.find("state")
    if number is None or state_element is None or state_element.get("state") != "open":
        return None
    service_element = port.find("service")
    raw: dict[str, object] = {}
    service: dict[str, object] = {
        "name": None,
        "product": None,
        "version": None,
        "extrainfo": None,
        "tunnel": None,
        "cpe": [],
        "method": None,
        "confidence": None,
    }
    if service_element is not None:
        for field in ("name", "product", "version", "extrainfo", "tunnel", "method", "ostype"):
            raw[field] = _attribute(service_element, field)
        service.update({field: raw[field] for field in ("name", "product", "version", "extrainfo", "tunnel", "method")})
        # Validate the complete bounded attribute before converting it.  If we
        # truncated first, hostile evidence such as ``conf="100"`` could be
        # misrepresented as the valid confidence value ``10``.
        confidence = _attribute(service_element, "conf", maximum=80)
        if confidence and _SAFE_SERVICE_CONFIDENCE.fullmatch(confidence):
            confidence_value = int(confidence)
            service["confidence"] = (
                confidence_value if 0 <= confidence_value <= 10 else None
            )
        cpes = [
            sanitize_evidence_text(child.text)
            for child in service_element.findall("cpe")
            if sanitize_evidence_text(child.text)
        ]
        service["cpe"] = sorted(set(cpes))
        raw["conf"] = confidence
    return {
        "protocol": "tcp",
        "port": number,
        "state": "open",
        "reason": _attribute(state_element, "reason"),
        "service": service,
        "raw": raw,
    }


def parse_nmap_xml(
    xml: str | bytes,
    *,
    target: str,
    maximum_services: object = MAX_XML_SERVICES,
) -> ParsedNmapEvidence:
    """Parse bounded Nmap XML without accepting entities or extra host evidence.

    Missing completion metadata or an absent requested host creates an explicit
    incomplete result.  Malformed XML is rejected because it cannot safely be
    distinguished from a complete observation.
    """
    safe_target = validate_service_target(target)
    safe_maximum_services = validate_top_ports(maximum_services)
    payload = _validated_xml_bytes(xml)
    try:
        root = ElementTree.fromstring(payload)
    except (ElementTree.ParseError, UnicodeDecodeError) as exc:
        raise NmapXMLParseError("Nmap XML was malformed or incomplete.") from exc
    if root.tag != "nmaprun" or root.get("scanner") not in {None, "nmap"}:
        raise NmapXMLParseError("Nmap XML did not contain an nmaprun root element.")
    if root.find(".//script") is not None:
        raise NmapXMLSecurityError(
            "Nmap XML contained script evidence outside the permitted profile."
        )

    incomplete_reasons: list[str] = []
    finished = root.find("runstats/finished")
    if finished is None:
        incomplete_reasons.append("Nmap completion metadata was not present in the XML.")
    elif finished.get("exit") not in {None, "success"}:
        incomplete_reasons.append("Nmap XML reported a non-success completion state.")

    matching_host: ElementTree.Element | None = None
    reported_host_count = 0
    for host in root.findall("host"):
        reported_host_count += 1
        addresses = [item.get("addr") for item in host.findall("address") if item.get("addrtype") == "ipv4"]
        if safe_target in addresses and matching_host is None:
            matching_host = host
    if reported_host_count > 1:
        incomplete_reasons.append("Additional reported hosts were ignored; only the requested target is used.")
    if matching_host is None:
        incomplete_reasons.append("The requested target was not present in Nmap XML output.")
        return ParsedNmapEvidence(
            host={"state": "unknown", "reason": None},
            services=(),
            evidence_incomplete=True,
            incomplete_reasons=tuple(incomplete_reasons),
            nmap_xml_version=_attribute(root, "version", maximum=80),
        )

    status = matching_host.find("status")
    host = {
        "state": _attribute(status, "state", maximum=32) if status is not None else "unknown",
        "reason": _attribute(status, "reason") if status is not None else None,
    }
    if status is None:
        incomplete_reasons.append("The requested host did not include a host-state record.")
    parsed_services: list[dict[str, object]] = []
    seen_ports: set[int] = set()
    for port in matching_host.findall("ports/port"):
        record = _parse_service(port)
        if record is None:
            continue
        port_number = int(record["port"])
        if port_number in seen_ports:
            incomplete_reasons.append("Duplicate open-port records were ignored.")
            continue
        seen_ports.add(port_number)
        parsed_services.append(record)
        if len(parsed_services) > safe_maximum_services:
            raise NmapXMLSecurityError(
                "Nmap XML contained more open TCP services than the selected port scope."
            )
    parsed_services.sort(key=lambda item: int(item["port"]))
    return ParsedNmapEvidence(
        host=host,
        services=tuple(parsed_services),
        evidence_incomplete=bool(incomplete_reasons),
        incomplete_reasons=tuple(incomplete_reasons),
        nmap_xml_version=_attribute(root, "version", maximum=80),
    )
