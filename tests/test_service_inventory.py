"""Tests for the mocked-only Nmap service-inventory adapter."""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path
from unittest.mock import Mock

from driftbox.service_inventory import (
    DEFAULT_TOP_PORTS,
    MAX_EVIDENCE_FIELD_LENGTH,
    MAX_XML_BYTES,
    NMAP_HOST_TIMEOUT,
    NMAP_PROCESS_TIMEOUT_SECONDS,
    NMAP_VERSION_TIMEOUT_SECONDS,
    NmapAdapter,
    NmapExecutionError,
    NmapExecutionTimeoutError,
    NmapUnavailableError,
    NmapXMLParseError,
    NmapXMLSecurityError,
    ServiceTargetValidationError,
    TopPortsValidationError,
    build_nmap_command,
    parse_nmap_xml,
    sanitize_display,
    sanitize_evidence_text,
    validate_service_target,
    validate_top_ports,
)


FIXTURES = Path(__file__).with_name("fixtures")
COMPLETE_XML = (FIXTURES / "nmap_services_complete.xml").read_text(encoding="utf-8")
NO_OPEN_PARTIAL_XML = (FIXTURES / "nmap_no_open_partial.xml").read_text(
    encoding="utf-8"
)


class TargetAndProfileTests(unittest.TestCase):
    def test_allowlisted_canonical_single_addresses_only(self) -> None:
        for target in ("10.1.2.3", "172.16.0.1", "192.168.1.2", "127.0.0.1", "169.254.2.3"):
            with self.subTest(target=target):
                self.assertEqual(validate_service_target(target), target)
        unsafe = (
            "8.8.8.8", "172.15.0.1", "192.169.1.1", "10.0.0.0/24",
            "10.0.0.1-10.0.0.2", "10.*", "localhost", "https://10.0.0.1",
            "::1", " 10.0.0.1", "010.0.0.1", "10.0.0.1;--script=vuln",
        )
        for target in unsafe:
            with self.subTest(target=target):
                with self.assertRaises(ServiceTargetValidationError):
                    validate_service_target(target)

    def test_top_ports_default_and_boundaries(self) -> None:
        self.assertEqual(validate_top_ports(), DEFAULT_TOP_PORTS)
        self.assertEqual((validate_top_ports("1"), validate_top_ports(1000)), (1, 1000))
        for value in (0, 1001, -1, "01", "1.0", True, 1.0):
            with self.subTest(value=value):
                with self.assertRaises(TopPortsValidationError):
                    validate_top_ports(value)

    def test_exact_fixed_argument_array(self) -> None:
        executable = r"C:\Program Files\Nmap\nmap.exe"
        command = build_nmap_command(executable, "192.168.1.20", 1000)
        self.assertEqual(command, [
            executable, "-n", "-Pn", "--disable-arp-ping", "--unprivileged", "-sT", "--top-ports", "1000", "-sV",
            "--version-light", "--reason", "--open", "--host-timeout",
            NMAP_HOST_TIMEOUT, "-oX", "-", "192.168.1.20",
        ])
        for prohibited in ("-sC", "--script", "--script=vuln", "-O", "-sU", "-sS", "-A", "-D", "-f"):
            with self.subTest(prohibited=prohibited):
                self.assertNotIn(prohibited, command)
        self.assertEqual(command.count("192.168.1.20"), 1)


class XMLParsingTests(unittest.TestCase):
    def test_parses_and_orders_open_tcp_evidence_without_guessing(self) -> None:
        parsed = parse_nmap_xml(COMPLETE_XML, target="192.168.1.20")
        self.assertFalse(parsed.evidence_incomplete)
        self.assertEqual(parsed.host, {"state": "up", "reason": "user-set"})
        self.assertEqual([item["port"] for item in parsed.services], [22, 443])
        self.assertEqual(parsed.services[0]["service"], {
            "name": "ssh", "product": "Example SSH Server", "version": "9.6",
            "extrainfo": None, "tunnel": None, "cpe": [], "method": "probed", "confidence": 8,
        })
        self.assertEqual(
            parsed.services[1]["service"]["cpe"],
            ["cpe:/a:example:web_server:1.24"],
        )

    def test_privacy_safe_no_open_fixture_remains_partial_not_an_error(self) -> None:
        parsed = parse_nmap_xml(NO_OPEN_PARTIAL_XML, target="10.10.10.25")
        self.assertEqual(parsed.services, ())
        self.assertTrue(parsed.evidence_incomplete)
        self.assertTrue(any("completion metadata" in item for item in parsed.incomplete_reasons))

    def test_absent_target_extra_hosts_and_missing_finished_are_explicitly_incomplete(self) -> None:
        parsed = parse_nmap_xml("<nmaprun><host><address addr='10.0.0.2' addrtype='ipv4'/></host></nmaprun>", target="10.0.0.1")
        self.assertTrue(parsed.evidence_incomplete)
        self.assertEqual(parsed.host["state"], "unknown")
        self.assertEqual(parsed.services, ())
        self.assertTrue(any("requested target" in reason for reason in parsed.incomplete_reasons))

    def test_malformed_oversized_and_hostile_xml_are_rejected(self) -> None:
        cases = (
            ("<nmaprun><host>", NmapXMLParseError),
            ("<!DOCTYPE nmaprun SYSTEM 'https://bad.example/dtd'><nmaprun/>", NmapXMLSecurityError),
            ("<!DOCTYPE nmaprun [<!ENTITY x 'boom'>]><nmaprun>&x;</nmaprun>", NmapXMLSecurityError),
            ("<nmaprun><hostscript><script id='unexpected'/></hostscript></nmaprun>", NmapXMLSecurityError),
            ("<nmaprun>" + "x" * MAX_XML_BYTES + "</nmaprun>", NmapXMLSecurityError),
        )
        for xml, error in cases:
            with self.subTest(error=error):
                with self.assertRaises(error):
                    parse_nmap_xml(xml, target="10.0.0.1")

    def test_hostile_service_text_is_control_stripped_bounded_and_display_truncated(self) -> None:
        hostile = "X" + "z" * (MAX_EVIDENCE_FIELD_LENGTH + 50)
        xml = (
            "<nmaprun><host><status state='up'/><address addr='10.0.0.1' addrtype='ipv4'/>"
            "<ports><port protocol='tcp' portid='9'><state state='open'/><service product='"
            + hostile.replace("&", "&amp;").replace("'", "&apos;")
            + "'/></port></ports></host><runstats><finished/></runstats></nmaprun>"
        )
        value = parse_nmap_xml(xml, target="10.0.0.1").services[0]["service"]["product"]
        self.assertEqual(len(value), MAX_EVIDENCE_FIELD_LENGTH)
        self.assertTrue(sanitize_display(value, 12).endswith("…"))
        self.assertEqual(sanitize_evidence_text("a\tb\n"), "a b")
        self.assertEqual(sanitize_evidence_text("a\x1b[31mb\r\n"), "a [31mb")
        self.assertEqual(sanitize_evidence_text("safe\u202ereversed\u2066text"), "safe reversed text")

    def test_non_success_runstats_is_explicitly_incomplete(self) -> None:
        xml = COMPLETE_XML.replace('exit="success"', 'exit="failure"')
        parsed = parse_nmap_xml(xml, target="192.168.1.20")
        self.assertTrue(parsed.evidence_incomplete)
        self.assertTrue(any("non-success" in reason for reason in parsed.incomplete_reasons))

    def test_selected_scope_limits_services_and_invalid_confidence_is_unknown(self) -> None:
        with self.assertRaises(NmapXMLSecurityError):
            parse_nmap_xml(
                COMPLETE_XML,
                target="192.168.1.20",
                maximum_services=1,
            )
        for invalid_confidence in ("99", "100"):
            with self.subTest(confidence=invalid_confidence):
                xml = COMPLETE_XML.replace(
                    'conf="8"', f'conf="{invalid_confidence}"'
                )
                parsed = parse_nmap_xml(xml, target="192.168.1.20")
                self.assertIsNone(parsed.services[0]["service"]["confidence"])
                self.assertEqual(
                    parsed.services[0]["raw"]["conf"], invalid_confidence
                )


class AdapterTests(unittest.TestCase):
    def test_path_discovery_and_version_use_fixed_shell_false_calls(self) -> None:
        runner = Mock(
            return_value=subprocess.CompletedProcess(
                [], 0, b"Nmap version 7.95 ( https://nmap.org )", b""
            )
        )
        adapter = NmapAdapter(runner=runner, finder=Mock(return_value=r"C:\Nmap Space\nmap.exe"))
        installed = adapter.find_installation()
        self.assertEqual(installed.version, "7.95")
        runner.assert_called_once_with(
            [r"C:\Nmap Space\nmap.exe", "--version"], capture_output=True, text=False,
            timeout=NMAP_VERSION_TIMEOUT_SECONDS, check=False, shell=False,
        )

    def test_absent_bad_or_unresponsive_nmap_is_unavailable(self) -> None:
        with self.assertRaises(NmapUnavailableError):
            NmapAdapter(finder=Mock(return_value=None)).find_installation()
        for result in (
            subprocess.CompletedProcess([], 1, b"", b""),
            subprocess.CompletedProcess([], 0, b"other tool", b""),
        ):
            with self.subTest(result=result):
                with self.assertRaises(NmapUnavailableError):
                    NmapAdapter(runner=Mock(return_value=result), finder=Mock(return_value="nmap")).find_installation()

    def test_scan_is_mocked_and_uses_exact_argv_shell_false_and_bounded_timeout(self) -> None:
        runner = Mock(side_effect=(
            subprocess.CompletedProcess([], 0, b"Nmap version 7.95", b""),
            subprocess.CompletedProcess([], 0, COMPLETE_XML.encode("utf-8"), b""),
        ))
        adapter = NmapAdapter(runner=runner, finder=Mock(return_value="nmap"))
        result = adapter.scan("192.168.1.20", top_ports=100)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.command[-1], "192.168.1.20")
        call = runner.call_args_list[1]
        self.assertEqual(call.args[0], build_nmap_command("nmap", "192.168.1.20", 100))
        self.assertEqual(call.kwargs, {
            "capture_output": True, "text": False, "timeout": NMAP_PROCESS_TIMEOUT_SECONDS,
            "check": False, "shell": False,
        })

    def test_scan_timeout_nonzero_and_process_failure_are_structured(self) -> None:
        version = subprocess.CompletedProcess([], 0, b"Nmap version 7.95", b"")
        timeout_adapter = NmapAdapter(
            runner=Mock(side_effect=(version, subprocess.TimeoutExpired(["nmap"], 1))), finder=Mock(return_value="nmap")
        )
        with self.assertRaises(NmapExecutionTimeoutError):
            timeout_adapter.scan("10.0.0.1")
        nonzero_adapter = NmapAdapter(
            runner=Mock(
                side_effect=(
                    version,
                    subprocess.CompletedProcess([], 2, b"", b"bad\x1b[31m"),
                )
            ),
            finder=Mock(return_value="nmap"),
        )
        with self.assertRaises(NmapExecutionError) as raised:
            nonzero_adapter.scan("10.0.0.1")
        self.assertEqual(raised.exception.returncode, 2)
        self.assertNotIn("\x1b", str(raised.exception))
        unavailable_adapter = NmapAdapter(
            runner=Mock(side_effect=(version, FileNotFoundError())), finder=Mock(return_value="nmap")
        )
        with self.assertRaises(NmapUnavailableError):
            unavailable_adapter.scan("10.0.0.1")


if __name__ == "__main__":
    unittest.main()
