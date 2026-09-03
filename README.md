# driftbox

[![Cross-platform test](https://github.com/bitdrifted/driftbox/actions/workflows/cross-platform-test.yml/badge.svg)](https://github.com/bitdrifted/driftbox/actions/workflows/cross-platform-test.yml)

> inspect the system. reduce uncertainty. trust less.

**Driftbox** is a cross-platform terminal toolkit for system inspection, security checks, and resilient operations.

Built for Linux, Windows, macOS, and Windows Subsystem for Linux (WSL).

## status

`v0.1.0 — early development`

System inspection, network inspection, listening-port inspection, portable JSON reports, automated tests, and cross-platform validation are operational.

## current commands

| Command | Purpose |
|---|---|
| `driftbox info` | Display system and execution-environment information |
| `driftbox network` | Display local network information |
| `driftbox ports` | Classify listening TCP and bound UDP ports by network scope |
| `driftbox report` | Generate a machine-readable JSON report |
## port exposure

Inspect services accepting network traffic:

```bash
driftbox ports
```
## Firewall inspection

Inspect the local firewall status without changing its configuration:

```bash
driftbox firewall
```

Driftbox supports Microsoft Defender Firewall on Windows, UFW or firewalld
on Linux, and the Application Firewall on macOS. If the status cannot be
confirmed, Driftbox reports it as `unknown` instead of guessing.

## portable reports

Display a report in the terminal:

```bash
driftbox report
```

Save it to a file:

```bash
driftbox report > driftbox-report.json
```

Reports include system details, local network addresses, listening ports, process information, exposure classifications, the Driftbox version, and a UTC generation timestamp.

Review reports before sharing them because they may contain hostnames, local addresses, process names, process IDs, and other system information.

## compatibility

| Environment | Status |
|---|---|
| Linux | Verified through automated testing |
| Windows Terminal / PowerShell | Verified locally and through automated testing |
| Windows Terminal / WSL 2 | Verified locally with Kali Linux |
| macOS | Verified through automated testing |

Driftbox automatically detects the operating environment and exposes information appropriate to that system.

## planned capabilities

- File-integrity verification
- Security configuration checks
- Optional report redaction

## operating principles

```text
trust: minimal
verify: always
assume: compromise
```

- Prefer inspection over assumption
- Produce readable, exportable results
- Avoid unnecessary privileges
- Keep core functions transparent
- Fail safely and explain why

## development installation

Clone the repository:

```bash
git clone https://github.com/bitdrifted/driftbox.git
cd driftbox
```

Install Driftbox:

```bash
python -m pip install -e .
```

Run the test suite:

```bash
python -m unittest discover -s tests -v
```

## license

Released under the [MIT License](LICENSE).

---

`root@bitdrifted:~# build > break > learn > repeat`