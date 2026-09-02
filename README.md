# driftbox

[![Cross-platform test](https://github.com/bitdrifted/driftbox/actions/workflows/cross-platform-test.yml/badge.svg)](https://github.com/bitdrifted/driftbox/actions/workflows/cross-platform-test.yml)

> inspect the system. reduce uncertainty. trust less.

**Driftbox** is a cross-platform terminal toolkit for system inspection, security checks, and resilient operations.

Built for Linux, Windows, macOS, and Windows Subsystem for Linux (WSL).

## status

`v0.1.0 — early development`

The cross-platform foundation and first system-inspection command are operational.

## current command

```text
driftbox info
```

Displays the execution environment, operating system, architecture, hostname, Python version, executable path, and WSL status.

## compatibility

| Environment | Status |
|---|---|
| Linux | Verified through automated testing |
| Windows Terminal / PowerShell | Verified locally and through automated testing |
| Windows Terminal / WSL 2 | Verified locally with Kali Linux |
| macOS | Verified through automated testing |

Driftbox automatically detects the operating environment and exposes information appropriate to that system.

## planned capabilities

- Network visibility and diagnostics
- File-integrity verification
- Security configuration checks
- Portable system reports
- Cross-platform terminal interface

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

Run the first command:

```bash
driftbox info
```

## license

Released under the [MIT License](LICENSE).

---

`root@bitdrifted:~# build > break > learn > repeat`
