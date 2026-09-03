# driftbox

[![Cross-platform test](https://github.com/bitdrifted/driftbox/actions/workflows/cross-platform-test.yml/badge.svg)](https://github.com/bitdrifted/driftbox/actions/workflows/cross-platform-test.yml)

> inspect the system. reduce uncertainty. trust less.

**Driftbox** is a cross-platform terminal toolkit for system inspection, security checks, and resilient operations.

Built for Linux, Windows, macOS, and Windows Subsystem for Linux (WSL).

## status

`v0.1.0 — early development`

System inspection, network inspection, listening-port inspection, portable JSON reports, persistent report history, report drift detection, file-integrity verification, security posture checks, automated tests, and cross-platform validation are operational.

## current commands

| Command | Purpose |
|---|---|
| `driftbox info` | Display system and execution-environment information |
| `driftbox network` | Display local network information |
| `driftbox ports` | Classify listening TCP and bound UDP ports by network scope |
| `driftbox firewall` | Inspect local firewall status without changing its configuration |
| `driftbox report` | Generate a machine-readable JSON report |
| `driftbox diff baseline.json` | Compare current security-relevant state with a saved report |
| `driftbox integrity create PATH --output MANIFEST.json` | Create a SHA-256 file-integrity manifest |
| `driftbox integrity verify PATH MANIFEST.json` | Verify files against an integrity manifest |
| `driftbox check` | Analyze firewall and listening-port security posture |
| `driftbox check --json` | Produce a machine-readable security posture result |
| `driftbox history capture` | Save the current report in local history |
| `driftbox history list [--json]` | List saved report snapshots newest first |
| `driftbox history show SNAPSHOT` | Display a stored report snapshot |
| `driftbox history diff SNAPSHOT` | Compare current state with a stored snapshot |
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

Reports include system details, local network addresses, firewall status, listening ports, process information, exposure classifications, the Driftbox version, and a UTC generation timestamp. Firewall inspection results appear under the top-level `firewall` key.

Review reports before sharing them because they may contain hostnames, local addresses, process names, process IDs, and other system information.

## report drift detection

Create a baseline from the system's current state:

```bash
driftbox report > baseline.json
```

This command works directly in PowerShell as well as other supported shells.
Driftbox accepts UTF-8 baselines (with or without a byte-order marker) and the
BOM-marked UTF-16 output produced by Windows PowerShell redirection.

Later, compare a fresh report with that baseline:

```bash
driftbox diff baseline.json
```

Driftbox reports added and removed listening services or endpoints and firewall
status changes. Listener comparisons include protocol, address, port, process,
and interface scope. Volatile timestamps and process IDs are ignored, and output
is sorted so repeated comparisons remain predictable.

The command exits with status `0` when no drift is detected, `1` when drift is
detected, and `2` when the baseline cannot be read or is not a valid Driftbox
report.

## file-integrity verification

Create a SHA-256 manifest for one regular file or an entire directory tree:

```bash
driftbox integrity create PATH --output MANIFEST.json
```

Verify the current files against that manifest:

```bash
driftbox integrity verify PATH MANIFEST.json
```

Manifests contain normalized relative paths, file sizes, and SHA-256 hashes in
deterministic order. Directory scans are recursive and do not follow symbolic
links. A manifest stored inside the scanned directory excludes itself from both
creation and verification.

Verification reports added, missing, modified, and unchanged files. It exits
with status `0` when integrity is intact, `1` when changes are detected, and `2`
for invalid manifests, unsupported versions, missing or unreadable paths, and
permission errors. Driftbox fails instead of writing or checking a partial
manifest if any regular file cannot be read.

## security posture checks

Analyze existing firewall and listening-port inspection data:

```bash
driftbox check
```

Produce a versioned JSON result for automation:

```bash
driftbox check --json
```

Driftbox reports a high-severity finding when the firewall is confirmed disabled
and a warning when firewall status is unknown. Unknown status is never treated as
secure. Services listening on all interfaces or bound to a public address produce
warnings; local-only, link-local, and private-network bindings do not produce
findings solely because of their scope.

A broad or public binding does not by itself prove that a service is accessible
from the internet. Firewall policy, routing, and NAT can all affect reachability.
The command exits with status `0` when no warning or high-severity findings exist,
`1` when findings exist, and `2` after an unexpected inspection or output error.

## persistent report history

Capture a complete report using an automatic, unique UTC snapshot identifier:

```bash
driftbox history capture
```

List snapshots newest first, either for people or automation:

```bash
driftbox history list
driftbox history list --json
```

Display a snapshot exactly as stored or compare it with the current system:

```bash
driftbox history show SNAPSHOT
driftbox history diff SNAPSHOT
```

Use `latest` instead of `SNAPSHOT` to select the newest saved report. History
diff uses the same normalization as `driftbox diff`: exit status `0` means no
drift, `1` means drift was detected, and `2` means the snapshot was missing,
corrupt, unreadable, or invalid. Other history errors also return `2`.

Snapshots are written atomically outside the repository in these per-user
locations:

- Windows: `%LOCALAPPDATA%\Driftbox\history`
- macOS: `~/Library/Application Support/Driftbox/history`
- Linux and WSL: `${XDG_STATE_HOME:-~/.local/state}/driftbox/history`

Set `DRIFTBOX_STATE_DIR` to override the history directory for testing or
advanced use. Stored reports can contain hostnames, network addresses, process
details, and other sensitive local information. Protect the history directory
and review snapshots before sharing them.

## compatibility

| Environment | Status |
|---|---|
| Linux | Verified through automated testing |
| Windows Terminal / PowerShell | Verified locally and through automated testing |
| Windows Terminal / WSL 2 | Verified locally with Kali Linux |
| macOS | Verified through automated testing |

Driftbox automatically detects the operating environment and exposes information appropriate to that system.

## planned capabilities

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
