# driftbox

[![Cross-platform test](https://github.com/bitdrifted/driftbox/actions/workflows/cross-platform-test.yml/badge.svg)](https://github.com/bitdrifted/driftbox/actions/workflows/cross-platform-test.yml)

> inspect the system. reduce uncertainty. trust less.

**Driftbox** is a cross-platform terminal toolkit for system inspection, security checks, and resilient operations.

Built for Linux, Windows, macOS, and Windows Subsystem for Linux (WSL).

## status

`v0.1.0 — early development`

System inspection, network inspection, listening-port inspection, portable JSON reports, persistent report history, report drift detection, file-integrity verification, unified findings, security posture checks, persistent configuration, configured scanning, safe scan scheduling, automated tests, and cross-platform validation are operational.

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
| `driftbox analyze [SNAPSHOT]` | Combine snapshot drift with current security posture |
| `driftbox analyze [SNAPSHOT] --json` | Produce versioned unified findings as JSON |
| `driftbox history capture` | Save the current report in local history |
| `driftbox history list [--json]` | List saved report snapshots newest first |
| `driftbox history show SNAPSHOT` | Display a stored report snapshot |
| `driftbox history diff SNAPSHOT` | Compare current state with a stored snapshot |
| `driftbox config show [--json]` | Display persistent per-user settings |
| `driftbox config set KEY VALUE` | Update one validated setting |
| `driftbox config reset` | Restore default settings |
| `driftbox scan [--json]` | Analyze, verify configured targets, and capture a report |
| `driftbox schedule install --daily HH:MM [--dry-run]` | Install or preview a daily per-user scan |
| `driftbox schedule status` | Show scheduled-scan state |
| `driftbox schedule remove` | Remove Driftbox's scheduled scan |

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

Verification classifies added, missing, or modified monitored files as
`suspicious` and an intact manifest as `normal`. It exits with status `0` when
integrity is intact, `1` when changes are detected, and `2` for invalid
manifests, unsupported versions, missing or unreadable paths, and permission
errors. Driftbox fails instead of writing or checking a partial manifest if any
regular file cannot be read.

## security posture checks

Analyze existing firewall and listening-port inspection data:

```bash
driftbox check
```

Produce a versioned JSON result for automation:

```bash
driftbox check --json
```

Driftbox reports a `critical` finding when the firewall is confirmed disabled
and a `suspicious` finding when firewall status is unknown. Unknown status is
never treated as secure. Services listening on all interfaces or bound to a
public address are `suspicious`; local-only, link-local, and private-network
bindings do not produce findings solely because of their scope.

A broad or public binding does not by itself prove that a service is accessible
from the internet. Firewall policy, routing, and NAT can all affect reachability.
The command exits with status `0` when only `normal` findings exist, `1` when a
`suspicious` or `critical` finding exists, and `2` after an unexpected inspection
or output error.

## unified findings and analysis

Analyze the current report against the latest history snapshot while also
evaluating current security posture:

```bash
driftbox analyze
```

Select a specific snapshot or request versioned JSON output:

```bash
driftbox analyze SNAPSHOT
driftbox analyze latest --json
```

Every finding contains a stable ID, one of the exact classifications `normal`,
`suspicious`, or `critical`, a short title, a plain-language explanation,
supporting evidence, and a practical recommended action. Results are sorted
deterministically for reliable automation.

An enabled-to-disabled firewall change and a currently disabled firewall are
`critical`. Unknown firewall state, newly detected listeners, and public or
all-interface listeners are `suspicious`. Removed listeners and firewall
improvements are `normal`, with guidance to confirm that the change was expected.
When no actionable drift or posture problem exists, the result is `normal`.

A listener's bind address alone never proves internet accessibility. Firewall
policy, routing, and NAT may change actual reachability. Analysis is entirely
local and read-only. It exits with status `0` for only normal findings, `1` when
any suspicious or critical finding exists, and `2` for invalid input, malformed
data, unreadable files, or operational errors.

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

## persistent configuration

Display the current configuration in readable or machine-readable form:

```bash
driftbox config show
driftbox config show --json
```

Update one setting without changing the others, or restore all defaults:

```bash
driftbox config set history_retention_days 14
driftbox config set scan_output json
driftbox config reset
```

The schema-versioned JSON configuration starts with these settings:

| Setting | Default | Purpose |
|---|---:|---|
| `history_retention_days` | `30` | Retention preference for future history management; snapshots are not automatically deleted yet |
| `default_baseline` | `latest` | Use the newest valid history snapshot as the scan baseline |
| `integrity_targets` | `[]` | JSON array of `path` and `manifest` pairs verified during a scan |
| `scan_output` | `human` | Default `human` or `json` scan presentation |

For example, PowerShell or a POSIX shell can configure an integrity target with:

```bash
driftbox config set integrity_targets '[{"path":"important","manifest":"important-manifest.json"}]'
```

Every key and value is validated, unknown keys are rejected, and updates are
written atomically. Driftbox configuration contains behavior and path settings,
not credentials or secrets. The default file locations are:

- Windows: `%LOCALAPPDATA%\Driftbox\config.json`
- macOS: `~/Library/Application Support/Driftbox/config.json`
- Linux and WSL: `${XDG_CONFIG_HOME:-~/.config}/driftbox/config.json`

Set `DRIFTBOX_CONFIG_DIR` to an alternate configuration directory for an
isolated lab or test. This override is separate from `DRIFTBOX_STATE_DIR`, which
controls report-history storage.

## configured scans

Run the complete configured workflow without interactive prompts:

```bash
driftbox scan
driftbox scan --json
```

A scan loads configuration, collects the current report, compares it with the
previous history snapshot, evaluates current security posture, and verifies all
configured integrity targets. Only after those steps succeed does it atomically
append the current report to history. It never compares a new snapshot with
itself or replaces the prior snapshot.

If history is empty, the first successful scan captures the initial baseline and
reports a `normal` baseline-initialization finding. Later unchanged scans return
status `0`. Status `1` means one or more `suspicious` or `critical` findings were
reported. Status `2` means configuration, input, storage, or another operational
step failed. JSON scan output is schema-versioned and findings remain
deterministically ordered.

## scheduled scans

Preview a daily schedule before installing it:

```bash
driftbox schedule install --daily 02:30 --dry-run
```

Install, inspect, or remove the schedule:

```bash
driftbox schedule install --daily 02:30
driftbox schedule status
driftbox schedule remove
```

Windows uses a per-user Task Scheduler task named `Driftbox Daily Scan`. Linux
and macOS use the current user's crontab with a Driftbox-owned marker. The job
runs `driftbox scan` headlessly. Times use local 24-hour `HH:MM` format.

`--dry-run` prints the escaped scheduler action and makes no scheduler change.
Status distinguishes `installed`, `absent`, `unsupported`, and `malformed`.
Driftbox verifies its stable task name, exact executable, scan argument, or cron
marker before replacement or removal; unrelated tasks and crontab entries are
preserved. Malformed, unsupported, invalid, or operational scheduler errors
return status `2`. Installation and removal do not require administrator access
where the platform permits per-user scheduling.

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
