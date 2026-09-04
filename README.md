# driftbox

[![Cross-platform test](https://github.com/bitdrifted/driftbox/actions/workflows/cross-platform-test.yml/badge.svg)](https://github.com/bitdrifted/driftbox/actions/workflows/cross-platform-test.yml)

> inspect the system. reduce uncertainty. trust less.

**Driftbox** is a cross-platform terminal toolkit for system inspection, security checks, and resilient operations.

Built for Linux, Windows, macOS, and Windows Subsystem for Linux (WSL).

## status

`v0.1.0 — early development`

System inspection, interpreted authorized private-network discovery, safe next-move
guidance, listening-port inspection, portable JSON reports, persistent report history, report drift detection,
file-integrity verification, unified findings, security posture checks, persistent
configuration, configured scanning, safe scan scheduling, an experimental
synthetic training mission, automated tests, and cross-platform validation are
operational.

Driftbox's core product direction is operational security learning: real,
authorized host and network inspection, vulnerability discovery, tool guidance,
safe validation, remediation, and learning through operation. Synthetic
quiz-style training remains experimental rather than defining the product's
direction.

## current commands

| Command | Purpose |
|---|---|
| `driftbox info` | Display system and execution-environment information |
| `driftbox network` | Display local network information |
| `driftbox discover [CIDR]` | Discover evidence of hosts on one authorized private IPv4 network |
| `driftbox discover [CIDR] --json` | Produce a schema-versioned discovery result for later inventory |
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
| `driftbox mission list [--json]` | List synthetic training missions |
| `driftbox mission start first-watch` | Start or resume the first mission |
| `driftbox mission brief` | Review the active mission and evidence |
| `driftbox mission status` | Show hints, attempts, and best score |
| `driftbox mission hint` | Request the next progressive hint |
| `driftbox mission submit` | Submit decisions for scoring and coaching |
| `driftbox mission reset` | Reset only the active mission workspace |

## authorized private-network discovery

Use discovery only on a network you own or have explicit permission to inspect.
Authorization is the operator's responsibility. Driftbox accepts one canonical,
numeric IPv4 CIDR and only permits loopback (`127.0.0.0/8`), link-local
(`169.254.0.0/16`), and RFC 1918 private space (`10.0.0.0/8`,
`172.16.0.0/12`, and `192.168.0.0/16`). Public, mixed private/public, IPv6,
non-canonical, and hostname targets are rejected. Hostnames are not resolved,
which prevents a name from silently expanding discovery beyond the reviewed
numeric target.

Discover a specifically authorized network:

```bash
driftbox discover 192.168.50.0/29
```

If the CIDR is omitted, Driftbox inspects local interface configuration for
suitable private IPv4 candidates. Exactly one candidate is selected
automatically. When several candidates exist, Driftbox lists them and exits
without probing so the operator can make an explicit choice. When none is
available, discovery cannot proceed.

```bash
driftbox discover
driftbox discover 192.168.50.0/29 --timeout 0.5 --workers 8
driftbox discover 192.168.50.0/29 --json > discovery.json
```

User testing showed that raw discovery rows were technically useful but did not
give beginners enough plain-English interpretation or contextual command
options. Discovery now explains what the evidence does and does not prove, then
offers ranked next moves without running them. An illustrative human-readable
result is:

```text
driftbox :: authorized private-network discovery

DISCOVERY SUMMARY
-----------------
Network inspected: 192.168.1.0/29 (8 addresses; 6 host addresses; 5 remote probes)
Authorization: scan only networks you own or have explicit permission to inspect.
Method: bounded, unprivileged ICMP echo plus read-only local neighbor/cache and routing-table evidence.
Parameters: timeout 0.5 seconds; workers 4
Collection status: partial
Positive host evidence: 4 addresses; 1 reply.
This computer's address: 192.168.1.1
Devices that responded during the scan: 192.168.1.2
Devices supported only by neighbor/cache evidence: 192.168.1.3
Probes that received no reply: 2.
No-reply/cache overlap: 1 of the 2 addresses without a reply also have neighbor/cache evidence; these categories overlap and should not be added together.
Confirmed default gateway: 192.168.1.4
Collection errors or incomplete evidence: reachability=partial (some probes failed); probe issues at 192.168.1.5, 192.168.1.6.

WHAT THIS MEANS
---------------
- A response proves only that the device answered at scan time.
- Cache evidence means this computer has seen the device, not necessarily that it is currently online.
- Silence does not prove an address is unused or offline.
- The discovered device count is a minimum supported by positive evidence.
- Unknown devices are not automatically suspicious or malicious.

RECOMMENDED NEXT STEPS
----------------------
1. driftbox ports
   Purpose: Inspect listening TCP and locally bound UDP ports on this machine.
   Reason: This adds local exposure context without contacting discovered hosts.
   Target: this local machine
   Risk/activity: LOCAL READ-ONLY
   Authorization: Permission to inspect this local machine; no additional network authorization is required.
   Expected result: A local list of accessible listening ports and their bind scope.
   Available now: yes. Runs locally and does not probe discovered addresses.
2. driftbox firewall
   Purpose: Inspect local firewall status and available profile details.
   Reason: Firewall policy is separate local evidence that discovery cannot establish.
   Target: this local machine
   Risk/activity: LOCAL READ-ONLY
   Authorization: Permission to inspect this local machine; no additional network authorization is required.
   Expected result: Read-only firewall status; unavailable or unknown is reported rather than guessed.
   Available now: yes. Runs locally and does not change firewall configuration.
3. driftbox report
   Purpose: Create a machine-readable local system report.
   Reason: A local report provides a separate baseline without expanding discovery.
   Target: this local machine
   Risk/activity: LOCAL READ-ONLY
   Authorization: Permission to inspect this local machine; no additional network authorization is required.
   Expected result: JSON containing local system, network, firewall, and listener observations.
   Available now: yes. Review the report before sharing it.
4. driftbox discover 192.168.1.0/29 --json
   Purpose: Display complete structured evidence from a new run of the same bounded collection.
   Reason: The human view is summarized; JSON displays every per-address outcome in the same reviewed scope.
   Target: 192.168.1.0/29
   Risk/activity: ACTIVE AUTHORIZED SCAN
   Authorization: Explicit authorization to inspect 192.168.1.0/29.
   Expected result: Schema-versioned JSON is written to standard output; Driftbox does not save it automatically.
   Available now: yes. Run only after reconfirming authorization for this exact CIDR.

DETAILED EVIDENCE
-----------------
Terminal previews show at most 10 addresses or host rows. To display complete structured evidence from a newly authorized collection, use: driftbox discover 192.168.1.0/29 --json. JSON is written to standard output and is not saved automatically.
ADDRESS         CLASSIFICATION              EVIDENCE
--------------- --------------------------- --------------------------------
192.168.1.1     local machine               local interface address (source: local interface data)
192.168.1.2     confirmed responsive        ICMP echo reply (source: system ping)
192.168.1.3     locally known neighbor      neighbor/cache entry (source: ARP cache)
192.168.1.4     routing evidence only       configured default-gateway route (source: local routing table, interface: eth0)

4 host records: 1 local machine, 1 responsive, 1 cache-only, 1 routing-evidence-only.
Confirmed gateway roles: 1 (192.168.1.4); role counts may overlap host classifications.
Probe outcomes (aggregated): 5 attempted; 1 reply; 1 without an observed reply; 1 timed out; 1 unavailable; 1 error.
Neighbor/cache evidence: available.
Hostnames: not collected (unavailable metadata; reverse DNS is disabled).
Addresses that did not respond (terminal preview): 192.168.1.3, 192.168.1.4
```

Human-readable discovery output is intentionally bounded: each address list
and the host-evidence table shows at most 10 items, followed by `and N more`
when additional evidence exists. The summary always states the silent-address
count, while detailed evidence aggregates probe outcomes. To collect complete
schema-versioned JSON for an explicitly authorized CIDR, use
`driftbox discover CIDR --json`; the command displays every per-address outcome
on standard output but does not save it automatically. This change follows a
real, explicitly authorized user test in which a `/24` discovery completed
successfully but the old default output exceeded the terminal capture buffer by
enumerating silent addresses.
The defect was found before PR #17 was merged; the human view is now bounded
while schema-v2 JSON remains complete.

Discovery uses short, unprivileged ICMP echo commands and reads the operating
system's local neighbor cache and routing table. Routing-table collection is
read-only and uses fixed commands behind the same testable adapter: `ip -4 route
show default` on Linux, `route print -4` on Windows, and `route -n get default`
on macOS. A host is labeled `gateway_router` only when a parsed default-route
record names its address inside the inspected CIDR. Ping responses, neighbor
records, address position, and common `.1` conventions never assign that role.
Human output reports mutually exclusive host-evidence classifications separately
from gateway roles. A confirmed gateway role can overlap a local, responsive, or
cache-based classification and therefore never adds another host record.

Discovery does not require administrator privileges or raw sockets. Results
distinguish the local machine, a confirmed responsive host, a cache-only host,
and a configured default-route next hop. A cache entry is historical local
evidence, not proof that a device is currently online. A silent target may block
ICMP, be asleep, or be absent; Driftbox never claims that silence proves a host
does not exist. The summary explicitly reports how many no-reply addresses also
have neighbor/cache evidence because those categories overlap and must not be
added together. Reverse DNS remains disabled, so hostnames cannot expand the
reviewed numeric scope or trigger external DNS traffic.

The Next Move Engine is deterministic and offline. It recommends only commands
implemented by the current CLI, validates every recommendation with the real
argument parser, and never inserts a hostname or unvalidated text into a command.
Each structured recommendation records its rank, exact command, purpose, reason,
exact target, risk/activity label, authorization requirement, expected result,
and current availability. The activity vocabulary is `PASSIVE`, `LOCAL
READ-ONLY`, `ACTIVE AUTHORIZED SCAN`, and `LAB-ONLY`; current recommendations use
only the applicable local-read-only and authorized-scan labels. Recommendations
are guidance, not authorization, and Driftbox never executes them automatically.

The conservative defaults are 16 workers and 0.75 seconds per probe. Driftbox
constrains `--workers` to 1 through 32 and `--timeout` to 0.1 through 2.0
seconds; values beyond those limits are safely clamped. Driftbox refuses targets
larger than 256 total addresses. Work is bounded and output is sorted by numeric
address, but operating-system scheduling means overall run time can still vary.

`--json` displays discovery schema version 2 on standard output and does not
persist it automatically. Version 2 deliberately adds ordered
`probe_outcomes`, `default_gateway`, `sources.routing_table`, route evidence and
the optional `confirmed_gateway` host status, plus the top-level
`interpretation` object. Existing fields retain their meanings. The nested
interpretation schema starts at version 1 and contains `discovery_summary`,
`what_this_means`, `recommendations`, and `detailed_evidence`. Consumers must
check both schema versions and tolerate additive fields. The interpretation's
additive `neighbor_cache_evidence_addresses` and `evidence_overlap` fields expose
the complete no-reply/cache relationship without changing either schema version.
Older schema-v1 discovery data can still be interpreted, but address-level
negative outcomes and gateway evidence are reported as not collected rather
than reconstructed.

`collection_status` keeps its established reachability/neighbor semantics so
existing exit codes do not change. A routing-table failure is instead explicit
under `default_gateway`, `sources.routing_table`, and the interpretation's
incomplete-evidence data. Each host retains its classification and supporting
evidence; consumers must not infer liveness from missing entries. Discovery data
contains private addresses, interface and route details, MAC addresses when the
operating system exposes them, and other local network evidence. Protect it and
review it before storing or sharing it.

Discovery has stable exit codes:

| Code | Meaning |
|---:|---|
| `0` | Discovery completed or collected partial evidence, including zero recorded hosts |
| `2` | The target or parameters were invalid, unsafe, or outside the allowed scope |
| `3` | Multiple suitable local networks require explicit selection; no probes ran |
| `4` | No suitable local network was found, or discovery could not operate |

This milestone does not perform port scanning, service detection, CVE lookup,
Nmap integration, exploitation, credential attacks, stealth, persistence,
evasion, or attack-tool execution. Tests mock interface, probe, routing-table,
neighbor-cache, command, and timeout behavior; automated validation does not
probe or scan a real network.

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

## experimental training: First Watch

The local training engine is experimental. Its first playable mission,
`first-watch`, places the learner at the fictional St. Meridian Medical Center
and demonstrates this complete loop:

```text
mission brief -> evidence investigation -> finding submission -> scoring -> coaching
```

List missions and start or resume First Watch:

```bash
driftbox mission list
driftbox mission list --json
driftbox mission start first-watch
```

Investigate the synthetic evidence and track progress:

```bash
driftbox mission brief
driftbox mission status
driftbox mission hint
```

Submit findings interactively, then reset only the mission when desired:

```bash
driftbox mission submit
driftbox mission reset
```

The submission flow displays numbered evidence, classification, response, and
priority menus when each answer is requested. Enter a menu number or the stable
textual ID; both forms work on PowerShell, Windows Terminal, macOS, Linux, and
WSL. Invalid entries are explained and re-prompted without discarding the
attempt. The priority menu repeats every selected evidence ID and description,
so learners do not need to memorize the brief.

Every learner-facing result carries a permanent training indicator. The mission
uses only fictional reports, hostnames, addresses, processes, files, and
organization data. It never inspects or changes the real firewall, listeners,
services, files, scheduler, Driftbox configuration, or report history. The
synthetic evidence is analyzed by Driftbox's existing report-diff, integrity,
posture, and unified findings engines.

Submission scoring separately measures identification, classification,
prioritization, and response decisions for a total of 0-100. Coaching is
deterministic and rule-based, not AI-generated. Priority tiers allow equally
defensible ordering: First Watch requires EV-001 first and EV-004 last, while
EV-002 and EV-003 receive full credit in either order. Scenario definitions can
also distinguish a preferred action from reasonable full-credit alternatives.
For normal EV-004, both `verify-expected` and `no-action` receive full credit;
coaching identifies `verify-expected` as the more cautious operational choice.
Score output states the points lost in each component and never asks learners
to revisit a fully accepted answer.

A disabled firewall is critical; a new all-interface listener and an integrity
change are suspicious. An
all-interface listener may be reachable from other networks, but its binding
alone does not prove internet accessibility because firewall policy, routing,
and NAT also affect reachability. Volatile background changes such as a process
ID change remain normal when the meaningful endpoint is unchanged.

Hints are progressive, tracked in the session, and apply a modest score penalty.
Attempts and the best score persist so a learner can leave and resume. Mission
commands return `0` after successful operations, including a completed
submission regardless of score, and `2` for malformed data, invalid input,
missing sessions, or operational errors.

Mission state is isolated from other Driftbox data in these locations:

- Windows: `%LOCALAPPDATA%\Driftbox\missions`
- macOS: `~/Library/Application Support/Driftbox/missions`
- Linux and WSL: `${XDG_STATE_HOME:-~/.local/state}/driftbox/missions`

Set `DRIFTBOX_MISSION_DIR` to an isolated mission directory for a lab, test, or
future cyber-range instance. See
[`docs/training-architecture.md`](docs/training-architecture.md) for the
prototype boundaries and future migration path.

## compatibility

| Environment | Status |
|---|---|
| Linux | Verified through automated testing |
| Windows Terminal / PowerShell | Verified locally and through automated testing |
| Windows Terminal / WSL 2 | Verified locally with Kali Linux |
| macOS | Verified through automated testing |

Driftbox automatically detects the operating environment and exposes information appropriate to that system.

## coming next

- Authorized service inventory and vulnerability-analysis guidance built on
  reviewed discovery evidence
- Optional report redaction

## repository boundary

`C:\Users\cjboo\driftbox-platform` is a frozen, read-only, separate private
platform repository. Public Driftbox development does not modify it or copy its
private code into this repository.

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
