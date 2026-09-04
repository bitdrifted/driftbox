# driftbox

[![Cross-platform test](https://github.com/bitdrifted/driftbox/actions/workflows/cross-platform-test.yml/badge.svg)](https://github.com/bitdrifted/driftbox/actions/workflows/cross-platform-test.yml)

> inspect the system. reduce uncertainty. trust less.

**Driftbox** is a cross-platform terminal toolkit for system inspection, security checks, and resilient operations.

Built for Linux, Windows, macOS, and Windows Subsystem for Linux (WSL).

## status

`v0.1.0 — early development`

System inspection, interpreted authorized private-network discovery, authorized
single-device service inventory, evidence-driven vulnerability correlation,
safe next-move guidance, listening-port
inspection, portable JSON reports, persistent report history, report drift detection,
file-integrity verification, unified findings, evidence-driven posture triage, persistent
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
| `driftbox services TARGET --confirm-authorization` | Inventory common TCP services on one authorized private IPv4 device |
| `driftbox services TARGET --confirm-authorization --json` | Produce schema-versioned service evidence without terminal truncation |
| `driftbox vulnerabilities SERVICE_REPORT.json` | Correlate sufficiently specific service evidence with NVD and CISA KEV |
| `driftbox vulnerabilities SERVICE_REPORT.json --json` | Produce complete, schema-versioned vulnerability-candidate evidence |
| `driftbox vulnerabilities SERVICE_REPORT.json --offline` | Use only locally cached authoritative-source evidence |
| `driftbox vulnerabilities SERVICE_REPORT.json --refresh` | Bypass fresh-cache reuse and retrieve current source data |
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

Discovery itself does not perform port scanning, service detection, CVE lookup,
Nmap integration, exploitation, credential attacks, stealth, persistence,
evasion, or attack-tool execution. An operator can review a discovered numeric
address and separately authorize the single-device service inventory described
below. There is no automatic handoff or target expansion. Discovery tests mock
interface, probe, routing-table, neighbor-cache, command, and timeout behavior;
automated validation does not probe or scan a real network.

## authorized single-device service inventory

Service inventory is an explicit active scan of exactly one device. Use it only
after confirming that you own the target or have permission to scan it. Private
addressing is a scope restriction, not proof of authorization, so Driftbox
refuses every service scan unless `--confirm-authorization` is present.

```bash
driftbox services 192.168.1.20 --confirm-authorization
driftbox services 192.168.1.20 --confirm-authorization --json
driftbox services 192.168.1.20 --confirm-authorization --top-ports 1000
```

`TARGET` must be exactly one canonical numeric IPv4 address in RFC 1918 private,
IPv4 loopback, or IPv4 link-local space. CIDRs, ranges, wildcards, hostnames,
URLs, IPv6, alternate numeric spellings, and public or other special-use targets
are refused before Nmap detection. Driftbox never resolves, follows, or adds a
target based on Nmap output, redirects, DNS, or discovered names.

The default is Nmap's 100 most commonly used TCP ports. `--top-ports NUMBER`
accepts only canonical integers from 1 through 1,000. The fixed profile is:

```text
nmap -n -Pn --disable-arp-ping --unprivileged -sT --top-ports NUMBER -sV --version-light --reason --open --host-timeout 60s -oX - TARGET
```

This is an `ACTIVE AUTHORIZED SCAN`: a TCP connect scan, no DNS resolution, no
host-discovery dependency, no ARP discovery, an explicit unprivileged mode,
bounded common-port scope, lightweight service/version detection, reasons for
open states, a 60-second Nmap host timeout, a 75-second Driftbox process timeout,
and XML on standard output for bounded parsing. The single validated target is
the final argument. Driftbox uses a fixed argument array with `shell=False`.

The profile contains no NSE or default scripts, `--script vuln`, OS detection,
UDP or SYN/raw-packet scanning, aggressive mode, decoys, spoofing,
fragmentation, evasion, credential attacks, exploitation, persistence, or extra
targets. These controls are not exposed as user-supplied options.
If XML nevertheless contains a script-result element, Driftbox rejects that
evidence as outside the permitted profile.

Driftbox dynamically finds `nmap` on the operator's `PATH` and asks that
executable for its version only after authorization, target, and port-scope
validation. Install Nmap separately and ensure `nmap` is available on `PATH`.
Driftbox does not bundle, download, update, or redistribute Nmap or Npcap. This
repository remains MIT-licensed; Nmap is governed separately by the
[Nmap Public Source License](https://nmap.org/npsl/), and Npcap has its own
[licensing terms](https://npcap.com/oem/). Operators and redistributors are
responsible for the upstream terms that apply to their installation and use.

An illustrative privacy-safe terminal result is:

```text
driftbox :: authorized single-device service inventory

SERVICE INVENTORY SUMMARY
-------------------------
Target: 192.168.1.20
Authorization confirmation: yes (--confirm-authorization). Private addressing does not prove authorization.
Nmap version: 7.99
Scan profile: active authorized TCP connect scan; no DNS; no host discovery; lightweight service version detection.
TCP ports examined: 100 (common-port scope)
Completion status: completed
Open ports: 3
Evidence incomplete: no

WHAT THIS MEANS
---------------
- An open port means a service accepted a connection during this scan.
- Nmap service and version labels are observations, not guaranteed identity.
- An open service is not automatically vulnerable or malicious.

SERVICE EVIDENCE
----------------
tcp/135
  State/reason: open / syn-ack
  Service name: msrpc
  Common association: Commonly associated with Microsoft Windows RPC.
  Product: unavailable
  Version: unavailable
  Extra information: unavailable
  Tunnel/TLS: unavailable
  CPE: unavailable
  Detection method/confidence: table / 3
tcp/139
  State/reason: open / syn-ack
  Service name: netbios-ssn
  Common association: Commonly associated with legacy Windows file/printer networking.
  Product: unavailable
  Version: unavailable
  Extra information: unavailable
  Tunnel/TLS: unavailable
  CPE: unavailable
  Detection method/confidence: table / 3
tcp/445
  State/reason: open / syn-ack
  Service name: microsoft-ds
  Common association: Commonly associated with SMB and Windows file sharing.
  Product: unavailable
  Version: unavailable
  Extra information: unavailable
  Tunnel/TLS: unavailable
  CPE: unavailable
  Detection method/confidence: table / 3

BOTTOM LINE
-----------
Nmap reported 3 open TCP service endpoints. The recognized service labels are commonly seen on Windows systems. Nothing in this evidence proves a vulnerability. Verify that SMB/NetBIOS service exposure is intentional and restricted by firewall rules to only the networks that need it. This scan does not establish internet reachability or reachability from another device.

RECOMMENDED NEXT STEPS
----------------------
Recommendations are suggestions only; Driftbox never executes them automatically.
1. [LOCAL READ-ONLY] driftbox ports
   Correlate local listening ports with owning process IDs and names on the computer running Driftbox.
   Scope: Inspects only this local machine and correlates directly only when it is the scanned target.
2. [LOCAL READ-ONLY] driftbox firewall
   Review local firewall status and available profile protection on the computer running Driftbox.
   Scope: Inspects only this local machine and does not prove policy on a different scanned target.
3. [LOCAL READ-ONLY] driftbox check
   Evaluate local firewall and listener posture with Driftbox's existing deterministic checks.
   Scope: Inspects only this local machine and does not evaluate a different scanned target.
4. [ACTIVE AUTHORIZED SCAN] driftbox services 192.168.1.20 --confirm-authorization --top-ports 100 --json
   Optionally collect a new bounded JSON service-inventory record for the exact same device.
   Scope: This starts another active scan and must never run automatically; use it only after fresh authorization.
   Authorization: Explicit authorization is required again immediately before scanning 192.168.1.20; private addressing does not establish authorization.

LIMITATIONS
-----------
- Only the selected common TCP ports were examined.
- Firewalls, filtering, and network conditions can affect observations.
- Vulnerability correlation is not performed by this service-inventory command.
```

An open port is evidence that a service accepted a connection during this scan,
not a vulnerability finding, maliciousness claim, or guarantee of service
identity. No open-port result is also inconclusive: only the selected common TCP
ports were examined, and firewalls, filtering, timeouts, and network conditions
can affect observations. This scan does not establish internet reachability or
reachability from another device.

Service-inventory JSON uses top-level schema version 1 and an independently
versioned interpretation schema version 1. It preserves the exact target and
authorization state; detected Nmap and XML versions; canonical bounded profile;
execution status and timestamps; TCP port scope; parsed host state; ordered open
services; raw bounded Nmap service attributes; CPE, method, and confidence;
recognized common-service context; a plain-English bottom line;
incomplete-evidence reasons; limitations; and structured recommendations.
Output keys and services are deterministic. The absolute executable path is
redacted, uncontrolled raw XML is never included, and output is not saved
automatically.

Terminal fields are stripped of control and Unicode formatting characters and
truncated for display. JSON retains the more complete parsed evidence within a
2,048-character per-field and 1,000,000-byte XML-input boundary. Even bounded
inventory can contain sensitive private addresses, products, versions, CPEs,
and configuration clues; protect and review JSON before storing or sharing it.

Service inventory has stable exit codes:

| Code | Meaning |
|---:|---|
| `0` | Collection completed or returned explicitly partial evidence, including no reported open ports |
| `2` | Authorization was not confirmed, or the target/port scope was invalid or unsafe; no scan ran |
| `4` | Nmap was unavailable, timed out, exited nonzero, returned malformed/oversized evidence, or output failed |

JSON errors include a stable status and `scan_started` boolean. Partial evidence
is successful but explicitly marked; an open port is never an error or automatic
vulnerability finding. The service-inventory command itself does not perform
vulnerability correlation. Its saved JSON can be reviewed and passed explicitly
to the separate vulnerability-intelligence command below. Service inventory
generates no exploit commands.

## evidence-driven vulnerability intelligence

Analyze a previously created service-inventory report without scanning the
device again:

```bash
driftbox vulnerabilities service-report.json
driftbox vulnerabilities service-report.json --json
driftbox vulnerabilities service-report.json --offline
driftbox vulnerabilities service-report.json --refresh
```

In PowerShell, create the input from a separately authorized, privacy-safe
single-device inventory. Review the target and authorization before running the
active inventory:

```powershell
driftbox services 192.168.50.20 --confirm-authorization --json > service-report.json
driftbox vulnerabilities service-report.json
```

Windows PowerShell may write redirected native output as BOM-marked UTF-16.
Vulnerability analysis deterministically accepts UTF-8, UTF-8 with a byte-order
marker, UTF-16 little-endian with a marker, and UTF-16 big-endian with a marker.
An unmarked file must be strict UTF-8. The input file and every collection,
string, CPE, service, query, source response, and candidate list are bounded.
The complete service transport schema and supported version are validated before
any network request. Malformed, oversized, unsupported, ambiguous, or unsafe
input returns a stable error without contacting a source.

This command is correlation, not scanning. It never launches Nmap, probes the
saved target, expands a target, resolves names, executes a recommendation,
patches software, or invokes a shell. The private target address, Nmap command,
raw report, process details, and unrelated evidence are never sent to a public
source. Only an eligible canonical CPE 2.3 name is sent to NVD. CISA receives no
device evidence.

### evidence eligibility

A service is eligible only when all of these deterministic conditions hold:

- Nmap recorded the service with detection method `probed` and its maximum
  confidence value, `10`.
- Nmap supplied an application (`a`) or operating-system (`o`) CPE 2.2 URI that
  Driftbox can convert unambiguously to canonical CPE 2.3.
- The CPE contains exact, non-wildcard vendor, product, and version components.
- The CPE contains no unsupported edition/language ambiguity, unsafe escape,
  control character, or unsupported part.

Product names alone never trigger a keyword search. Missing CPEs, wildcard or
missing versions, table-based labels, low confidence, and unsupported CPE forms
remain in the result with an explanation and cause no lookup for that service.
Identical canonical CPEs are queried once. The per-invocation unique-query limit
is deliberately small; evidence beyond it is marked partial rather than silently
dropped.

For example, high-confidence probed evidence containing
`cpe:/a:apache:http_server:2.4.49` is specific enough to query NVD as
`cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*`. Any returned CVE is still a
candidate requiring local confirmation. By contrast, observed tcp/135 `msrpc`,
tcp/139 `netbios-ssn`, and tcp/445 `microsoft-ds` labels, or the incomplete CPE
`cpe:/o:microsoft:windows`, support only this bottom line:

- common Windows-related services were observed;
- no exact affected product version was established;
- reliable CVE correlation was therefore not performed;
- no vulnerability or safety conclusion can be drawn; and
- the next step is better version or asset-owner evidence, not guessing.

Ordinary insufficient evidence is a successful, explicit result, not an
operational failure.

### authoritative sources, rate limits, and cache

Driftbox contacts only these fixed official HTTPS resources:

- [NVD CVE API 2.0](https://services.nvd.nist.gov/rest/json/cves/2.0), using the
  `cpeName` parameter for each eligible canonical CPE;
- [NVD human-readable CVE detail](https://nvd.nist.gov/vuln/detail/CVE-ID), with
  the validated CVE ID substituted into the fixed detail path;
- [CISA KEV JSON](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json);
  and
- [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).

Requests use certificate-verified HTTPS, fixed hosts and paths, safe URL
encoding, bounded responses, finite retries, conservative timeouts, and strict
redirect validation. Redirects outside the expected official HTTPS host/path are
refused. HTTP 403, 404, 429, 5xx, `Retry-After`, TLS failures, timeouts,
pagination, malformed JSON, and oversized/decompression responses are handled
without indefinite retries. Driftbox spaces unauthenticated NVD requests by at
least six seconds and permits no more than five in a rolling 30-second window.
With an NVD API key it still spaces requests conservatively and permits no more
than 50 in the rolling window.

An optional NVD key is read only from `DRIFTBOX_NVD_API_KEY`. It is sent only in
the `apiKey` request header. There is intentionally no API-key command-line
argument. For one PowerShell session:

```powershell
$env:DRIFTBOX_NVD_API_KEY = "your-key-from-NVD"
driftbox vulnerabilities service-report.json --refresh
Remove-Item Env:DRIFTBOX_NVD_API_KEY
```

The key is never placed in a URL, cache key/value, report, fixture, exception,
log, or terminal output. Avoid saving credentials in shell history or project
files.

Successful source data is cached for 24 hours in a schema-versioned per-user
vulnerability cache with atomic writes:

- Windows: `%LOCALAPPDATA%\Driftbox\vulnerability-cache`
- macOS: `~/Library/Application Support/Driftbox/vulnerability-cache`
- Linux and WSL: `${XDG_STATE_HOME:-~/.local/state}/driftbox/vulnerability-cache`
- override: `DRIFTBOX_STATE_DIR/vulnerability-cache`

Cache keys depend only on source identity and normalized CPE, never the target
or API key. Records identify the source, retrieval time, available upstream
version/timestamp, and retrieval state. Incompatible or malformed entries are
not trusted. Normal mode reuses fresh entries; `--refresh` bypasses fresh reuse
and requests current data. `--offline` makes zero network requests and uses only
valid cached evidence. Valid stale fallback is labeled `stale`, source failures
and partial availability remain visible, and `--offline --refresh` is refused as
conflicting.

### candidate meaning and output

Vulnerability JSON uses its own schema version. It preserves the validated local
service evidence, canonical CPE and eligibility reason, deterministic lookup
plan, candidate status, NVD status and English description, timestamps, best
supported CVSS version/score/vector/severity, CWE IDs, KEV fields when present,
retrieval/cache state, exact authoritative provenance, uncertainty,
limitations, and structured next steps. A CVE associated with multiple eligible
CPE queries appears once, with every distinct CPE/service correlation retained
in deterministic supporting evidence. Candidate limits count unique CVEs, not
correlation occurrences. `candidate_summary` reports globally deduplicated
observed, included, and omitted unique-CVE counts across eligible queries;
repeated omitted CVEs count once, and their identifiers are not retained or
exposed. Conflicting NVD metadata variants for one CVE are
preserved, make the candidate and report partial, and require authoritative
review; the highest reported severity and score are used only for deterministic
display and ordering. Candidates are ordered with KEV-listed items first, then
by severity/score and CVE ID. Human output independently bounds its preview and
lists each CVE once; `--json` retains the complete bounded evidence.

An NVD result means NVD associated a CVE candidate with the exact CPE sent. It
does not prove the saved device is affected, vulnerable, exploitable,
compromised, internet reachable, or unpatched. A zero-candidate response does
not prove the product is patched or safe.

A CISA KEV match means CISA has evidence that the vulnerability has been
exploited in the wild. It is urgent prioritization evidence, but it does not
prove that this specific device is affected or compromised. Absence from a
successfully retrieved KEV catalog means only that the candidate was not listed
in that catalog at retrieval time; it does not prove the vulnerability has never
been exploited or that the device is safe. An unavailable KEV source is reported
as unknown, not absent.

Recommendations are structured suggestions and never execute. They are limited
to confirming the installed product/version with the asset owner, reviewing the
authoritative NVD detail, prioritizing validated vendor remediation (especially
for KEV matches), applying vendor-supported updates or mitigations through an
approved change process, repeating an already-authorized inventory after
remediation, and preserving JSON evidence for comparison. Driftbox provides no
exploit code, public-exploit or proof-of-concept links, Metasploit guidance, NSE
vulnerability scripts, credentials/brute force, persistence, evasion,
destructive validation, automatic scanning, or automatic patching.

Vulnerability intelligence has stable exit codes:

| Code | Meaning |
|---:|---|
| `0` | Analysis completed with no candidate CVEs, or insufficient service evidence was reported successfully |
| `1` | One or more candidate CVEs require human review |
| `2` | Input/schema/options were invalid, conflicting, unsupported, or unsafe; no source request was made for invalid input |
| `4` | No usable authoritative or cached evidence remained after a source, timeout, cache, parsing, or output failure |

Usable partial evidence is preserved and clearly labeled rather than converted
to an operational failure. All automated tests use injected HTTP clients,
clocks, sleepers, temporary state directories, and synthetic reports; they make
no live NVD/CISA requests and invoke no Nmap or discovery command.

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

## posture triage

User testing found that the earlier `driftbox check` treated every all-interface
binding as a separate suspicious finding. On an otherwise ordinary Windows
workstation, dual-stack counterparts and dynamic endpoints produced 49 repetitive
blocks instead of a useful decision aid. No real workstation hostname, address,
PID, process inventory, or other private evidence is retained in Driftbox.

Run the local inspection and human posture summary:

```bash
driftbox check
```

Preserve complete evidence as dedicated posture-triage schema version 2:

```bash
driftbox check --json
```

A **raw endpoint** is one collected listener record. A **presentation group** is
a deterministic explanation aid that retains every member; it does not assert
that two records are literally one socket. Driftbox can group compatible
`0.0.0.0` and `::` records when protocol, port, and normalized process observation
match. PID is preserved as evidence but excluded from stable grouping identity.
It never merges wildcard and specific-address bindings.

On confirmed Windows evidence only, compatible wildcard TCP observations in the
49152-65535 dynamic RPC range can form one Windows RPC-range presentation group.
Repeated high-numbered wildcard UDP observations for one normalized process can
also be grouped. These rules retain every address, port, process label, and PID.
They do not prove that every dynamic port is RPC, that grouped records are one
socket, or that an observed process name is trustworthy. Windows-specific grouping
is not applied to Linux, macOS, or unknown platforms.

Common port context is deliberately cautious: port 123 is often associated with
time synchronization; 135 and compatible Windows dynamic endpoints with RPC;
137-139 and 445 with NetBIOS/SMB; 500 and 4500 with IPsec/IKE; 5353 with mDNS;
5355 with LLMNR; and 7680 on Windows with Delivery Optimization. A familiar port
or process label does not prove service identity, safety, or vulnerability, and
unknown broadly bound services remain visible. There is no safe-port allowlist.

Posture triage uses its own levels and validates their mapping into the existing
unified findings vocabulary:

| Posture level | Unified classification | Meaning |
| --- | --- | --- |
| `informational` | `normal` | Context worth understanding but not independently actionable; never a claim of safety |
| `review` | `suspicious` | Evidence warrants operator review |
| `urgent` | `critical` | A confirmed high-priority posture problem |

A confirmed disabled firewall is urgent. Unknown or mixed state requires review
because protection cannot be assumed. A public-address binding requires review
even when the firewall is enabled, but the binding does not prove internet
reachability. Sensitive or remote-administration-associated broad bindings can
receive review priority with the reason and uncertainty shown. A generic wildcard
listener with an enabled firewall is normally informational unless stronger
deterministic evidence elevates it. Enabled status never proves a listener is
blocked or safe; Driftbox does not infer inbound rules it did not collect, and it
reports the firewall condition once rather than multiplying it across listeners.

Human output leads with the bottom line and priority review, distinguishes raw
endpoint and presentation-group counts, shows at most 10 service groups, and says
when more are available. JSON is independently complete within collection bounds:
it includes firewall profiles, every sanitized raw endpoint, every group and
member, grouping reasons, triage and unified classifications, explanations,
uncertainty, both count families, terminal-bound metadata, deterministic
recommendations, limitations, and provenance. The privacy-safe synthetic Windows
regression retains 49 raw endpoints as 14 groups, with 6 review groups and no
urgent item; the reduction comes from grouping and triage, not discarded evidence.

For example, a synthetic `0.0.0.0:445`/`[::]:445` pair may be presented together
for review, while a specific documentation-only address such as `192.0.2.25`
remains separate. The group describes observed evidence only; firewall, routing,
NAT, reachability, service identity, vulnerability, compromise, and patch state
require evidence this command does not collect.

Recommendations are structured, local, read-only Driftbox commands such as
`driftbox firewall`, `driftbox ports`, `driftbox check --json`, and
`driftbox report`. Every command is parser-validated and is never executed
automatically. Posture triage adds no subprocess or network boundary and never
generates Nmap, discovery, remote scan, vulnerability lookup, configuration,
firewall-change, process-termination, patch, exploit, or attack-tool actions.

Exit status `0` means only informational triage was produced. Status `1` means at
least one review or urgent item exists. Status `2` means malformed evidence,
validation failure, collection failure, or output failure prevented a valid result.

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
`critical`. Unknown firewall state, newly detected listeners, public bindings,
and posture-triage review groups are `suspicious`. Informational posture context,
removed listeners, and firewall improvements map to `normal` without implying
safety. When no actionable drift or posture problem exists, the unified result is
`normal`.

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

- Operator-confirmed remediation tracking and before/after evidence comparison,
  without automatic patching or unapproved rescanning
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
