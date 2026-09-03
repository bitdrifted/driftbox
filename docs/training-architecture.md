# Driftbox experimental training architecture

The local mission prototype proves a complete learning loop while keeping
Driftbox Core read-only and reusable:

```text
versioned mission definition
          |
          v
synthetic evidence adapter --> existing Driftbox analyzers
          |                              |
          v                              v
 isolated session <--- submission -> deterministic scoring
          |                              |
          +----------> terminal presentation and coaching
```

Every learner-facing terminal result is marked as a training environment, and
machine-readable discovery includes `training_environment: true` and
`data_source: synthetic`. Mission commands do not invoke live system collectors.

## Current boundaries

`mission_definitions.py` owns deterministic, schema-versioned scenario data. A
definition includes organization, environment, difficulty, learner role,
objectives, evidence, expected findings, scoring rules, and coaching. The first
definition uses only fictional St. Meridian Medical Center data. Private answer
and scoring fields are never returned by normal mission commands or written to
the learner-visible evidence packet.

`mission_engine.py` validates definitions and adapts their synthetic reports and
manifest-shaped records to the existing report-diff, security-posture,
file-integrity, and unified findings engines. This is the boundary that prevents
a second, training-only implementation of Driftbox security analysis.

`mission_storage.py` owns session persistence. Each mission gets an isolated
workspace containing only its learner-visible synthetic evidence and session
state. An active-session pointer selects the resumable mission. Writes are
atomic, reset removes only known files in the active mission workspace, and an
unexpected file causes reset to fail safely. `DRIFTBOX_MISSION_DIR` permits
isolated labs and future range instances without touching normal configuration
or report history.

`mission_scoring.py` owns deterministic 0-100 scoring across identification,
classification, prioritization, and response decisions. It also creates
rule-based coaching for correct choices, missed findings, false positives,
underclassification, overclassification, response choices, and prioritization.
Hints have a small capped penalty.

`mission_commands.py` owns terminal presentation and the interactive submission
flow. It depends on the engine, storage, and scoring interfaces rather than live
system inspection.

## Safety model

- Evidence is synthetic and definitions must explicitly identify it as such.
- No mission code executes exploits, malware, persistence, credential access,
  network traffic, remediation, or system configuration changes.
- No mission command calls firewall, port, process, file-tree, scheduler,
  configuration, or report-history collectors.
- The all-interface listener lesson discusses possible network reachability but
  never equates a binding with proven internet accessibility.
- Missing, corrupt, unsupported, or malformed mission/session data fails with a
  clear operational error instead of being silently replaced.

## Path to a persistent cyber range

The definition and scoring models can move to a range service without changing
Driftbox Core. A future platform can assign definitions to organizations and
learners, replace local session storage with an authenticated persistence layer,
and present the same public mission/evidence and submission interfaces through a
web client. Timeline events, advanced missions, expert teams, red-team/blue-team
roles, and mentor integrations can be added as versioned model fields.

Those future layers must preserve the current trust boundary: raw answer keys
remain server-side, evidence sources declare whether they are synthetic, and
Driftbox analysis stays separate from accounts, multiplayer coordination, cloud
hosting, and any AI mentor implementation.
