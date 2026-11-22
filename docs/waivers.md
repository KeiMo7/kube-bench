# Waivers

A waiver records that a specific result is understood and accepted, rather than
silently excluded. Use it to answer the audit question *"is this control not
applicable, or did we accept the risk, and who signed off?"* — without losing
the evidence that the check ran.

Waivers are declared in a YAML file and enabled with `--waivers <path>`.

```sh
kube-bench run --benchmark cis-1.11 --waivers ./waivers.yaml
```

## What a waiver does and does not do

- It **never skips a check**. Every check in the benchmark still executes and
  its raw output is preserved in the report.
- It changes only the **conclusion** of a result: a failing or warned check
  becomes `ACCEPTED RISK` or `NOT APPLICABLE`.
- It **never affects the exit code**. Only a check that is left in `FAIL` after
  waivers are applied drives the configured `--exit-code`.
- An **expired waiver stops applying**. The check falls back to its measured
  result (`FAIL`/`WARN`) and a diagnostic is printed to stderr.
- A waiver that **references a check that does not exist aborts the run**. This
  catches typos and stale entries after a benchmark upgrade.

## File format

```yaml
# Default benchmark for entries that do not set one.
benchmark: cis-1.11

waivers:
  - name: "api-server-file-perms"       # optional, defaults to <benchmark>/<target>
    node_type: master                   # master, node, controlplane, etcd, policies, managedservices
    check: "1.1.1"                      # one of check, group or node_type is required
    kind: accepted-risk                 # accepted-risk | not-applicable
    reason: "Managed control plane enforces equivalent permissions via admission policy"
    requester: "ops-team"
    approver: "security-review-board"
    starts: 2026-01-01                  # optional, accepts YYYY-MM-DD or RFC3339
    expires: 2030-12-31                 # optional; omit for a permanent waiver

  - name: "worker-node-files"
    node_type: node
    group: "4.1"                        # applies to every check in the group
    kind: not-applicable
    reason: "Worker nodes are managed by the cloud provider"
    requester: "ops-team"
    approver: "security-review-board"
    expires: 2027-06-30
```

| Field | Required | Notes |
| --- | --- | --- |
| `benchmark` | yes (top level or per entry) | Binds the waiver to a benchmark version. |
| `check` / `group` / `node_type` | at least one | `check` and `group` are mutually exclusive. |
| `kind` | yes | `accepted-risk` or `not-applicable`. |
| `reason` | yes | Shown in every output and in the audit trail. |
| `requester` | yes | Who asked for the waiver. |
| `approver` | yes | Who approved it. |
| `starts` | no | Inclusive start. Omitted means already active. |
| `expires` | no | Inclusive end date. Omitted means permanent. |

## Benchmark upgrades

Every waiver is bound to the **benchmark version** it was written for. When a
benchmark is upgraded and control numbers change, a waiver written for the old
version will not follow a reused identifier onto a different control. If the
new benchmark is selected, the waiver is reported as not selected rather than
applied:

```
[WARN] waiver: waiver "old-secure-port" targets benchmark cis-1.7, which was not selected; not applied
```

Re-review the waiver file when you upgrade the benchmark, and update its
`benchmark` and identifiers deliberately.

## Node types

A waiver with `node_type` only applies to that node type. If the same selector
exists on more than one node type (some benchmarks reuse identifiers, e.g. the
STIG profile) and the waiver does not set `node_type`, the run fails and asks
you to disambiguate. A waiver for one node type can never spread to another.

## Result states

| State | Meaning |
| --- | --- |
| `PASS` | The check ran and passed. |
| `FAIL` | The check ran and failed. Drives the exit code. |
| `WARN` | The check needs manual attention, or could not run. |
| `INFO` | Informational; e.g. a check marked `skip`. |
| `ACCEPTED RISK` | The measured result was a failure/warning and the risk was explicitly accepted. |
| `NOT APPLICABLE` | The control does not apply in this environment. |

An `accepted-risk` waiver has no effect on a check that passed: there is no risk
to accept, and the pass is reported normally.

## Output

The same result is described identically in all formats:

- **stdout** — the check line carries the new state, and a `== Waivers ==`
  section lists every applied waiver with its reason, requester, approver and
  expiry.
- **JSON** — each waived result gains a `waiver` object, and a top-level
  `Waivers` block summarises the file and any diagnostics.
- **JUnit** — waived results are marked `<skipped>` with a message containing
  the state, reason and expiry.

Waiver-free runs are unchanged: no `waiver` fields, no extra summary lines.

## Diagnostics

Expired, duplicate and conflicting waivers are reported on stderr as
`[WARN] waiver: ...` lines, and included in the JSON `Waivers` block when it is
present. Duplicate entries that match the same check resolve to the most
specific entry (ties by file order), so the conclusion does not depend on the
order checks are evaluated in.

A **contradiction at the same scope** — two waivers for the same check that use
different kinds, e.g. one `not-applicable` and one `accepted-risk` — cannot be
resolved on your behalf. The run fails with a message naming both entries:

```
waiver validation failed: 1 check(s) have waivers that contradict each other; resolve them in the waiver file
```

A narrower waiver refining a broader one (for example a group-level
`not-applicable` overridden by a single-check `accepted-risk`) is allowed: the
more specific entry wins and the choice is reported.
