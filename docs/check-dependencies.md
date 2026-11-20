# Check dependencies and audit reports

Dependency checking is opt-in. Existing benchmark and check files remain valid
without modification, and the default execution path is unchanged.

Enable dependency-aware execution with:

```bash
kube-bench --enable-dependencies
```

`--check-dependencies` is an alias. A global per-check timeout can be set with
`--check-timeout 30s`; timed out checks are reported as `NOT_EXECUTED`.

## Declaring dependencies

Dependencies are declared on the check itself. Only a `PASS` prerequisite
satisfies a dependent check.

```yaml
- id: 1.2.1
  text: Check that depends on a running API server
  depends_on:
    - 1.1.1
  audit: ...
```

Both `depends_on` and `requires` are accepted. A scalar dependency is also
accepted:

```yaml
- id: 1.2.2
  requires: 1.1.1
```

Optional check metadata:

```yaml
- id: 1.2.3
  version: cis-1.24
  timeout: 15s
  applicable: false
  depends_on: [1.1.1]
```

`applicable: false` produces `NOT_APPLICABLE`. `enabled: false` produces
`NOT_EXECUTED` with reason `configuration_disallowed`.

## States and summary

Dependency-aware reports distinguish these result states:

- `PASS`: the check executed and met its expected result.
- `FAIL`: the check executed and did not meet its expected result.
- `SKIP`: explicitly skipped by the check type, group, or command line.
- `NOT_APPLICABLE`: the check does not apply to the scanned target.
- `NOT_EXECUTED`: the check was not run because configuration or a prerequisite
  prevented execution.

`NOT_EXECUTED` includes a reason category:

- `prerequisite_failed`: a dependency executed but did not pass.
- `dependency_missing`: a dependency was not selected or was not executed.
- `configuration_disallowed`: configuration disabled the check.
- `timeout`: the audit exceeded its timeout.

A missing `audit_config` file is reported as `SKIP` with reason
`configuration_unavailable` in dependency mode, rather than being allowed to
pass through another audit output.

Reports include complete counts for each result state. A check that has
different results on different nodes is retained in the `Distributions` section
with per-state and per-node counts; no majority result is selected.

## Load-time validation

Before checks run, kube-bench builds the dependency graph and rejects:

- Missing dependency IDs, naming the check and the missing dependency.
- Dependency cycles, printing the complete cycle such as
  `A -> B -> C -> A`.

## Audit trail

With dependency checking enabled, every state transition is recorded in
`AuditTrail` on each controls section. Each record includes the check ID, source
and destination state, condition, reason category, and any blocking dependency.
Records can be queried by check ID with `Controls.AuditByCheckID(id)`.

This distinguishes a check that passed directly from one that was previously
blocked as `NOT_EXECUTED` and later became `PASS` after its dependencies were
satisfied.

## Version metadata

Each report header includes the selected baseline version and the check version.
Per-check `version` metadata is compared with the baseline. A mismatch marks
the check and report as not cross-version comparable.

Compare two JSON reports with:

```bash
kube-bench compare --before before.json --after after.json
kube-bench compare --before before.json --after after.json --json
```

When baseline or check versions differ, the comparison reports
`NOT_COMPARABLE` and prints `不可跨版本比对` instead of a normal summary.
Otherwise, every changed check is listed with an explanation.
