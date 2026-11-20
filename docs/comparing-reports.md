# Comparing scan reports

When a cluster is upgraded, it is common to scan before and after the upgrade
and place the two reports side by side. A raw comparison of pass/fail counts
is misleading: a rule set upgrade can tighten a check, delete a check, add a
check, or change which node roles are scanned, and none of those is a change
in the machine configuration.

kube-bench can compare two JSON reports and attribute every difference using
only information recorded inside the reports themselves.

## What gets recorded in a report

Each scan report carries additive metadata (existing fields and output
formats are unchanged):

- `schema_version` — identifies the report structure, so consumers can
  recognise it without guessing.
- `rule_set` on every control section — the rule set version, benchmark
  product line, how the rule set was selected (`manual` for `--benchmark`,
  `platform`, or `version-mapping`), the requested/detected versions, and a
  fallback trail when version mapping fell back to an older rule set.
- `rule_fingerprint` on every check result — the triple that identifies the
  exact rule that produced the result:
  - `check_id` — the check identifier, e.g. `1.1.20`;
  - `condition_hash` / `condition` — a SHA-256 hash (and canonical rendering)
    of the decision condition: test items, compare operators and values,
    check type and the scored flag. Runtime results never participate in the
    hash;
  - `rule_set_version` — the rule set version the check belongs to.

## Running a comparison

Produce two JSON reports (the additive fields appear automatically), then:

```
kube-bench compare --older report-before.json --newer report-after.json
```

By default the result is machine-consumable JSON (`kube-bench-diff-v1`). Add
`--text` for a human-readable report, `-o file` to write to a file, and
`--max-entries N` to bound the number of emitted differences (excess entries
are truncated and explicitly marked in the summary).

## Attribution categories

| Category          | Meaning                                                                 | Counts as improvement/regression? |
|-------------------|-------------------------------------------------------------------------|------------------------------------|
| `config_change`   | Same rule fingerprint on both sides, different result — the machine configuration changed. | Yes (only this category) |
| `rule_change`     | Same check ID, different decision condition (e.g. permission requirement tightened 644 → 600). A result flip is the rule's doing. | No |
| `added`           | Check exists only in the newer rule set. A new rule is not a new failure. | No |
| `removed`         | Check exists only in the older rule set. A deleted rule is not a fixed failure. | No |
| `coverage_change` | Difference explained by the two scans covering different node roles (e.g. one included `etcd`). | No |
| `incomparable`    | Same ID but different content behind an identical decision condition (ID appears repurposed), or reports from different product lines. | No |
| `unattributable`  | A side lacks rule set version or fingerprint information; nothing is assumed identical. | No |

Each entry includes both sides' expected and actual values for manual review.
Audit output is redacted (PEM blocks and password/secret/token/key values) and
truncated, so comparison output never contains file contents or key material.

## Degradation and refusal

- Reports from different benchmark product lines (e.g. `eks-*` vs
  `k3s-cis-*`) are marked **not comparable** with an explanation.
- If either side is missing rule set version information, overlapping checks
  are marked `unattributable` and no improvement/regression counts are
  produced.
- A report whose structure cannot be recognised is refused with an error
  rather than guessed at.
- Re-running the same pair of inputs always produces byte-identical output.

## Reproducing the bundled demo

`hack/compare-demo` generates two reports from the real
`k3s-cis-1.10` / `k3s-cis-1.11` rule sets against a simulated, unchanging
machine configuration:

```
go run ./hack/compare-demo . /tmp/demo older
go run ./hack/compare-demo . /tmp/demo newer
kube-bench compare --older /tmp/demo/older.json --newer /tmp/demo/newer.json --text
```

In that scenario check `1.1.20` flips PASS → FAIL while the on-disk
permissions stay `644`; because the rule's bitmask requirement changed, the
flip is attributed to `rule_change`, not to the configuration.
