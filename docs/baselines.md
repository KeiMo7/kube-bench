# Declarative Baselines

kube-bench can run multiple security baselines — the built-in CIS-style
benchmarks and fully external, organization-internal baselines — in a
single run. Baselines are registered through **declarative YAML manifests**
discovered at startup, so adding a distribution family or an internal
baseline requires no source change and no recompilation.

## Registry layout

A registry root contains a `baselines/` directory holding one or more
manifest files:

```
<registry-root>/
  config.yaml                 # optional variable substitutions
  baselines/
    cis.yaml                  # one manifest per family
    internal.yaml
  cis-1.24/                   # definition directories referenced by manifests
    master.yaml
    node.yaml
    ...
```

The built-in registry is the `cfg/` directory. Additional external roots
are added with `--baseline-dir <path>` (repeatable).

## Manifest reference

```yaml
apiVersion: kube-bench.io/v1alpha1
kind: BaselineManifest
family: internal                 # stable family id; unique across the registry
displayName: Internal Baseline   # human readable name
platforms:                       # detected platform names mapped to this family
  - internal
default: internal-2025.1         # optional explicit fallback version
baselines:
  - version: internal-2025.1     # definition version id
    displayName: Internal 2025.1
    versions:                    # cluster versions this entry applies to
      - "1.31"                   # exact version
      - "1.*"                    # wildcard
      - "1.22-1.24"              # inclusive range
      - "[1.22,1.24]"            # inclusive bracket range
    targets: [master, node]      # available check targets
    definitions: ../defs/v1      # definition directory (confined to the root)
    normalizationKey: internal/v1   # optional, defaults to "<family>/<version>"
    config: ../defs/v1/config.yaml  # optional version-specific config
```

### Version selection rules

When several entries match a requested cluster version, selection is fully
deterministic:

1. **Narrower expression wins**: exact version > bounded range > wildcard.
   Among ranges, the smaller span wins; among wildcards, the longer fixed
   prefix wins.
2. **Declaration order breaks ties**: when specificity is equal, the entry
   declared first in the manifest wins.
3. **No match**: if the family explicitly declares `default`, the run
   degrades to that version and reports the reason; otherwise the run fails
   with a non-zero exit code, listing the family, requested version and
   available ranges.

## Running baselines

Select a baseline with `--baseline` (repeatable to merge several in one
run):

```sh
# family resolved against a cluster version
kube-bench run --baseline cis:1.31 --targets master

# pin an exact registered definition version
kube-bench run --baseline cis@cis-1.24

# merge two built-in families and one fully external family
kube-bench run \
  --baseline cis:1.31 \
  --baseline k3s:1.31 \
  --baseline-dir ./examples/external-baseline \
  --baseline internal@internal-2025.1
```

The `--baseline` syntax is:

| Form | Meaning |
| --- | --- |
| `family` | detect the cluster version and range-match |
| `family:<cluster-version>` | range-match an explicit cluster version |
| `family@<definition-version>` | pin a registered definition version |

## Result normalization

Every result carries a three-layer **source key** — family, definition
version and check target. A result missing any layer is invalid and never
enters the report. The key is produced once at load time and only passed
through filtering, execution, normalization and output.

- **Deduplication**: the same check number repeated under one source key
  keeps its first occurrence; later occurrences are marked duplicates and
  excluded from pass/fail/warn/info counters.
- **Cross-baseline merge**: the same check number under different families
  is an independent item — never overwritten and never summed. The merged
  total equals the count of normalized independent items.
- **Semantic conflicts**: when the same number under two sources differs in
  judgment type or expected value, both original values are retained and
  the pair is explicitly marked as a conflict; nothing is chosen silently.
- Duplicate and conflict counts are reported separately from the
  pass/fail/warn/info totals.

## Safety properties

- Definition directories are treated as read-only; kube-bench never writes
  caches, indexes or rewritten definitions into them.
- Manifest-declared paths are confined to the registry root: path traversal
  and symlink escapes are rejected at load time. Load errors name only the
  manifest location and entry identifier — audit commands and environment
  values are never echoed.
- A structurally invalid manifest aborts the whole run with a non-zero code;
  a single unparseable check definition is skipped and counted as a
  definition error while all other checks still run.
- File output is written atomically (temp file + rename), so a failure
  leaves no partial artifact and retries replace rather than append.
