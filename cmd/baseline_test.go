// Copyright © 2025 Aqua Security Software Ltd. <info@aquasec.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/kube-bench/check"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testEnv snapshots and restares the package globals touched by the
// multi-baseline path.
type testEnv struct {
	cfgDir      string
	cfgFile     string
	kubeVersion string
	detected    string
	jsonFmt     bool
	junitFmt    bool
	pgSQL       bool
	aSFF        bool
	outputFile  string
	noTotals    bool
	skipIds     string
	filterOpts  FilterOpts
	collection  []*check.Controls
}

func snapshotEnv(t *testing.T) *testEnv {
	t.Helper()
	s := &testEnv{
		cfgDir:      cfgDir,
		cfgFile:     cfgFile,
		kubeVersion: kubeVersion,
		detected:    detecetedKubeVersion,
		jsonFmt:     jsonFmt,
		junitFmt:    junitFmt,
		pgSQL:       pgSQL,
		aSFF:        aSFF,
		outputFile:  outputFile,
		noTotals:    noTotals,
		skipIds:     skipIds,
		filterOpts:  filterOpts,
		collection:  controlsCollection,
	}
	t.Cleanup(func() {
		cfgDir = s.cfgDir
		cfgFile = s.cfgFile
		kubeVersion = s.kubeVersion
		detecetedKubeVersion = s.detected
		jsonFmt = s.jsonFmt
		junitFmt = s.junitFmt
		pgSQL = s.pgSQL
		aSFF = s.aSFF
		outputFile = s.outputFile
		noTotals = s.noTotals
		skipIds = s.skipIds
		filterOpts = s.filterOpts
		controlsCollection = s.collection
	})
	// Production flag defaults.
	filterOpts = FilterOpts{Scored: true, Unscored: true}
	skipIds = ""
	cfgFile = ""
	junitFmt = false
	pgSQL = false
	aSFF = false
	noTotals = false
	controlsCollection = nil
	return s
}

const minimalConfig = `master:
  components: []
node:
  components: []
etcd:
  components: []
`

// writeTestRegistry builds a self-contained registry root.
func writeTestRegistry(t *testing.T, root string, families map[string]string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "baselines"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "config.yaml"), []byte(minimalConfig), 0o644))
	for family, body := range families {
		require.NoError(t, os.WriteFile(filepath.Join(root, "baselines", family+".yaml"), []byte(body), 0o644))
	}
}

func manifest(family, version string, withDefault bool) string {
	defaultLine := ""
	if withDefault {
		defaultLine = "default: " + version + "\n"
	}
	return sprintfManifest(family, version, defaultLine)
}

func sprintfManifest(family, version, defaultLine string) string {
	return "apiVersion: kube-bench.io/v1alpha1\n" +
		"kind: BaselineManifest\n" +
		"family: " + family + "\n" +
		"displayName: " + family + "\n" +
		defaultLine +
		"baselines:\n" +
		"  - version: " + version + "\n" +
		"    versions: [\"1.*\"]\n" +
		"    targets: [master, node]\n" +
		"    definitions: ../defs/" + version + "\n"
}

// checkDef builds a definition with one check whose audit emits output.
func checkDef(version, nodeType, checkID, expected string) string {
	return `---
version: "` + version + `"
id: 1
text: "t"
type: "` + nodeType + `"
groups:
  - id: 1.1
    text: "g"
    checks:
      - id: ` + checkID + `
        text: "sample check"
        audit: "echo permissions=600"
        tests:
          test_items:
            - flag: "permissions=600"
        remediation: "fix it"
        scored: true
`
}

func writeDef(t *testing.T, root, version, target, content string) {
	t.Helper()
	dir := filepath.Join(root, "defs", version)
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, target+".yaml"), []byte(content), 0o644))
}

func TestRunBaselinesThreeFamilyMerge(t *testing.T) {
	snapshotEnv(t)
	root := t.TempDir()
	cfgDir = root
	kubeVersion = "1.31"
	jsonFmt = true
	outputFile = filepath.Join(t.TempDir(), "out.json")

	families := map[string]string{
		"cis":      manifest("cis", "cis-v1", false),
		"eks":      manifest("eks", "eks-v1", false),
		"internal": manifest("internal", "internal-v1", true),
	}
	writeTestRegistry(t, root, families)

	// Same check number 1.1.1 under all three families; the internal one
	// uses a different expected value to force a semantic conflict.
	writeDef(t, root, "cis-v1", "master", checkDef("cis-v1", "master", "1.1.1", "600"))
	writeDef(t, root, "eks-v1", "master", checkDef("eks-v1", "master", "1.1.1", "600"))
	internalDef := `---
version: "internal-v1"
id: 1
text: "t"
type: "master"
groups:
  - id: 1.1
    text: "g"
    checks:
      - id: 1.1.1
        text: "different semantics"
        audit: "echo permissions=644"
        tests:
          test_items:
            - flag: "permissions=644"
        remediation: "fix it"
        scored: true
`
	writeDef(t, root, "internal-v1", "master", internalDef)

	err := runBaselines(
		[]string{"cis@cis-v1", "eks@eks-v1", "internal@internal-v1"},
		nil, []string{"master"},
	)
	require.NoError(t, err)

	raw, err := os.ReadFile(outputFile)
	require.NoError(t, err)
	var envelope BaselineEnvelope
	require.NoError(t, json.Unmarshal(raw, &envelope))
	require.NotNil(t, envelope.Baselines)

	// Acceptance: three independent items; total equals independent count.
	assert.Equal(t, 3, envelope.Baselines.Summary.Total)
	assert.Len(t, envelope.Baselines.Items, 3)
	familiesSeen := map[string]bool{}
	for _, item := range envelope.Baselines.Items {
		assert.True(t, item.SourceKey.Valid())
		familiesSeen[item.SourceKey.Family] = true
	}
	assert.ElementsMatch(t, []string{"cis", "eks", "internal"}, keysOf(familiesSeen))

	// Conflicts marked, both original values retained.
	assert.NotEmpty(t, envelope.Baselines.Conflicts)
	for _, c := range envelope.Baselines.Conflicts {
		assert.Equal(t, "1.1.1", c.CheckID)
		assert.NotEmpty(t, c.SourceA)
		assert.NotEmpty(t, c.SourceB)
	}

	// Provenance fields are present on the new path.
	require.NotEmpty(t, envelope.Controls)
	for _, c := range envelope.Controls {
		assert.NotEmpty(t, c.SourceFamily)
		assert.NotEmpty(t, c.SourceDefinitionVersion)
		assert.Equal(t, "master", c.SourceTarget)
	}
}

func TestRunBaselinesDedupExcludesFromCounters(t *testing.T) {
	snapshotEnv(t)
	root := t.TempDir()
	cfgDir = root
	kubeVersion = "1.31"
	jsonFmt = true
	outputFile = filepath.Join(t.TempDir(), "out.json")

	writeTestRegistry(t, root, map[string]string{"cis": manifest("cis", "v1", false)})
	dupDef := `---
version: "v1"
id: 1
text: "t"
type: "master"
groups:
  - id: 1.1
    text: "g"
    checks:
      - id: 1.1.1
        text: "first"
        audit: "echo permissions=600"
        tests:
          test_items:
            - flag: "permissions=600"
        scored: true
      - id: 1.1.1
        text: "duplicate occurrence"
        audit: "echo permissions=600"
        tests:
          test_items:
            - flag: "permissions=600"
        scored: true
      - id: 1.1.2
        text: "second independent"
        audit: "echo permissions=600"
        tests:
          test_items:
            - flag: "permissions=600"
        scored: true
`
	writeDef(t, root, "v1", "master", dupDef)

	require.NoError(t, runBaselines([]string{"cis@v1"}, nil, []string{"master"}))

	raw, err := os.ReadFile(outputFile)
	require.NoError(t, err)
	var envelope BaselineEnvelope
	require.NoError(t, json.Unmarshal(raw, &envelope))

	assert.Equal(t, 2, envelope.Baselines.Summary.Total)
	assert.Equal(t, 2, envelope.Baselines.Summary.Pass)
	require.Len(t, envelope.Baselines.Duplicates, 1)
	assert.Equal(t, "1.1.1", envelope.Baselines.Duplicates[0].CheckID)
	assert.Equal(t, 2, envelope.Baselines.Duplicates[0].Occurrence)
	assert.Equal(t, 1, envelope.Baselines.Summary.DuplicateCount)
}

func TestRunBaselinesExternalRegistryNoRegistration(t *testing.T) {
	snapshotEnv(t)
	// Use the shipped minimal external sample directly: loading it proves
	// no compile-time registration is needed.
	externalDir := filepath.Join("..", "examples", "external-baseline")
	kubeVersion = "1.31"
	jsonFmt = true
	outputFile = filepath.Join(t.TempDir(), "out.json")

	require.NoError(t, runBaselines(
		[]string{"internal@internal-2025.1"},
		[]string{externalDir}, []string{"master"},
	))

	raw, err := os.ReadFile(outputFile)
	require.NoError(t, err)
	var envelope BaselineEnvelope
	require.NoError(t, json.Unmarshal(raw, &envelope))
	require.NotNil(t, envelope.Baselines)
	assert.NotEmpty(t, envelope.Baselines.Items)
	for _, item := range envelope.Baselines.Items {
		assert.Equal(t, "internal", item.SourceKey.Family)
		assert.Equal(t, "internal-2025.1", item.SourceKey.Version)
	}
}

func TestRunBaselinesBrokenManifestFails(t *testing.T) {
	snapshotEnv(t)
	root := t.TempDir()
	cfgDir = root
	require.NoError(t, os.MkdirAll(filepath.Join(root, "baselines"), 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(root, "baselines", "bad.yaml"),
		[]byte("apiVersion: kube-bench.io/v1alpha1\nkind: BaselineManifest\nfamily: x\nbaselines: []\n"),
		0o644))

	err := runBaselines([]string{"x@v1"}, nil, nil)
	require.Error(t, err)
	// Error must name manifest location and field path.
	assert.Contains(t, err.Error(), "bad.yaml")
	assert.Contains(t, err.Error(), "baselines")
}

func TestRunBaselinesVersionOutOfRange(t *testing.T) {
	snapshotEnv(t)
	root := t.TempDir()
	cfgDir = root
	kubeVersion = "1.31"

	t.Run("no default fails with family version and ranges", func(t *testing.T) {
		writeTestRegistry(t, root, map[string]string{"cis": manifest("cis", "v1", false)})
		writeDef(t, root, "v1", "master", checkDef("v1", "master", "1.1.1", "600"))
		err := runBaselines([]string{"cis:9.9"}, nil, []string{"master"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cis")
		assert.Contains(t, err.Error(), "9.9")
		assert.Contains(t, err.Error(), "1.*")
	})

	t.Run("explicit default degrades with reason", func(t *testing.T) {
		jsonFmt = true
		outputFile = filepath.Join(t.TempDir(), "out.json")
		writeTestRegistry(t, root, map[string]string{"cis": manifest("cis", "v1", true)})
		writeDef(t, root, "v1", "master", checkDef("v1", "master", "1.1.1", "600"))
		require.NoError(t, runBaselines([]string{"cis:9.9"}, nil, []string{"master"}))

		raw, err := os.ReadFile(outputFile)
		require.NoError(t, err)
		var envelope BaselineEnvelope
		require.NoError(t, json.Unmarshal(raw, &envelope))
		require.NotEmpty(t, envelope.Selections)
		assert.True(t, envelope.Selections[0].Degraded)
		assert.Contains(t, envelope.Selections[0].DegradeReason, "default")
	})
}

func TestRunBaselinesSingleBadDefinitionIsSkipped(t *testing.T) {
	snapshotEnv(t)
	root := t.TempDir()
	cfgDir = root
	kubeVersion = "1.31"
	jsonFmt = true
	outputFile = filepath.Join(t.TempDir(), "out.json")

	writeTestRegistry(t, root, map[string]string{"cis": manifest("cis", "v1", false)})
	badDef := `---
version: "v1"
id: 1
text: "t"
type: "master"
groups:
  - id: 1.1
    text: "g"
    checks:
      - id: 1.1.1
        text: "good check"
        audit: "echo permissions=600"
        tests:
          test_items:
            - flag: "permissions=600"
        scored: true
      - id: 1.1.2
        text: "broken check"
        tests:
          test_items:
            - compare:
                op: [not, a, string]
      - id: 1.1.3
        text: "another good check"
        audit: "echo permissions=600"
        tests:
          test_items:
            - flag: "permissions=600"
        scored: true
`
	writeDef(t, root, "v1", "master", badDef)

	// The run must not fail wholesale.
	require.NoError(t, runBaselines([]string{"cis@v1"}, nil, []string{"master"}))

	raw, err := os.ReadFile(outputFile)
	require.NoError(t, err)
	var envelope BaselineEnvelope
	require.NoError(t, json.Unmarshal(raw, &envelope))
	require.NotNil(t, envelope.Baselines)

	assert.Equal(t, 1, envelope.Baselines.Summary.DefinitionErrors)
	require.Len(t, envelope.Baselines.DefinitionErrors, 1)
	assert.Equal(t, "1.1.2", envelope.Baselines.DefinitionErrors[0].EntryID)
	// The other checks still ran.
	ids := map[string]bool{}
	for _, item := range envelope.Baselines.Items {
		ids[item.Check.ID] = true
	}
	assert.True(t, ids["1.1.1"])
	assert.True(t, ids["1.1.3"])
	assert.False(t, ids["1.1.2"])
}

func TestRunBaselinesDuplicateRequestFails(t *testing.T) {
	snapshotEnv(t)
	_, err := parseBaselineRequests([]string{"cis:1.31", "cis:1.31"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate")
}

func TestPrintOutputAtomicNoPartialOrAppend(t *testing.T) {
	snapshotEnv(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "out.json")

	require.NoError(t, printOutputAtomic("first", target))
	raw, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, "first\n", string(raw))

	// A retry replaces the file instead of appending.
	require.NoError(t, printOutputAtomic("second", target))
	raw, err = os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, "second\n", string(raw))

	// Failure leaves no partial artifact behind.
	badTarget := filepath.Join(dir, "missing-dir", "out.json")
	err = printOutputAtomic("payload", badTarget)
	require.Error(t, err)
	_, err = os.Stat(badTarget)
	assert.True(t, os.IsNotExist(err))
}

func TestProvenanceFieldsDoNotLeakIntoLegacyOutput(t *testing.T) {
	snapshotEnv(t)
	// Legacy structs with zero-value provenance fields must not serialize
	// the additive fields at all.
	legacy := &check.Controls{ID: "1", Type: check.MASTER, Groups: []*check.Group{}}
	out, err := json.Marshal(legacy)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "source_family")
	assert.NotContains(t, string(out), "normalization_key")

	legacyCheck := &check.Check{ID: "1.1.1"}
	out, err = json.Marshal(legacyCheck)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "source_family")
	assert.NotContains(t, string(out), "duplicate")
}

func TestRunBaselinesDefinitionDirectoryIsReadOnly(t *testing.T) {
	snapshotEnv(t)
	root := t.TempDir()
	cfgDir = root
	kubeVersion = "1.31"
	jsonFmt = true
	outputFile = filepath.Join(t.TempDir(), "out.json")

	writeTestRegistry(t, root, map[string]string{"cis": manifest("cis", "v1", false)})
	writeDef(t, root, "v1", "master", checkDef("v1", "master", "1.1.1", "600"))

	// Snapshot every file under the definition tree, then make the tree
	// read-only. A run that tried to write caches/indexes would fail.
	defDir := filepath.Join(root, "defs", "v1")
	before := snapshotTree(t, defDir)
	require.NoError(t, os.Chmod(defDir, 0o500))
	require.NoError(t, os.Chmod(root, 0o500))
	t.Cleanup(func() {
		_ = os.Chmod(root, 0o755)
		_ = os.Chmod(defDir, 0o755)
	})

	require.NoError(t, runBaselines([]string{"cis@v1"}, nil, []string{"master"}))
	after := snapshotTree(t, defDir)
	assert.Equal(t, before, after, "definition directory contents must not change")
}

// snapshotTree returns a deterministic map of relative path -> content for
// every file under dir.
func snapshotTree(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		require.NoError(t, err)
		if info.IsDir() {
			return nil
		}
		raw, err := os.ReadFile(path)
		require.NoError(t, err)
		rel, err := filepath.Rel(dir, path)
		require.NoError(t, err)
		out[rel] = string(raw)
		return nil
	})
	require.NoError(t, err)
	return out
}

func TestRunBaselinesUnknownFamilyFails(t *testing.T) {
	snapshotEnv(t)
	root := t.TempDir()
	cfgDir = root
	kubeVersion = "1.31"
	writeTestRegistry(t, root, map[string]string{"cis": manifest("cis", "v1", false)})

	err := runBaselines([]string{"ghost@v1"}, nil, []string{"master"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ghost")
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
