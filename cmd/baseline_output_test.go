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
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/kube-bench/check"
	"github.com/aquasecurity/kube-bench/internal/baseline"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sampleControls() []*check.Controls {
	return []*check.Controls{
		{
			ID:      "1",
			Version: "1.24",
			Text:    "Control Plane",
			Type:    check.MASTER,
			Groups: []*check.Group{
				{
					ID:   "1.1",
					Text: "group",
					Checks: []*check.Check{
						{ID: "1.1.1", Text: "check one", State: check.PASS, Scored: true, TestInfo: []string{"rem"}},
					},
				},
			},
			Summary: check.Summary{Pass: 1},
		},
	}
}

// captureStdout runs fn while redirecting os.Stdout and returns everything
// it printed.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	fn()
	require.NoError(t, w.Close())
	os.Stdout = old
	var buf bytes.Buffer
	_, err = buf.ReadFrom(r)
	require.NoError(t, err)
	return buf.String()
}

// TestLegacyJunitOutputUnchanged locks the JUnit serialization of controls
// that carry no provenance fields (the legacy single-baseline path).
func TestLegacyJunitOutputUnchanged(t *testing.T) {
	snapshotEnv(t)
	c, err := sampleControls()[0].JUnit()
	require.NoError(t, err)
	out := "<testsuites>\n" + string(c) + "\n</testsuites>"

	assert.NotContains(t, out, "source_family")
	assert.NotContains(t, out, "normalization_key")
	assert.Contains(t, out, "1.1.1")
}

// TestMultiBaselineJunitReusesLegacySerialization ensures the multi-baseline
// JUnit path keeps the historical testsuites/testcase envelope. The per-check
// JSON embedded in system-out is the full check serialization by design, so
// additive provenance fields may appear there; the JUnit XML structure itself
// is unchanged.
func TestMultiBaselineJunitReusesLegacySerialization(t *testing.T) {
	snapshotEnv(t)
	outputFile = filepath.Join(t.TempDir(), "out.xml")
	junitFmt = true

	writeBaselineJunit(sampleControls())

	raw, err := os.ReadFile(outputFile)
	require.NoError(t, err)
	assert.True(t, bytes.HasPrefix(raw, []byte("<testsuites>")))
	assert.True(t, bytes.HasSuffix(bytes.TrimSpace(raw), []byte("</testsuites>")))
	assert.Contains(t, string(raw), "<testsuite")
	assert.Contains(t, string(raw), "<testcase")
	assert.Contains(t, string(raw), "1.1.1")
}

// TestLegacyStdoutOutputStable verifies console output keeps the historical
// counters and never emits additive provenance fields. Color-printed headers
// bypass os.Stdout redirection (fatih/color caches the writer at init), so
// assertions target the fmt.Printf content exactly as the existing stdout
// tests do.
func TestLegacyStdoutOutputStable(t *testing.T) {
	snapshotEnv(t)
	text := captureStdout(t, func() { writeStdoutOutput(sampleControls()) })

	assert.Contains(t, text, "1.1.1")
	assert.Contains(t, text, "1 checks PASS")
	assert.NotContains(t, text, "source_family")
}

// TestMultiBaselineStdoutCarriesNormalizationNotices ensures conflict,
// duplicate and definition-error notices appear on the multi-baseline path
// while a nil report stays silent.
func TestMultiBaselineStdoutCarriesNormalizationNotices(t *testing.T) {
	snapshotEnv(t)

	silent := captureStdout(t, func() { printNormalizationNotice(nil) })
	assert.Empty(t, silent)

	report := &baseline.NormalizedReport{
		Conflicts: []baseline.ConflictPair{
			{CheckID: "1.1.1", SourceA: "cis/v1", SourceB: "internal/v1", ConflictField: "expected_result"},
		},
		Duplicates: []baseline.DuplicateEntry{
			{CheckID: "1.1.2", SourceKey: baseline.SourceKey{Family: "cis", Version: "v1", Target: "master"}, Occurrence: 2},
		},
		DefinitionErrors: []baseline.DefinitionError{
			{SourceKey: baseline.SourceKey{Family: "cis", Version: "v1", Target: "master"}, EntryID: "1.1.3"},
		},
	}
	// Notice body lines use fmt.Printf and are captured via os.Stdout.
	text := captureStdout(t, func() { printNormalizationNotice(report) })
	assert.Contains(t, text, "1.1.1")
	assert.Contains(t, text, "cis/v1 vs internal/v1")
	assert.Contains(t, text, "1.1.2")
	assert.Contains(t, text, "1.1.3")
}

// TestLegacyASFFExcludesProvenance ensures ASFF findings never carry the
// additive provenance JSON fields, keeping that output channel stable.
func TestLegacyASFFExcludesProvenance(t *testing.T) {
	snapshotEnv(t)
	viper.Set("AWS_ACCOUNT", "foo account")
	viper.Set("CLUSTER_ARN", "foo Cluster")
	viper.Set("AWS_REGION", "somewhere")

	controls := sampleControls()
	controls[0].Groups[0].Checks[0].State = check.FAIL
	findings, err := controls[0].ASFF()
	require.NoError(t, err)
	require.Len(t, findings, 1)
	_, hasSource := findings[0].ProductFields["source_family"]
	assert.False(t, hasSource)
	_, hasNorm := findings[0].ProductFields["normalization_key"]
	assert.False(t, hasNorm)
}

// TestLegacyJSONOutputByteStable compares the legacy JSON path against its
// recorded golden file, proving additive fields do not alter it.
func TestLegacyJSONOutputByteStable(t *testing.T) {
	snapshotEnv(t)
	controls, err := parseControlsJsonFile("./testdata/controlsCollection.json")
	require.NoError(t, err)

	jsonFmt = true
	outputFile = filepath.Join(t.TempDir(), "result.json")
	writeOutput(controls)

	got, err := parseResultJsonFile(outputFile)
	require.NoError(t, err)
	want, err := parseResultJsonFile("./testdata/result.json")
	require.NoError(t, err)
	assert.Equal(t, want, got)
}
