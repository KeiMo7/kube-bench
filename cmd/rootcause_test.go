// Copyright © 2024 Aqua Security Software Ltd. <info@aquasec.com>
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
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aquasecurity/kube-bench/check"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sampleControlsForRootCause() []*check.Controls {
	return []*check.Controls{
		{
			ID:   "1",
			Type: check.MASTER,
			Groups: []*check.Group{
				{
					ID: "1.1",
					Checks: []*check.Check{
						{ID: "1.1.1", State: check.FAIL, Scored: true},
						{ID: "1.1.2", State: check.PASS, Scored: true},
					},
				},
			},
		},
	}
}

func resetRootCauseFlags(t *testing.T) {
	t.Helper()
	oldRoot, oldCfg, oldBaseline, oldReport := rootCause, rootCauseConfig, rootCauseBaselinePath, rootCauseReport
	t.Cleanup(func() {
		rootCause, rootCauseConfig, rootCauseBaselinePath, rootCauseReport = oldRoot, oldCfg, oldBaseline, oldReport
	})
	rootCause = true
	rootCauseConfig = ""
	rootCauseBaselinePath = ""
	rootCauseReport = nil
}

func TestRootCauseDisabledLeavesOutputUnchanged(t *testing.T) {
	resetRootCauseFlags(t)
	rootCause = false

	controls := sampleControlsForRootCause()
	controls[0].Groups[0].Checks[0].RootCause = nil
	applyRootCauseAnalysis(controls)

	assert.Nil(t, controls[0].RootCause)
	assert.Nil(t, rootCauseReport)

	out, err := json.Marshal(controls)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "root_cause")
}

func TestRootCauseReportIsIncludedInJSON(t *testing.T) {
	resetRootCauseFlags(t)

	controls := sampleControlsForRootCause()
	controls[0].Groups[0].Checks[0].State = check.FAIL
	applyRootCauseAnalysis(controls)

	require.NotNil(t, rootCauseReport)
	require.NotNil(t, controls[0].RootCause)

	dir := t.TempDir()
	outFile := filepath.Join(dir, "out.json")
	oldJSON, oldTotals, oldOut := jsonFmt, noTotals, outputFile
	t.Cleanup(func() { jsonFmt, noTotals, outputFile = oldJSON, oldTotals, oldOut })
	jsonFmt = true
	noTotals = false
	outputFile = outFile

	writeOutput(controls)

	in, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var envelope struct {
		RootCause *check.RootCauseReport `json:"RootCause"`
	}
	require.NoError(t, json.Unmarshal(in, &envelope))
	require.NotNil(t, envelope.RootCause)
	assert.Equal(t, 1, envelope.RootCause.TotalNonPassing)
	assert.Equal(t, 1, envelope.RootCause.Counts[check.RootCauseUnclassified])
}

func TestRootCauseNotInJSONWhenDisabled(t *testing.T) {
	resetRootCauseFlags(t)
	rootCause = false

	controls := sampleControlsForRootCause()

	dir := t.TempDir()
	outFile := filepath.Join(dir, "out.json")
	oldJSON, oldTotals, oldOut := jsonFmt, noTotals, outputFile
	t.Cleanup(func() { jsonFmt, noTotals, outputFile = oldJSON, oldTotals, oldOut })
	jsonFmt = true
	noTotals = false
	outputFile = outFile

	writeOutput(controls)

	in, err := os.ReadFile(outFile)
	require.NoError(t, err)
	assert.NotContains(t, string(in), "RootCause")
	assert.NotContains(t, string(in), "root_cause")
}

func TestLoadRootCauseBaselineFromEnvelope(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "prev.json")
	require.NoError(t, os.WriteFile(path, []byte(`{
  "Controls": [],
  "Totals": {"total_pass": 0, "total_fail": 0, "total_warn": 0, "total_info": 0},
  "RootCause": {"enabled": true, "counts": {"file_unreadable": 7, "command_missing": 2}}
}`), 0o600))

	counts, err := loadRootCauseBaseline(path)
	require.NoError(t, err)
	assert.Equal(t, 7, counts[check.RootCauseFileUnreadable])
	assert.Equal(t, 2, counts[check.RootCauseCommandMissing])
}

func TestLoadRootCauseBaselineFromSections(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "prev.json")
	require.NoError(t, os.WriteFile(path, []byte(`[
  {"id": "1", "root_cause": {"enabled": true, "counts": {"file_unreadable": 3}}},
  {"id": "2", "root_cause": {"enabled": true, "counts": {"file_unreadable": 4}}}
]`), 0o600))

	counts, err := loadRootCauseBaseline(path)
	require.NoError(t, err)
	assert.Equal(t, 7, counts[check.RootCauseFileUnreadable])
}

func TestLoadRootCauseBaselineWithoutData(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "prev.json")
	require.NoError(t, os.WriteFile(path, []byte(`[{"id": "1"}]`), 0o600))

	_, err := loadRootCauseBaseline(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no root cause data")
}

func TestRootCauseDeltaInOutput(t *testing.T) {
	resetRootCauseFlags(t)
	rootCauseBaseline = map[check.RootCauseClass]int{check.RootCauseUnclassified: 4}
	t.Cleanup(func() { rootCauseBaseline = nil })

	controls := sampleControlsForRootCause()
	applyRootCauseAnalysis(controls)

	require.NotNil(t, rootCauseReport)
	assert.Equal(t, -3, rootCauseReport.Delta[check.RootCauseUnclassified])
}

func TestApplyRootCauseAnalysisRejectsCycle(t *testing.T) {
	resetRootCauseFlags(t)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "rc.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`
dependencies:
  1.1.1: [1.1.2]
  1.1.2: [1.1.1]
`), 0o600))
	rootCauseConfig = cfgPath

	controls := sampleControlsForRootCause()

	// exitWithError calls os.Exit; the cycle itself is asserted in the check
	// package. Here we assert the analysis stops before mutating the results.
	_, err := check.AnalyzeControls(controls, mustConfig(t, cfgPath), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cycle")
	assert.Nil(t, controls[0].RootCause)
}

func mustConfig(t *testing.T, path string) *check.RootCauseConfig {
	t.Helper()
	cfg, err := check.ReadRootCauseConfig(path)
	require.NoError(t, err)
	return cfg
}

func TestPrintRootCauseRendersOncePerClass(t *testing.T) {
	report := &check.RootCauseReport{
		Enabled:         true,
		TotalNonPassing: 2,
		Groups: []check.RootCauseGroup{
			{
				Class:       check.RootCauseFileUnreadable,
				Count:       2,
				Checks:      []string{"1.1.1", "1.1.2"},
				Sources:     []string{"/etc/kubernetes/manifests/kube-apiserver.yaml"},
				Actions:     []check.RootCauseAction{{Detail: "/etc/kubernetes/manifests/kube-apiserver.yaml", Checks: []string{"1.1.1", "1.1.2"}}},
				Remediation: check.ClassRemediations[check.RootCauseFileUnreadable],
			},
		},
	}

	out := captureStdout(t, func() { printRootCause(report) })

	assert.Contains(t, out, "file_unreadable (2 checks)")
	assert.Contains(t, out, "1.1.1, 1.1.2")
	assert.Contains(t, out, "fix once:")
	// The remediation appears once, not once per check.
	assert.Equal(t, 1, countOccurrences(out, "fix once:"))
	assert.Equal(t, 1, countOccurrences(out, "Expose the unreachable host file"))
}

func TestPrintRootCauseDegraded(t *testing.T) {
	report := &check.RootCauseReport{Enabled: true, Degraded: true, Note: "boom"}
	out := captureStdout(t, func() { printRootCause(report) })
	assert.Contains(t, out, "root cause grouping was not applied: boom")
	assert.NotContains(t, out, "non-passing checks grouped")
}

func TestAggregatedReportSumsSections(t *testing.T) {
	r1 := &check.RootCauseReport{Enabled: true, Counts: map[check.RootCauseClass]int{check.RootCauseFileUnreadable: 3}, TotalNonPassing: 3,
		Groups: []check.RootCauseGroup{{Class: check.RootCauseFileUnreadable, Count: 3, Checks: []string{"1.1.1", "1.1.2", "1.1.3"},
			Actions: []check.RootCauseAction{{Detail: "/a", Checks: []string{"1.1.1", "1.1.2", "1.1.3"}}}}}}
	r2 := &check.RootCauseReport{Enabled: true, Counts: map[check.RootCauseClass]int{check.RootCauseFileUnreadable: 2}, TotalNonPassing: 2,
		Groups: []check.RootCauseGroup{{Class: check.RootCauseFileUnreadable, Count: 2, Checks: []string{"2.1.1", "2.1.2"},
			Actions: []check.RootCauseAction{{Detail: "/a", Checks: []string{"2.1.1", "2.1.2"}}}}}}

	merged := check.AggregateRootCauseReports([]*check.RootCauseReport{r1, r2}, nil)
	assert.Equal(t, 5, merged.Counts[check.RootCauseFileUnreadable])
	assert.Equal(t, 5, merged.TotalNonPassing)
	require.Len(t, merged.Groups, 1)
	assert.Equal(t, 5, merged.Groups[0].Count)
	assert.Len(t, merged.Groups[0].Actions, 1)
	assert.Len(t, merged.Groups[0].Actions[0].Checks, 5)
}

func TestAggregatedReportDegradedSuppressesStatistics(t *testing.T) {
	r1 := &check.RootCauseReport{Enabled: true, Counts: map[check.RootCauseClass]int{check.RootCauseFileUnreadable: 3}, TotalNonPassing: 3}
	r2 := &check.RootCauseReport{Enabled: true, Degraded: true, Note: "boom"}

	merged := check.AggregateRootCauseReports([]*check.RootCauseReport{r1, r2}, nil)
	assert.True(t, merged.Degraded)
	assert.Nil(t, merged.Counts, "a degraded report must not publish partial counts")
	assert.Zero(t, merged.TotalNonPassing)
	assert.Empty(t, merged.Groups)
	assert.Equal(t, "boom", merged.Note)
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	old := os.Stdout
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = old
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(out)
}

func countOccurrences(s, sub string) int {
	return strings.Count(s, sub)
}

func TestApplyRootCauseAnalysisLoadsBaselineFromPath(t *testing.T) {
	// The `run` subcommand does not execute RootCmd.Run, so baseline loading
	// must happen inside applyRootCauseAnalysis or it would silently no-op.
	resetRootCauseFlags(t)
	rootCauseBaseline = nil

	dir := t.TempDir()
	basePath := filepath.Join(dir, "prev.json")
	require.NoError(t, os.WriteFile(basePath, []byte(`{
  "Controls": [],
  "Totals": {"total_pass":0,"total_fail":0,"total_warn":0,"total_info":0},
  "RootCause": {"enabled": true, "counts": {"unclassified": 5}}
}`), 0o600))
	rootCauseBaselinePath = basePath

	controls := sampleControlsForRootCause()
	applyRootCauseAnalysis(controls)

	require.NotNil(t, rootCauseReport)
	assert.Equal(t, -4, rootCauseReport.Delta[check.RootCauseUnclassified])
}
