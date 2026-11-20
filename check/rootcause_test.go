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

package check

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newRootCauseCheck builds a failed check carrying the audit evidence that the
// classifier consumes. It mirrors what Check.run records, without executing
// anything.
func newRootCauseCheck(id string, state State, evidence ...auditEvidence) *Check {
	return &Check{
		ID:            id,
		State:         state,
		Scored:        true,
		auditEvidence: evidence,
	}
}

func failedAudit(stage, command, output string, err error) auditEvidence {
	e := auditEvidence{Stage: stage, Command: command, Output: output}
	if err != nil {
		e.Err = err.Error()
	}
	return e
}

// TestRootCauseClasses asserts the correct landing class for each of the six
// root causes.
func TestRootCauseClasses(t *testing.T) {
	tests := []struct {
		name     string
		check    *Check
		blocked  []string
		expected RootCauseClass
	}{
		{
			name: "file unreadable from explicit audit error",
			check: newRootCauseCheck("1.1.1", FAIL, failedAudit("auditConfig",
				"cat /etc/kubernetes/manifests/kube-apiserver.yaml",
				"cat: /etc/kubernetes/manifests/kube-apiserver.yaml: No such file or directory\n",
				errors.New("exit status 1"))),
			expected: RootCauseFileUnreadable,
		},
		{
			name: "file unreadable behind a test -e guard",
			check: newRootCauseCheck("1.1.2", FAIL, auditEvidence{
				Stage:   "audit",
				Command: "/bin/sh -c 'if test -e /etc/kubernetes/manifests/kube-apiserver.yaml; then stat -c permissions=%a /etc/kubernetes/manifests/kube-apiserver.yaml; fi'",
				Output:  "",
			}),
			expected: RootCauseFileUnreadable,
		},
		{
			name: "command missing",
			check: newRootCauseCheck("1.1.3", FAIL, failedAudit("audit",
				"kubectl version",
				"/bin/sh: 1: kubectl: not found\n",
				errors.New("exit status 127"))),
			expected: RootCauseCommandMissing,
		},
		{
			name: "permission denied",
			check: newRootCauseCheck("1.1.4", FAIL, failedAudit("audit",
				"stat -c %a /etc/kubernetes/admin.conf",
				"stat: cannot statx '/etc/kubernetes/admin.conf': Permission denied\n",
				errors.New("exit status 1"))),
			expected: RootCausePermissionDenied,
		},
		{
			name:     "upstream check did not pass",
			check:    newRootCauseCheck("1.1.6", FAIL),
			blocked:  []string{"1.1.5"},
			expected: RootCauseUpstreamBlocked,
		},
		{
			name: "not applicable because skipped",
			check: &Check{
				ID:    "1.1.7",
				State: INFO,
				Type:  SKIP,
			},
			expected: RootCauseNotApplicable,
		},
		{
			name: "not applicable because manual",
			check: &Check{
				ID:     "1.1.9",
				State:  WARN,
				Type:   MANUAL,
				Reason: "Test marked as a manual test",
			},
			expected: RootCauseNotApplicable,
		},
		{
			name: "unclassified keeps the raw symptom",
			check: func() *Check {
				c := newRootCauseCheck("1.1.8", FAIL)
				c.Reason = "unexpected output shape"
				return c
			}(),
			expected: RootCauseUnclassified,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc := classifyCheck(tt.check, tt.blocked)
			assert.Equal(t, tt.expected, rc.Class)
		})
	}
}

func TestRootCauseUnclassifiedDoesNotGuess(t *testing.T) {
	c := newRootCauseCheck("9.9", FAIL)
	c.Reason = "something entirely unexpected"

	rc := classifyCheck(c, nil)
	assert.Equal(t, RootCauseUnclassified, rc.Class)
	assert.Equal(t, "something entirely unexpected", rc.Detail,
		"the original symptom must be reported verbatim")
}

func TestRootCauseClassIsUniqueAndStable(t *testing.T) {
	checks := []*Check{
		newRootCauseCheck("a", FAIL, failedAudit("auditConfig", "cat /missing", "cat: /missing: No such file or directory", errors.New("exit status 1"))),
		newRootCauseCheck("b", FAIL, failedAudit("audit", "kubectl get nodes", "kubectl: command not found", errors.New("exit status 127"))),
		newRootCauseCheck("c", FAIL, failedAudit("audit", "cat /secret", "cat: /secret: Permission denied", errors.New("exit status 1"))),
		newRootCauseCheck("d", FAIL),
	}

	// A check with evidence for two classes must land in exactly one: the first
	// recorded failure decides.
	ambiguous := newRootCauseCheck("e", FAIL,
		failedAudit("audit", "kubectl get nodes", "kubectl: command not found", errors.New("exit status 127")),
		failedAudit("auditConfig", "cat /missing", "cat: /missing: No such file or directory", errors.New("exit status 1")))
	report, err := AnalyzeRootCauses(append(checks, ambiguous), &RootCauseConfig{}, nil)
	require.NoError(t, err)
	assert.Equal(t, RootCauseCommandMissing, ambiguous.RootCause.Class)
	assert.Equal(t, 5, report.TotalNonPassing)

	// Same inputs must produce byte-identical reports.
	first, err := AnalyzeRootCauses(checks, &RootCauseConfig{}, nil)
	require.NoError(t, err)
	second, err := AnalyzeRootCauses(checks, &RootCauseConfig{}, nil)
	require.NoError(t, err)
	firstJSON, _ := json.Marshal(first)
	secondJSON, _ := json.Marshal(second)
	assert.Equal(t, string(firstJSON), string(secondJSON))
}

// TestRootCauseAggregationNoDoubleCounting is the merge case: three root
// causes affect several checks; their counts must sum to the total and no
// check may be counted twice.
func TestRootCauseAggregationNoDoubleCounting(t *testing.T) {
	checks := []*Check{
		// file_unreadable x3, two distinct paths
		newRootCauseCheck("1.1.1", FAIL, failedAudit("auditConfig", "cat /a", "cat: /a: No such file or directory", errors.New("exit status 1"))),
		newRootCauseCheck("1.1.2", FAIL, failedAudit("auditConfig", "cat /a", "cat: /a: No such file or directory", errors.New("exit status 1"))),
		newRootCauseCheck("1.1.3", FAIL, failedAudit("auditConfig", "cat /b", "cat: /b: No such file or directory", errors.New("exit status 1"))),
		// command_missing x2
		newRootCauseCheck("1.2.1", FAIL, failedAudit("audit", "kubectl", "kubectl: command not found", errors.New("exit status 127"))),
		newRootCauseCheck("1.2.2", WARN, failedAudit("audit", "etcdctl", "etcdctl: command not found", errors.New("exit status 127"))),
		// permission_denied x1
		newRootCauseCheck("1.3.1", FAIL, failedAudit("audit", "cat /secret", "cat: /secret: Permission denied", errors.New("exit status 1"))),
		// passes are never counted
		newRootCauseCheck("1.4.1", PASS),
	}

	report, err := AnalyzeRootCauses(checks, &RootCauseConfig{}, nil)
	require.NoError(t, err)

	assert.Equal(t, 6, report.TotalNonPassing)
	sum := 0
	seen := map[string]int{}
	for _, g := range report.Groups {
		sum += g.Count
		assert.Equal(t, g.Count, len(g.Checks), "group count must match its listed checks")
		for _, id := range g.Checks {
			seen[id]++
		}
	}
	assert.Equal(t, report.TotalNonPassing, sum, "group counts must sum to the total")

	for id, n := range seen {
		assert.Equal(t, 1, n, "check %s was counted %d times", id, n)
	}

	assert.Equal(t, 3, report.Counts[RootCauseFileUnreadable])
	assert.Equal(t, 2, report.Counts[RootCauseCommandMissing])
	assert.Equal(t, 1, report.Counts[RootCausePermissionDenied])

	// Distinct points of action are visible under one class.
	var fileGroup RootCauseGroup
	for _, g := range report.Groups {
		if g.Class == RootCauseFileUnreadable {
			fileGroup = g
		}
	}
	assert.Equal(t, []string{"/a", "/b"}, fileGroup.Sources)
	assert.Len(t, fileGroup.Actions, 2)
	// One remediation per class, not per check.
	assert.NotEmpty(t, fileGroup.Remediation)
}

// TestRootCauseUpstreamBlocked is the dependency case: when an upstream check
// fails, the downstream one is marked blocked, not failed.
func TestRootCauseUpstreamBlocked(t *testing.T) {
	upstream := newRootCauseCheck("1.1.1", FAIL)
	downstream := newRootCauseCheck("1.1.2", FAIL)
	healthy := newRootCauseCheck("1.1.3", PASS)

	cfg := &RootCauseConfig{Dependencies: map[string][]string{
		"1.1.2": {"1.1.1"},
	}}

	report, err := AnalyzeRootCauses([]*Check{upstream, downstream, healthy}, cfg, nil)
	require.NoError(t, err)

	assert.Equal(t, RootCauseUpstreamBlocked, downstream.RootCause.Class)
	assert.Equal(t, []string{"1.1.1"}, downstream.RootCause.BlockedBy)
	assert.Equal(t, RootCauseUnclassified, upstream.RootCause.Class,
		"the upstream check keeps its own cause")
	assert.Nil(t, healthy.RootCause, "passing checks carry no root cause")

	// The downstream check is blocked, not counted as an ordinary failure class.
	assert.Equal(t, 1, report.Counts[RootCauseUpstreamBlocked])
	assert.Equal(t, 2, report.TotalNonPassing)
}

func TestRootCauseUpstreamBlockedIsTransitive(t *testing.T) {
	a := newRootCauseCheck("1.1.1", FAIL)
	b := newRootCauseCheck("1.1.2", FAIL)
	c := newRootCauseCheck("1.1.3", FAIL)

	cfg := &RootCauseConfig{Dependencies: map[string][]string{
		"1.1.2": {"1.1.1"},
		"1.1.3": {"1.1.2"},
	}}

	_, err := AnalyzeRootCauses([]*Check{a, b, c}, cfg, nil)
	require.NoError(t, err)

	assert.Equal(t, RootCauseUpstreamBlocked, b.RootCause.Class)
	assert.Equal(t, RootCauseUpstreamBlocked, c.RootCause.Class)
}

// TestRootCauseCycle asserts that a cyclic dependency names the checks on the
// cycle and produces no statistics.
func TestRootCauseCycle(t *testing.T) {
	checks := []*Check{
		newRootCauseCheck("1.1.1", FAIL),
		newRootCauseCheck("1.1.2", FAIL),
		newRootCauseCheck("1.1.3", FAIL),
	}

	cfg := &RootCauseConfig{Dependencies: map[string][]string{
		"1.1.1": {"1.1.2"},
		"1.1.2": {"1.1.3"},
		"1.1.3": {"1.1.1"},
	}}

	report, err := AnalyzeRootCauses(checks, cfg, nil)
	require.Error(t, err)
	assert.Nil(t, report, "no statistics may be produced on a cycle")
	assert.Contains(t, err.Error(), "cycle")
	assert.Contains(t, err.Error(), "1.1.1")
	assert.Contains(t, err.Error(), "1.1.2")
	assert.Contains(t, err.Error(), "1.1.3")

	for _, c := range checks {
		assert.Nil(t, c.RootCause, "no partial annotation may be left behind")
	}
}

func TestRootCauseCycleReportedDeterministically(t *testing.T) {
	cfg := map[string][]string{
		"b": {"c"},
		"c": {"a"},
		"a": {"b"},
	}
	var messages []string
	for i := 0; i < 20; i++ {
		messages = append(messages, ValidateDependencies(cfg).Error())
	}
	for _, m := range messages {
		assert.Equal(t, messages[0], m, "cycle reporting must be deterministic")
	}
}

func TestRootCauseSelfDependencyIsIgnored(t *testing.T) {
	cfg := &RootCauseConfig{Dependencies: map[string][]string{"1.1.1": {"1.1.1"}}}
	cfg.Normalize()
	require.NoError(t, ValidateDependencies(cfg.Dependencies))
}

func TestRootCauseDegradedReportOnAggregationFailure(t *testing.T) {
	// An empty section is a complete (zero) statistic, not a degraded one.
	empty, err := buildReport(nil, nil)
	require.NoError(t, err)
	assert.Equal(t, 0, empty.TotalNonPassing)
	assert.True(t, empty.Enabled)
	assert.False(t, empty.Degraded)

	// SectionReport surfaces an aggregation failure as a degraded report
	// instead of panicking or emitting partial counts.
	degraded := SectionReport(nil)
	require.NotNil(t, degraded)
	assert.Equal(t, 0, degraded.TotalNonPassing)
}

func TestRootCauseConfigParsing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rootcause.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
dependencies:
  1.1.2: [1.1.1]
  1.1.3:
    - 1.1.2
    - 1.1.1
`), 0o600))

	cfg, err := ReadRootCauseConfig(path)
	require.NoError(t, err)
	assert.Equal(t, []string{"1.1.1"}, cfg.Dependencies["1.1.2"])
	assert.Equal(t, []string{"1.1.1", "1.1.2"}, cfg.Dependencies["1.1.3"])
}

func TestReadRootCauseConfigMissingFile(t *testing.T) {
	_, err := ReadRootCauseConfig(filepath.Join(t.TempDir(), "nope.yaml"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read root cause config")
}

func TestRootCauseReportIsDeterministic(t *testing.T) {
	build := func() string {
		checks := []*Check{
			newRootCauseCheck("c", FAIL, failedAudit("audit", "cmd-c", "cmd-c: command not found", errors.New("exit status 127"))),
			newRootCauseCheck("a", FAIL, failedAudit("audit", "cmd-a", "cmd-a: command not found", errors.New("exit status 127"))),
			newRootCauseCheck("b", WARN, failedAudit("auditConfig", "cat /x", "cat: /x: No such file or directory", errors.New("exit status 1"))),
		}
		report, err := AnalyzeRootCauses(checks, &RootCauseConfig{}, nil)
		require.NoError(t, err)
		out, err := json.Marshal(report)
		require.NoError(t, err)
		return string(out)
	}

	want := build()
	for i := 0; i < 25; i++ {
		assert.Equal(t, want, build(), "report must be byte-identical across runs")
	}
}

func TestRootCauseDeltaAcrossRounds(t *testing.T) {
	// Round one: five checks fail for a missing file.
	round1 := []*Check{
		newRootCauseCheck("1", FAIL, failedAudit("auditConfig", "cat /a", "cat: /a: No such file or directory", errors.New("exit status 1"))),
		newRootCauseCheck("2", FAIL, failedAudit("auditConfig", "cat /a", "cat: /a: No such file or directory", errors.New("exit status 1"))),
		newRootCauseCheck("3", FAIL, failedAudit("auditConfig", "cat /a", "cat: /a: No such file or directory", errors.New("exit status 1"))),
		newRootCauseCheck("4", FAIL, failedAudit("auditConfig", "cat /a", "cat: /a: No such file or directory", errors.New("exit status 1"))),
		newRootCauseCheck("5", FAIL, failedAudit("auditConfig", "cat /a", "cat: /a: No such file or directory", errors.New("exit status 1"))),
	}
	first, err := AnalyzeRootCauses(round1, &RootCauseConfig{}, nil)
	require.NoError(t, err)
	assert.Equal(t, 5, first.Counts[RootCauseFileUnreadable])

	// Round two: the file was exposed, so only one check still fails.
	round2 := []*Check{
		newRootCauseCheck("1", PASS),
		newRootCauseCheck("2", PASS),
		newRootCauseCheck("3", PASS),
		newRootCauseCheck("4", PASS),
		newRootCauseCheck("5", FAIL, failedAudit("audit", "kubectl", "kubectl: command not found", errors.New("exit status 127"))),
	}
	second, err := AnalyzeRootCauses(round2, &RootCauseConfig{}, first.Counts)
	require.NoError(t, err)

	assert.Equal(t, -5, second.Delta[RootCauseFileUnreadable])
	assert.Zero(t, second.Counts[RootCauseFileUnreadable])
}

func TestRootCauseReportJSONShapeIsAdditive(t *testing.T) {
	// Without analysis, the new fields must not appear at all.
	c := &Check{ID: "1.1.1", State: FAIL}
	out, err := json.Marshal(c)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "root_cause")

	controls := &Controls{
		ID:     "1",
		Groups: []*Group{{ID: "1.1", Checks: []*Check{c}}},
	}
	out, err = json.Marshal(controls)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "root_cause")
}

func TestRootCauseActionsGroupByPointNotByCheck(t *testing.T) {
	// Ten checks reading the same missing file must collapse to one action.
	var checks []*Check
	for i := 0; i < 10; i++ {
		checks = append(checks, newRootCauseCheck(
			fmt.Sprintf("1.1.%d", i+1), FAIL,
			failedAudit("auditConfig", "cat /etc/kubernetes/manifests/kube-apiserver.yaml",
				"cat: /etc/kubernetes/manifests/kube-apiserver.yaml: No such file or directory",
				errors.New("exit status 1"))))
	}
	report, err := AnalyzeRootCauses(checks, &RootCauseConfig{}, nil)
	require.NoError(t, err)

	require.Len(t, report.Groups, 1)
	g := report.Groups[0]
	assert.Equal(t, 10, g.Count)
	assert.Len(t, g.Actions, 1, "one point of action, not one per check")
	assert.Len(t, g.Actions[0].Checks, 10)
	assert.Equal(t, "/etc/kubernetes/manifests/kube-apiserver.yaml", g.Actions[0].Detail)
}

func TestRootCauseDoesNotChangeStates(t *testing.T) {
	checks := []*Check{
		newRootCauseCheck("1", FAIL, failedAudit("auditConfig", "cat /a", "cat: /a: No such file or directory", errors.New("exit status 1"))),
		newRootCauseCheck("2", WARN),
		newRootCauseCheck("3", PASS),
		newRootCauseCheck("4", INFO),
	}
	before := make([]State, len(checks))
	for i, c := range checks {
		before[i] = c.State
	}

	_, err := AnalyzeRootCauses(checks, &RootCauseConfig{}, nil)
	require.NoError(t, err)

	for i, c := range checks {
		assert.Equal(t, before[i], c.State, "analysis must never change state")
	}
}

func TestCommandMissingWinsOverMissingFileWording(t *testing.T) {
	// A missing executable must not be attributed to a missing file just
	// because the shell wording contains "not found".
	c := newRootCauseCheck("1", FAIL, failedAudit("audit", "kubectl version",
		"/bin/sh: 1: kubectl: not found", errors.New("exit status 127")))
	rc := classifyCheck(c, nil)
	assert.Equal(t, RootCauseCommandMissing, rc.Class)
	assert.Equal(t, "kubectl", rc.Detail)
}

func TestGuardedPathExtraction(t *testing.T) {
	cases := map[string]string{
		`/bin/sh -c 'if test -e /etc/kubernetes/manifests/kube-apiserver.yaml; then stat -c permissions=%a /etc/kubernetes/manifests/kube-apiserver.yaml; fi'`: "/etc/kubernetes/manifests/kube-apiserver.yaml",
		`/bin/sh -c "if test -e /var/lib/kubelet/config.yaml; then stat -c %U:%G /var/lib/kubelet/config.yaml; fi"`:                                            "/var/lib/kubelet/config.yaml",
		`echo hello`: "",
	}
	for command, want := range cases {
		assert.Equal(t, want, extractGuardedPath(command), command)
	}
}

func TestRootCauseSignatureIsStable(t *testing.T) {
	// The signature must not depend on run order or map iteration.
	checks := []*Check{
		newRootCauseCheck("2", FAIL, failedAudit("auditConfig", "cat /a", "cat: /a: No such file or directory", errors.New("exit status 1"))),
		newRootCauseCheck("1", FAIL, failedAudit("auditConfig", "cat /b", "cat: /b: No such file or directory", errors.New("exit status 1"))),
	}
	r1, err := AnalyzeRootCauses(checks, &RootCauseConfig{}, nil)
	require.NoError(t, err)

	reversed := []*Check{checks[1], checks[0]}
	r2, err := AnalyzeRootCauses(reversed, &RootCauseConfig{}, nil)
	require.NoError(t, err)

	assert.Equal(t, r1.Groups[0].Signature, r2.Groups[0].Signature)
}

func TestAnalyzeControlsAcrossSections(t *testing.T) {
	// A check in section 2 depends on a check in section 1. Global analysis
	// must resolve that, which per-section analysis could not.
	upstream := newRootCauseCheck("1.1.1", FAIL)
	downstream := newRootCauseCheck("2.1.1", FAIL)

	s1 := &Controls{ID: "1", Groups: []*Group{{ID: "1.1", Checks: []*Check{upstream}}}}
	s2 := &Controls{ID: "2", Groups: []*Group{{ID: "2.1", Checks: []*Check{downstream}}}}

	cfg := &RootCauseConfig{Dependencies: map[string][]string{"2.1.1": {"1.1.1"}}}
	merged, err := AnalyzeControls([]*Controls{s1, s2}, cfg, nil)
	require.NoError(t, err)

	assert.Equal(t, RootCauseUpstreamBlocked, downstream.RootCause.Class)
	assert.Equal(t, 1, s2.RootCause.Counts[RootCauseUpstreamBlocked])
	assert.Equal(t, 2, merged.TotalNonPassing)
}

func TestAnalyzeControlsCycleProducesNoStatistics(t *testing.T) {
	a := newRootCauseCheck("1.1.1", FAIL)
	b := newRootCauseCheck("1.1.2", FAIL)
	controls := &Controls{ID: "1", Groups: []*Group{{ID: "1.1", Checks: []*Check{a, b}}}}

	cfg := &RootCauseConfig{Dependencies: map[string][]string{
		"1.1.1": {"1.1.2"},
		"1.1.2": {"1.1.1"},
	}}

	report, err := AnalyzeControls([]*Controls{controls}, cfg, nil)
	require.Error(t, err)
	assert.Nil(t, report)
	assert.Nil(t, controls.RootCause)
	assert.Nil(t, a.RootCause)
	assert.Nil(t, b.RootCause)
}

func TestCycleMessageListsChecks(t *testing.T) {
	err := ValidateDependencies(map[string][]string{
		"1.1.1": {"1.1.2"},
		"1.1.2": {"1.1.3"},
		"1.1.3": {"1.1.1"},
	})
	require.Error(t, err)
	msg := err.Error()
	assert.True(t, strings.Contains(msg, "1.1.1") && strings.Contains(msg, "1.1.2") && strings.Contains(msg, "1.1.3"))
}

func TestRootCauseRejectsAmbiguousDependency(t *testing.T) {
	// Legacy benchmarks such as rh-0.7 repeat check IDs. Referring to such an
	// ID in a dependency is ambiguous, so it must be refused, not resolved by
	// picking one of the duplicates.
	checks := []*Check{
		newRootCauseCheck("1.1", FAIL),
		newRootCauseCheck("1.1", FAIL),
		newRootCauseCheck("1.2", FAIL),
	}
	cfg := &RootCauseConfig{Dependencies: map[string][]string{"1.2": {"1.1"}}}

	report, err := AnalyzeRootCauses(checks, cfg, nil)
	require.Error(t, err)
	assert.Nil(t, report)
	assert.Contains(t, err.Error(), "ambiguous check ID")
	assert.Contains(t, err.Error(), "1.1")
}

func TestBuildReportDegradesWhenSelfCheckFails(t *testing.T) {
	// A non-passing check with no annotation would be silently dropped, which
	// would make the totals wrong. The self-check must turn that into a
	// degraded report rather than a half statistic.
	checks := []*Check{
		{ID: "1.1.1", State: FAIL}, // never annotated
		{ID: "1.1.2", State: FAIL, RootCause: &CheckRootCause{Class: RootCauseUnclassified, Detail: "x"}},
	}

	report, err := buildReport(checks, nil)
	require.NoError(t, err)
	require.NotNil(t, report)
	assert.True(t, report.Degraded)
	assert.Nil(t, report.Counts, "a degraded report must not carry partial counts")
	assert.Zero(t, report.TotalNonPassing)
	assert.Empty(t, report.Groups)
	assert.Contains(t, report.Note, "aggregation failed")
}

func TestFileNotFoundStringIsNotCommandMissing(t *testing.T) {
	// Some benchmarks deliberately echo `File not found` when a service file
	// is absent (cis-1.8 node 4.1.2). That must never be read as a missing
	// command.
	c := newRootCauseCheck("4.1.2", FAIL)
	c.ActualValue = "File not found"
	c.auditEvidence = []auditEvidence{{
		Stage:   "audit",
		Command: `/bin/sh -c "if test -e /etc/systemd/system/kubelet.service; then stat -c %U:%G /etc/systemd/system/kubelet.service; else echo \"File not found\"; fi"`,
		Output:  "File not found\n",
	}}

	rc := classifyCheck(c, nil)
	assert.NotEqual(t, RootCauseCommandMissing, rc.Class,
		"a benchmark's own 'File not found' string is not a missing command")
	// There is no audit error and no empty guarded output, so the cause cannot
	// be determined. Reporting it verbatim is correct; guessing a class is not.
	assert.Equal(t, RootCauseUnclassified, rc.Class)
	assert.Contains(t, rc.Detail, "File not found")
}

func TestShellNotFoundStillClassifiedAsCommandMissing(t *testing.T) {
	for _, msg := range []string{
		"/bin/sh: 1: kubectl: not found",
		"sh: etcdctl: not found",
		"bash: line 2: jq: command not found",
	} {
		c := newRootCauseCheck("9.9", FAIL, failedAudit("audit", "x", msg, errors.New("exit status 127")))
		assert.Equal(t, RootCauseCommandMissing, classifyCheck(c, nil).Class, msg)
	}
}
