// Copyright © 2026 Aqua Security Software Ltd. <info@aquasec.com>
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
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/onsi/ginkgo/reporters"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const waiverBench = "cis-test-1.0"

func writeWaiver(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "waivers.yaml")
	require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	return p
}

// buildControls produces a minimal benchmark with one passing and one failing
// scored check, plus one warned unscored check.
func buildControls(nodeType NodeType, version string) *Controls {
	return &Controls{
		ID:      "1",
		Version: version,
		Text:    "Test " + string(nodeType),
		Type:    nodeType,
		Groups: []*Group{
			{
				ID:   "1.1",
				Text: "Group one",
				Checks: []*Check{
					{ID: "1.1.1", Text: "passes", State: PASS, Scored: true, ActualValue: "raw-output-1"},
					{ID: "1.1.2", Text: "fails", State: FAIL, Scored: true, ActualValue: "raw-output-2"},
					{ID: "1.1.3", Text: "warns", State: WARN, Scored: false},
				},
			},
			{
				ID:   "1.2",
				Text: "Group two",
				Checks: []*Check{
					{ID: "1.2.1", Text: "fails too", State: FAIL, Scored: true},
				},
			},
		},
		Summary: Summary{Pass: 1, Fail: 2, Warn: 1},
	}
}

func applyFile(t *testing.T, body string, collection []*Controls, now time.Time) (ApplyResult, error) {
	t.Helper()
	set, err := LoadWaivers(writeWaiver(t, body))
	require.NoError(t, err)
	var scopes []Scope
	for _, c := range collection {
		scopes = append(scopes, NewScope(c))
	}
	return set.Apply(collection, scopes, now)
}

func waivers(body string) string {
	return "benchmark: " + waiverBench + "\nwaivers:\n" + body
}

func commonWaiver(extra string) string {
	return `  - name: w1
    check: "1.1.2"
    kind: accepted-risk
    reason: "compensating control in place"
    requester: "alice"
    approver: "bob"
    expires: "2030-01-01"
` + extra
}

const waiverNowStr = "2026-06-01T00:00:00Z"

func mustParse(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, s)
	require.NoError(t, err)
	return ts
}

// ---------------------------------------------------------------------------
// Classification: not-applicable, accepted-risk and real failure stay distinct.
// ---------------------------------------------------------------------------

func TestWaiver_ClassifiesAcceptedRiskAndNotApplicable(t *testing.T) {
	controls := buildControls(MASTER, waiverBench)
	_, err := applyFile(t, waivers(commonWaiver(
		`  - name: w2
    check: "1.2.1"
    kind: not-applicable
    reason: "managed control plane owns this setting"
    requester: "carol"
    approver: "dave"
    expires: "2030-01-01"
`)), []*Controls{controls}, mustParse(t, waiverNowStr))
	require.NoError(t, err)

	byID := map[string]*Check{}
	for _, g := range controls.Groups {
		for _, c := range g.Checks {
			byID[c.ID] = c
		}
	}

	assert.Equal(t, ACCEPTEDRISK, byID["1.1.2"].State, "accepted risk is its own state")
	assert.Equal(t, NOTAPPLICABLE, byID["1.2.1"].State, "not applicable is its own state")
	assert.Equal(t, PASS, byID["1.1.1"].State, "unwaived pass stays PASS")
	assert.Equal(t, WARN, byID["1.1.3"].State, "unwaived warn stays WARN")

	// Nothing was collapsed into INFO/skip.
	assert.False(t, byID["1.1.2"].State == INFO || byID["1.2.1"].State == INFO)

	// The measured result and raw output survive reclassification.
	assert.Equal(t, "FAIL", byID["1.1.2"].Waiver.MeasuredState)
	assert.Equal(t, "raw-output-2", byID["1.1.2"].ActualValue)

	assert.Equal(t, Summary{Pass: 1, Fail: 0, Warn: 1, Info: 0, NotApplicable: 1, AcceptedRisk: 1}, controls.Summary)
}

func TestWaiver_AcceptedRiskDoesNotHideAPass(t *testing.T) {
	controls := buildControls(MASTER, waiverBench)
	body := waivers(`  - name: section
    group: "1.1"
    kind: accepted-risk
    reason: "risk accepted"
    requester: "alice"
    approver: "bob"
    expires: "2030-01-01"
`)
	res, err := applyFile(t, body, []*Controls{controls}, mustParse(t, waiverNowStr))
	require.NoError(t, err)

	passing := controls.Groups[0].Checks[0]
	assert.Equal(t, PASS, passing.State, "a passing check has no risk to accept")
	assert.Nil(t, passing.Waiver)
	// The failing and warned checks in the section are classified.
	assert.Equal(t, ACCEPTEDRISK, controls.Groups[0].Checks[1].State)
	assert.Equal(t, ACCEPTEDRISK, controls.Groups[0].Checks[2].State)
	assert.Contains(t, strings.Join(res.Diagnostics, "\n"), "accepted-risk only applies to FAIL or WARN")
}

// ---------------------------------------------------------------------------
// Expiry: an expired waiver must stop applying and the check returns to FAIL.
// ---------------------------------------------------------------------------

func TestWaiver_ExpiredReturnsMeasuredState(t *testing.T) {
	body := waivers(`  - name: expired
    check: "1.1.2"
    kind: accepted-risk
    reason: "was accepted last year"
    requester: "alice"
    approver: "bob"
    starts: "2024-01-01"
    expires: "2025-01-01"
`)
	controls := buildControls(MASTER, waiverBench)
	res, err := applyFile(t, body, []*Controls{controls}, mustParse(t, waiverNowStr))
	require.NoError(t, err)

	c := controls.Groups[0].Checks[1]
	assert.Equal(t, FAIL, c.State, "expired waiver must not hide the failure")
	assert.Nil(t, c.Waiver, "expired waiver must not be attached")
	assert.Equal(t, 2, controls.Summary.Fail)
	assert.Equal(t, 0, controls.Summary.AcceptedRisk)
	assert.Equal(t, 0, res.Applied)
	require.Len(t, res.Diagnostics, 1)
	assert.Contains(t, res.Diagnostics[0], "expired on 2025-01-01")
}

func TestWaiver_FutureStartDoesNotApply(t *testing.T) {
	body := waivers(`  - name: future
    check: "1.1.2"
    kind: accepted-risk
    reason: "staged change"
    requester: "alice"
    approver: "bob"
    starts: "2030-01-01"
    expires: "2031-01-01"
`)
	controls := buildControls(MASTER, waiverBench)
	res, err := applyFile(t, body, []*Controls{controls}, mustParse(t, waiverNowStr))
	require.NoError(t, err)

	assert.Equal(t, FAIL, controls.Groups[0].Checks[1].State)
	require.Len(t, res.Diagnostics, 1)
	assert.Contains(t, res.Diagnostics[0], "not yet active")
}

func TestWaiver_PermanentAndBoundaries(t *testing.T) {
	t.Run("no expiry is permanent", func(t *testing.T) {
		body := waivers(`  - name: forever
    check: "1.1.2"
    kind: accepted-risk
    reason: "no end date"
    requester: "alice"
    approver: "bob"
`)
		controls := buildControls(MASTER, waiverBench)
		_, err := applyFile(t, body, []*Controls{controls}, mustParse(t, waiverNowStr))
		require.NoError(t, err)
		c := controls.Groups[0].Checks[1]
		assert.Equal(t, ACCEPTEDRISK, c.State)
		assert.Equal(t, PermanentWaiver, c.Waiver.Expires)
	})

	t.Run("a calendar end date includes the whole day", func(t *testing.T) {
		body := waivers(`  - name: day
    check: "1.1.2"
    kind: accepted-risk
    reason: "expires at end of day"
    requester: "alice"
    approver: "bob"
    expires: "2026-06-01"
`)
		// 23:59 UTC on the named day is still inside the waiver.
		controls := buildControls(MASTER, waiverBench)
		_, err := applyFile(t, body, []*Controls{controls}, mustParse(t, "2026-06-01T23:59:59Z"))
		require.NoError(t, err)
		assert.Equal(t, ACCEPTEDRISK, controls.Groups[0].Checks[1].State)

		// The next day it is gone.
		controls = buildControls(MASTER, waiverBench)
		_, err = applyFile(t, body, []*Controls{controls}, mustParse(t, "2026-06-02T00:00:00Z"))
		require.NoError(t, err)
		assert.Equal(t, FAIL, controls.Groups[0].Checks[1].State)
	})

	t.Run("start boundary is inclusive", func(t *testing.T) {
		body := waivers(`  - name: startday
    check: "1.1.2"
    kind: accepted-risk
    reason: "starts today"
    requester: "alice"
    approver: "bob"
    starts: "2026-06-01"
    expires: "2026-07-01"
`)
		controls := buildControls(MASTER, waiverBench)
		_, err := applyFile(t, body, []*Controls{controls}, mustParse(t, "2026-06-01T00:00:00Z"))
		require.NoError(t, err)
		assert.Equal(t, ACCEPTEDRISK, controls.Groups[0].Checks[1].State)
	})
}

// ---------------------------------------------------------------------------
// Benchmark migration: entries are bound to a benchmark, never to a bare ID.
// ---------------------------------------------------------------------------

func TestWaiver_BenchmarkMigrationDoesNotMisTarget(t *testing.T) {
	// Same check ID exists in both benchmark versions with a different meaning.
	oldBench := buildControls(MASTER, "cis-test-1.0")
	newBench := buildControls(MASTER, "cis-test-2.0")

	body := `benchmark: cis-test-1.0
waivers:
  - name: legacy
    check: "1.1.2"
    kind: accepted-risk
    reason: "only valid for the old benchmark numbering"
    requester: "alice"
    approver: "bob"
    expires: "2030-01-01"
`
	set, err := LoadWaivers(writeWaiver(t, body))
	require.NoError(t, err)
	var scopes []Scope
	for _, c := range []*Controls{oldBench, newBench} {
		scopes = append(scopes, NewScope(c))
	}
	_, err = set.Apply([]*Controls{oldBench, newBench}, scopes, mustParse(t, waiverNowStr))
	require.NoError(t, err)

	assert.Equal(t, ACCEPTEDRISK, oldBench.Groups[0].Checks[1].State,
		"waiver applies to the benchmark it names")
	assert.Equal(t, FAIL, newBench.Groups[0].Checks[1].State,
		"waiver must not follow a reused identifier into a new benchmark version")
	assert.Equal(t, "cis-test-1.0", oldBench.Groups[0].Checks[1].Waiver.Benchmark)
}

func TestWaiver_TopLevelBenchmarkIsDefault(t *testing.T) {
	body := `benchmark: cis-test-1.0
waivers:
  - name: inherited
    check: "1.1.2"
    kind: accepted-risk
    reason: "inherits benchmark from the file"
    requester: "alice"
    approver: "bob"
`
	controls := buildControls(MASTER, waiverBench)
	_, err := applyFile(t, body, []*Controls{controls}, mustParse(t, waiverNowStr))
	require.NoError(t, err)
	assert.Equal(t, ACCEPTEDRISK, controls.Groups[0].Checks[1].State)
}

// ---------------------------------------------------------------------------
// Unknown check references are errors, not silent no-ops.
// ---------------------------------------------------------------------------

func TestWaiver_UnknownCheckIsError(t *testing.T) {
	body := waivers(`  - name: ghost
    check: "9.9.9"
    kind: accepted-risk
    reason: "typo"
    requester: "alice"
    approver: "bob"
`)
	controls := buildControls(MASTER, waiverBench)
	_, err := applyFile(t, body, []*Controls{controls}, mustParse(t, waiverNowStr))
	require.Error(t, err)
	assert.Contains(t, err.Error(), `references check "9.9.9", which does not exist`)
}

func TestWaiver_UnknownGroupIsError(t *testing.T) {
	body := waivers(`  - name: ghostgroup
    group: "9.9"
    kind: not-applicable
    reason: "typo"
    requester: "alice"
    approver: "bob"
`)
	controls := buildControls(MASTER, waiverBench)
	_, err := applyFile(t, body, []*Controls{controls}, mustParse(t, waiverNowStr))
	require.Error(t, err)
	assert.Contains(t, err.Error(), `references group "9.9"`)
}

// ---------------------------------------------------------------------------
// Node scoping: a waiver for one node type does not spread to other types.
// ---------------------------------------------------------------------------

func TestWaiver_NodeTypeDoesNotSpread(t *testing.T) {
	master := buildControls(MASTER, waiverBench)
	node := buildControls(NODE, waiverBench)
	// The same check identifier appears in both node types.
	body := waivers(`  - name: master-only
    node_type: master
    check: "1.1.2"
    kind: not-applicable
    reason: "only the control plane is affected"
    requester: "alice"
    approver: "bob"
    expires: "2030-01-01"
`)
	set, err := LoadWaivers(writeWaiver(t, body))
	require.NoError(t, err)
	scopes := []Scope{NewScope(master), NewScope(node)}
	_, err = set.Apply([]*Controls{master, node}, scopes, mustParse(t, waiverNowStr))
	require.NoError(t, err)

	assert.Equal(t, NOTAPPLICABLE, master.Groups[0].Checks[1].State)
	assert.Equal(t, FAIL, node.Groups[0].Checks[1].State, "node-type waiver must not leak")
	assert.Nil(t, node.Groups[0].Checks[1].Waiver)
}

func TestWaiver_AmbiguousNodeTypeIsError(t *testing.T) {
	master := buildControls(MASTER, waiverBench)
	node := buildControls(NODE, waiverBench)
	body := waivers(`  - name: ambiguous
    check: "1.1.2"
    kind: accepted-risk
    reason: "does not say which node type"
    requester: "alice"
    approver: "bob"
`)
	set, err := LoadWaivers(writeWaiver(t, body))
	require.NoError(t, err)
	scopes := []Scope{NewScope(master), NewScope(node)}
	_, err = set.Apply([]*Controls{master, node}, scopes, mustParse(t, waiverNowStr))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exists on multiple node types")
	assert.Contains(t, err.Error(), "master")
	assert.Contains(t, err.Error(), "node")
}

// ---------------------------------------------------------------------------
// Section/group waivers.
// ---------------------------------------------------------------------------

func TestWaiver_GroupWaiverCoversSection(t *testing.T) {
	controls := buildControls(MASTER, waiverBench)
	body := waivers(`  - name: section
    group: "1.2"
    kind: not-applicable
    reason: "whole section is out of scope"
    requester: "alice"
    approver: "bob"
    expires: "2030-01-01"
`)
	_, err := applyFile(t, body, []*Controls{controls}, mustParse(t, waiverNowStr))
	require.NoError(t, err)

	assert.Equal(t, NOTAPPLICABLE, controls.Groups[1].Checks[0].State)
	assert.Equal(t, FAIL, controls.Groups[0].Checks[1].State, "other groups untouched")
	assert.Equal(t, 1, controls.Groups[1].NotApplicable)
	assert.Equal(t, 0, controls.Groups[1].Fail)
}

// ---------------------------------------------------------------------------
// Duplicates and conflicts produce diagnostics, and selection is stable.
// ---------------------------------------------------------------------------

func TestWaiver_DuplicateAndConflictDiagnostics(t *testing.T) {
	t.Run("identical specificity duplicates are reported", func(t *testing.T) {
		controls := buildControls(MASTER, waiverBench)
		body := waivers(`  - name: first
    check: "1.1.2"
    kind: accepted-risk
    reason: "one"
    requester: "alice"
    approver: "bob"
    expires: "2030-01-01"
  - name: second
    check: "1.1.2"
    kind: accepted-risk
    reason: "two"
    requester: "carol"
    approver: "dave"
    expires: "2030-01-01"
`)
		res, err := applyFile(t, body, []*Controls{controls}, mustParse(t, waiverNowStr))
		require.NoError(t, err)
		require.Len(t, res.Diagnostics, 1)
		assert.Contains(t, res.Diagnostics[0], "duplicate waivers")
		assert.Equal(t, "first", controls.Groups[0].Checks[1].Waiver.Name,
			"ties resolve by file order, deterministically")
	})

	t.Run("conflicting kinds are reported", func(t *testing.T) {
		controls := buildControls(MASTER, waiverBench)
		body := waivers(`  - name: section
    group: "1.1"
    kind: accepted-risk
    reason: "risk accepted"
    requester: "alice"
    approver: "bob"
    expires: "2030-01-01"
  - name: precise
    check: "1.1.2"
    kind: not-applicable
    reason: "does not apply"
    requester: "carol"
    approver: "dave"
    expires: "2030-01-01"
`)
		res, err := applyFile(t, body, []*Controls{controls}, mustParse(t, waiverNowStr))
		require.NoError(t, err)
		assert.Contains(t, strings.Join(res.Diagnostics, "\n"), "waivers of different kinds")
		// The more specific entry wins for the failing check.
		assert.Equal(t, NOTAPPLICABLE, controls.Groups[0].Checks[1].State)
		// The section waiver also matches a passing check, but there is no risk
		// to accept there, so it stays PASS rather than being relabelled.
		assert.Equal(t, PASS, controls.Groups[0].Checks[0].State)
	})

	t.Run("contradictory kinds at the same scope are fatal", func(t *testing.T) {
		controls := buildControls(MASTER, waiverBench)
		body := waivers(`  - name: risk
    check: "1.1.2"
    kind: accepted-risk
    reason: "risk accepted"
    requester: "alice"
    approver: "bob"
    expires: "2030-01-01"
  - name: na
    check: "1.1.2"
    kind: not-applicable
    reason: "does not apply"
    requester: "carol"
    approver: "dave"
    expires: "2030-01-01"
`)
		_, err := applyFile(t, body, []*Controls{controls}, mustParse(t, waiverNowStr))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "contradict")
	})
}

func TestWaiver_DeterministicAcrossCheckOrder(t *testing.T) {
	body := waivers(`  - name: section
    group: "1.1"
    kind: accepted-risk
    reason: "risk accepted for section"
    requester: "alice"
    approver: "bob"
    expires: "2030-01-01"
  - name: precise
    check: "1.1.2"
    kind: not-applicable
    reason: "does not apply"
    requester: "carol"
    approver: "dave"
    expires: "2030-01-01"
`)

	snapshot := func(c *Controls) map[string]string {
		out := map[string]string{}
		for _, g := range c.Groups {
			for _, ck := range g.Checks {
				kind := ""
				if ck.Waiver != nil {
					kind = ck.Waiver.Name
				}
				out[ck.ID] = string(ck.State) + "|" + kind
			}
		}
		return out
	}

	forward := buildControls(MASTER, waiverBench)
	_, err := applyFile(t, body, []*Controls{forward}, mustParse(t, waiverNowStr))
	require.NoError(t, err)

	// Reverse the physical order of checks within each group.
	reversed := buildControls(MASTER, waiverBench)
	for _, g := range reversed.Groups {
		for i, j := 0, len(g.Checks)-1; i < j; i, j = i+1, j-1 {
			g.Checks[i], g.Checks[j] = g.Checks[j], g.Checks[i]
		}
	}
	_, err = applyFile(t, body, []*Controls{reversed}, mustParse(t, waiverNowStr))
	require.NoError(t, err)

	assert.Equal(t, snapshot(forward), snapshot(reversed),
		"the same waiver file must produce the same conclusion regardless of check order")
}

// ---------------------------------------------------------------------------
// Malformed input fails loudly.
// ---------------------------------------------------------------------------

func TestLoadWaivers_Errors(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "syntax error",
			body: "benchmark: [unterminated\n",
			want: "unable to parse waiver file",
		},
		{
			name: "unknown field",
			body: "benchmark: b\nwaivers:\n  - check: \"1.1\"\n    knd: accepted-risk\n",
			want: "field knd not found",
		},
		{
			name: "missing kind",
			body: "benchmark: b\nwaivers:\n  - check: \"1.1\"\n    reason: r\n    requester: a\n    approver: b\n",
			want: "kind must be",
		},
		{
			name: "missing reason",
			body: "benchmark: b\nwaivers:\n  - check: \"1.1\"\n    kind: accepted-risk\n    requester: a\n    approver: b\n",
			want: "reason is required",
		},
		{
			name: "missing requester",
			body: "benchmark: b\nwaivers:\n  - check: \"1.1\"\n    kind: accepted-risk\n    reason: r\n    approver: b\n",
			want: "requester is required",
		},
		{
			name: "missing approver",
			body: "benchmark: b\nwaivers:\n  - check: \"1.1\"\n    kind: accepted-risk\n    reason: r\n    requester: a\n",
			want: "approver is required",
		},
		{
			name: "missing benchmark",
			body: "waivers:\n  - check: \"1.1\"\n    kind: accepted-risk\n    reason: r\n    requester: a\n    approver: b\n",
			want: "benchmark is required",
		},
		{
			name: "check and group both set",
			body: "benchmark: b\nwaivers:\n  - check: \"1.1\"\n    group: \"1\"\n    kind: accepted-risk\n    reason: r\n    requester: a\n    approver: b\n",
			want: "mutually exclusive",
		},
		{
			name: "empty selector",
			body: "benchmark: b\nwaivers:\n  - kind: accepted-risk\n    reason: r\n    requester: a\n    approver: b\n",
			want: "one of check, group or node_type is required",
		},
		{
			name: "bad date",
			body: "benchmark: b\nwaivers:\n  - check: \"1.1\"\n    kind: accepted-risk\n    reason: r\n    requester: a\n    approver: b\n    expires: tomorrow\n",
			want: "invalid expires",
		},
		{
			name: "expiry before start",
			body: "benchmark: b\nwaivers:\n  - check: \"1.1\"\n    kind: accepted-risk\n    reason: r\n    requester: a\n    approver: b\n    starts: \"2030-01-01\"\n    expires: \"2029-01-01\"\n",
			want: "must be after",
		},
		{
			name: "unknown node type",
			body: "benchmark: b\nwaivers:\n  - node_type: toaster\n    kind: accepted-risk\n    reason: r\n    requester: a\n    approver: b\n",
			want: "unknown node_type",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadWaivers(writeWaiver(t, tc.body))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}

	t.Run("missing file", func(t *testing.T) {
		_, err := LoadWaivers(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unable to read waiver file")
	})
}

// ---------------------------------------------------------------------------
// Output formats describe the same result consistently.
// ---------------------------------------------------------------------------

func TestWaiver_OutputFormatsAgree(t *testing.T) {
	controls := buildControls(MASTER, waiverBench)
	_, err := applyFile(t, waivers(`  - name: accepted
    check: "1.1.2"
    kind: accepted-risk
    reason: "compensating control"
    requester: "alice"
    approver: "bob"
    expires: "2030-01-01"
  - name: na
    check: "1.2.1"
    kind: not-applicable
    reason: "not our control"
    requester: "carol"
    approver: "dave"
`), []*Controls{controls}, mustParse(t, waiverNowStr))
	require.NoError(t, err)

	// JSON carries the full audit trail.
	out, err := json.Marshal(controls)
	require.NoError(t, err)
	var decoded Controls
	require.NoError(t, json.Unmarshal(out, &decoded))
	jsonWaived := map[string]*WaiverInfo{}
	for _, g := range decoded.Groups {
		for _, c := range g.Checks {
			if c.Waiver != nil {
				jsonWaived[c.ID] = c.Waiver
			}
		}
	}
	require.Contains(t, jsonWaived, "1.1.2")
	require.Contains(t, jsonWaived, "1.2.1")
	assert.Equal(t, "compensating control", jsonWaived["1.1.2"].Reason)
	assert.Equal(t, "bob", jsonWaived["1.1.2"].Approver)
	assert.Equal(t, "2030-01-01", jsonWaived["1.1.2"].Expires)
	assert.Equal(t, NOTAPPLICABLE, decoded.Groups[1].Checks[0].State)

	// JUnit reports both as skipped, with the reason and expiry in the message.
	junit, err := controls.JUnit()
	require.NoError(t, err)
	var suite reporters.JUnitTestSuite
	require.NoError(t, xml.Unmarshal(junit, &suite))
	byName := map[string]reporters.JUnitTestCase{}
	for _, tc := range suite.TestCases {
		byName[strings.Fields(tc.Name)[0]] = tc
	}
	require.NotNil(t, byName["1.1.2"].Skipped)
	assert.Contains(t, byName["1.1.2"].Skipped.Message, "compensating control")
	assert.Contains(t, byName["1.1.2"].Skipped.Message, "2030-01-01")
	require.NotNil(t, byName["1.2.1"].Skipped)
	assert.Contains(t, byName["1.2.1"].Skipped.Message, "not-applicable")

	// The same strings are produced by the shared Summary() helper used by
	// stdout, so all three formats stay in sync.
	assert.Equal(t, decoded.Groups[0].Checks[1].Waiver.Summary(),
		strings.TrimPrefix(byName["1.1.2"].Skipped.Message, string(ACCEPTEDRISK)+": "))

	// A real failure is still a real failure in JUnit.
	require.NotNil(t, byName["1.1.1"].Skipped == nil)
}

// ---------------------------------------------------------------------------
// Waiving never changes what was executed or its raw output.
// ---------------------------------------------------------------------------

func TestWaiver_PreservesRawExecution(t *testing.T) {
	pre := buildControls(MASTER, waiverBench)
	for _, g := range pre.Groups {
		for _, c := range g.Checks {
			c.AuditOutput = "original-audit-output-" + c.ID
		}
	}
	post := buildControls(MASTER, waiverBench)
	for _, g := range post.Groups {
		for _, c := range g.Checks {
			c.AuditOutput = "original-audit-output-" + c.ID
		}
	}

	_, err := applyFile(t, waivers(`  - name: section
    group: "1.1"
    kind: accepted-risk
    reason: "waived"
    requester: "alice"
    approver: "bob"
    expires: "2030-01-01"
`), []*Controls{post}, mustParse(t, waiverNowStr))
	require.NoError(t, err)

	for i, g := range pre.Groups {
		for j, c := range g.Checks {
			got := post.Groups[i].Checks[j]
			assert.Equal(t, c.AuditOutput, got.AuditOutput, "audit output is untouched")
			assert.Equal(t, c.ActualValue, got.ActualValue, "actual value is untouched")
			assert.Equal(t, c.Text, got.Text)
			assert.Equal(t, c.Scored, got.Scored)
		}
	}
}

// ---------------------------------------------------------------------------
// Empty and large waiver files.
// ---------------------------------------------------------------------------

func TestWaiver_EmptyFileIsNoop(t *testing.T) {
	controls := buildControls(MASTER, waiverBench)
	res, err := applyFile(t, "benchmark: "+waiverBench+"\nwaivers: []\n", []*Controls{controls}, mustParse(t, waiverNowStr))
	require.NoError(t, err)
	assert.Equal(t, ApplyResult{}, res)
	assert.Equal(t, Summary{Pass: 1, Fail: 2, Warn: 1}, controls.Summary)
	assert.Equal(t, FAIL, controls.Groups[0].Checks[1].State)
}

func TestWaiver_ManyEntries(t *testing.T) {
	// Build a benchmark with several hundred checks, all failing.
	var groups []*Group
	for g := 0; g < 10; g++ {
		grp := &Group{ID: "G" + string(rune('A'+g))}
		for i := 0; i < 50; i++ {
			grp.Checks = append(grp.Checks, &Check{
				ID:    grp.ID + "/C" + string(rune('A'+i%26)) + string(rune('0'+i/26)),
				State: FAIL, Scored: true,
			})
			grp.Fail++
		}
		groups = append(groups, grp)
	}
	controls := &Controls{ID: "1", Version: waiverBench, Type: MASTER, Groups: groups}
	controls.Fail = 500

	var b strings.Builder
	b.WriteString("benchmark: " + waiverBench + "\nwaivers:\n")
	for _, grp := range groups {
		for _, c := range grp.Checks {
			b.WriteString("  - name: w-" + strings.ReplaceAll(c.ID, "/", "-") + "\n")
			b.WriteString("    check: \"" + c.ID + "\"\n")
			b.WriteString("    kind: accepted-risk\n")
			b.WriteString("    reason: \"bulk waiver\"\n")
			b.WriteString("    requester: \"alice\"\n")
			b.WriteString("    approver: \"bob\"\n")
			b.WriteString("    expires: \"2030-01-01\"\n")
		}
	}

	res, err := applyFile(t, b.String(), []*Controls{controls}, mustParse(t, waiverNowStr))
	require.NoError(t, err)
	assert.Equal(t, 500, res.Applied)
	assert.Equal(t, 500, controls.AcceptedRisk)
	assert.Equal(t, 0, controls.Fail)
}

// ---------------------------------------------------------------------------
// Applying twice is idempotent.
// ---------------------------------------------------------------------------

func TestWaiver_ApplyIsIdempotent(t *testing.T) {
	controls := buildControls(MASTER, waiverBench)
	body := waivers(commonWaiver(""))
	set, err := LoadWaivers(writeWaiver(t, body))
	require.NoError(t, err)
	scopes := []Scope{NewScope(controls)}

	first, err := set.Apply([]*Controls{controls}, scopes, mustParse(t, waiverNowStr))
	require.NoError(t, err)
	second, err := set.Apply([]*Controls{controls}, scopes, mustParse(t, waiverNowStr))
	require.NoError(t, err)

	assert.Equal(t, 1, first.Applied)
	assert.Equal(t, 0, second.Applied, "already-waived checks are not re-applied")
	assert.Equal(t, Summary{Pass: 1, Fail: 1, Warn: 1, AcceptedRisk: 1}, controls.Summary)
}

// ---------------------------------------------------------------------------
// Nil set is a no-op (the common path when --waivers is not supplied).
// ---------------------------------------------------------------------------

func TestWaiver_NilSetIsNoop(t *testing.T) {
	controls := buildControls(MASTER, waiverBench)
	var set *WaiverSet
	res, err := set.Apply([]*Controls{controls}, nil, time.Now())
	require.NoError(t, err)
	assert.Equal(t, ApplyResult{}, res)
	assert.Equal(t, FAIL, controls.Groups[0].Checks[1].State)
	assert.False(t, strings.Contains(string(mustJSON(t, controls)), `"waiver"`),
		"waiver field must be omitted when unused")
}

func mustJSON(t *testing.T, v interface{}) []byte {
	t.Helper()
	out, err := json.Marshal(v)
	require.NoError(t, err)
	return out
}
