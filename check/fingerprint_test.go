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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func newFingerprintCheck() *Check {
	return &Check{
		ID:   "1.1.1",
		Type: "",
		Tests: &tests{
			BinOp: and,
			TestItems: []*testItem{
				{
					Flag: "permissions",
					Set:  true,
					Compare: compare{
						Op:    "bitmask",
						Value: "600",
					},
				},
			},
		},
		Scored: true,
	}
}

func TestComputeFingerprint_StableAndComplete(t *testing.T) {
	c := newFingerprintCheck()
	f1 := c.ComputeFingerprint("k3s-cis-1.10")
	f2 := c.ComputeFingerprint("k3s-cis-1.10")

	assert.Equal(t, "1.1.1", f1.CheckID)
	assert.Equal(t, "k3s-cis-1.10", f1.RuleSetVersion)
	assert.NotEmpty(t, f1.ConditionHash)
	assert.Equal(t, f1.ConditionHash, f2.ConditionHash, "same rule must hash identically")
	assert.NotEmpty(t, f1.Condition)

	// The canonical condition must contain the decision elements and no
	// runtime state.
	assert.Contains(t, f1.Condition, `"op":"bitmask"`)
	assert.Contains(t, f1.Condition, `"value":"600"`)
	assert.NotContains(t, f1.Condition, "actual")
}

func TestComputeFingerprint_DetectsConditionTightening(t *testing.T) {
	old := newFingerprintCheck() // 600
	tightened := newFingerprintCheck()
	tightened.Tests.TestItems[0].Compare.Value = "644"

	hOld := old.ComputeFingerprint("k3s-cis-1.10").ConditionHash
	hNew := tightened.ComputeFingerprint("k3s-cis-1.11").ConditionHash
	assert.NotEqual(t, hOld, hNew, "a tightened compare value must change the fingerprint")
}

func TestComputeFingerprint_DetectsScoredAndTypeChanges(t *testing.T) {
	base := newFingerprintCheck()
	baseHash := base.ComputeFingerprint("v1").ConditionHash

	rescored := newFingerprintCheck()
	rescored.Scored = false
	assert.NotEqual(t, baseHash, rescored.ComputeFingerprint("v1").ConditionHash,
		"scored flag is part of the decision condition")

	manual := newFingerprintCheck()
	manual.Type = MANUAL
	assert.NotEqual(t, baseHash, manual.ComputeFingerprint("v1").ConditionHash,
		"manual/skip type is part of the decision condition")
}

func TestComputeFingerprint_RuntimeOutputDoesNotChangeHash(t *testing.T) {
	c1 := newFingerprintCheck()
	c2 := newFingerprintCheck()
	c2.State = FAIL
	c2.ActualValue = "permissions=644\n"
	c2.Reason = "something"
	c2.ExpectedResult = "bitmask 600"

	assert.Equal(t, c1.ComputeFingerprint("v").ConditionHash, c2.ComputeFingerprint("v").ConditionHash,
		"runtime results must never influence the rule fingerprint")
}

func TestComputeFingerprint_NoTestsStillRenders(t *testing.T) {
	c := &Check{ID: "9.9.9", Scored: false}
	f := c.ComputeFingerprint("v")
	assert.NotEmpty(t, f.ConditionHash)
	assert.True(t, strings.HasPrefix(f.Condition, "{"))
}

// RunChecks must attach a fingerprint to every emitted check, and the
// fingerprint's rule set version must come from the Controls section.
func TestRunChecksAttachesFingerprint(t *testing.T) {
	input := []byte(`
type: "master"
groups:
- id: G1
  checks:
  - id: 1.1.1
    text: "sample"
    audit: "echo permissions=600"
    tests:
      test_items:
      - flag: "permissions"
        compare:
          op: bitmask
          value: "600"
    scored: true
`)
	controls, err := NewControls(MASTER, input, "")
	assert.NoError(t, err)
	controls.Version = "k3s-cis-1.10"

	controls.RunChecks(NewRunner(), func(g *Group, c *Check) bool { return true }, map[string]bool{})

	assert.Len(t, controls.Groups, 1)
	assert.Len(t, controls.Groups[0].Checks, 1)
	fp := controls.Groups[0].Checks[0].RuleFingerprint
	assert.NotNil(t, fp)
	assert.Equal(t, "1.1.1", fp.CheckID)
	assert.Equal(t, "k3s-cis-1.10", fp.RuleSetVersion)
	assert.NotEmpty(t, fp.ConditionHash)
}

// Fingerprints must survive JSON marshalling with the additive field name.
func TestFingerprintJSONShape(t *testing.T) {
	c := newFingerprintCheck()
	c.RuleFingerprint = c.ComputeFingerprint("cis-1.10")
	raw, err := json.Marshal(c)
	assert.NoError(t, err)
	s := string(raw)
	assert.Contains(t, s, `"rule_fingerprint":{`)
	assert.Contains(t, s, `"condition_hash"`)
	assert.Contains(t, s, `"rule_set_version":"cis-1.10"`)
}
