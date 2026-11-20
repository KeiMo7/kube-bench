package check

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func allChecks(group *Group, c *Check) bool { return true }

func controlsFromYAML(t *testing.T, yaml, nodeType string) *Controls {
	t.Helper()
	c, err := NewControls(NodeType(nodeType), []byte(yaml), "")
	require.NoError(t, err)
	return c
}

const masterSample = `
---
type: "master"
id: "1"
text: "Control Plane Security Configuration"
groups:
- id: "1.1"
  text: "Control Plane Node Configuration Files"
  checks:
  - id: "1.1.1"
    text: "api server file permissions"
    audit: "echo permissions=600"
    tests:
      test_items:
      - flag: "permissions"
        compare:
          op: bitmask
          value: "600"
    remediation: "chmod 600"
    scored: true
  - id: "1.1.2"
    text: "api server file ownership"
    audit: "echo root:root"
    tests:
      test_items:
      - flag: "root:root"
    remediation: "chown root:root"
    scored: true
`

func TestMarkNotApplicable_DoesNotRunChecks(t *testing.T) {
	controls := controlsFromYAML(t, masterSample, "master")

	// No runner is supplied at all: trimming must not touch the audit path, so
	// it can never change a check's own decision logic or thresholds.
	got := controls.MarkNotApplicable(allChecks, ReasonRoleNotObserved, "control plane role not observed")

	assert.Equal(t, 0, got.Fail)
	assert.Equal(t, 0, got.Pass)
	assert.Equal(t, 0, got.Warn)
	assert.Equal(t, 2, got.NotApplicable)
	assert.Equal(t, Summary{NotApplicable: 2}, got)

	for _, g := range controls.Groups {
		for _, c := range g.Checks {
			assert.Equal(t, NOT_APPLICABLE, c.State)
			assert.Equal(t, ReasonRoleNotObserved, c.ReasonCode)
			assert.NotEmpty(t, c.Reason)
		}
	}
}

func TestSummary_SeparatesNotApplicableFromFail(t *testing.T) {
	controls := controlsFromYAML(t, masterSample, "master")

	runner := runnerFunc(func(c *Check) State { return FAIL })
	controls.RunChecks(runner, allChecks, map[string]bool{})

	assert.Equal(t, 2, controls.Summary.Fail)
	assert.Equal(t, 0, controls.Summary.NotApplicable)

	// Now fold a second target whose role is absent into the same report.
	na := controlsFromYAML(t, masterSample, "master")
	na.MarkNotApplicable(allChecks, ReasonRoleNotObserved, "not observed")

	totals := Summary{
		Pass:          controls.Pass + na.Pass,
		Fail:          controls.Fail + na.Fail,
		Warn:          controls.Warn + na.Warn,
		Info:          controls.Info + na.Info,
		NotApplicable: controls.NotApplicable + na.NotApplicable,
	}
	assert.Equal(t, 2, totals.Fail, "trimmed checks must not enter the fail total")
	assert.Equal(t, 2, totals.NotApplicable)
}

func TestDeduplicate_MixedRolesKeepsOneResultWithSources(t *testing.T) {
	master := controlsFromYAML(t, `
---
type: "master"
id: "1"
groups:
- id: "1.1"
  checks:
  - id: "SHARED-1"
    text: "shared control plane check"
    scored: true
`, "master")
	master.RunChecks(runnerFunc(func(c *Check) State { return PASS }), allChecks, map[string]bool{})

	node := controlsFromYAML(t, `
---
type: "node"
id: "4"
groups:
- id: "4.1"
  checks:
  - id: "SHARED-1"
    text: "shared worker check"
    scored: true
  - id: "4.1.1"
    text: "node only"
    scored: true
`, "node")
	node.RunChecks(runnerFunc(func(c *Check) State {
		if c.ID == "SHARED-1" {
			return FAIL
		}
		return PASS
	}), allChecks, map[string]bool{})

	collection := []*Controls{master, node}
	removed := Deduplicate(collection, func(c *Controls) bool { return true })
	assert.Equal(t, 1, removed)

	masterIDs := collectIDs(master)
	nodeIDs := collectIDs(node)
	assert.NotContains(t, masterIDs, "SHARED-1", "the losing occurrence is removed")
	assert.Contains(t, nodeIDs, "SHARED-1", "the more severe result is kept")

	kept := findCheck(node, "SHARED-1")
	require.NotNil(t, kept)
	assert.Equal(t, FAIL, kept.State)
	assert.ElementsMatch(t, []string{"master", "node"}, kept.Sources)
	assert.Equal(t, map[string]string{"master": "PASS", "node": "FAIL"}, kept.SourceStates)

	// Recalculated totals reflect the surviving results only: the master
	// target lost its only check, and the node result is counted once.
	master.RecalculateSummary()
	node.RecalculateSummary()
	assert.Equal(t, 0, master.Pass+master.Fail+master.Warn+master.Info+master.NotApplicable)
	assert.Equal(t, 2, node.Pass+node.Fail+node.Warn+node.Info+node.NotApplicable)
}

func TestDeduplicate_SameIdentifierNoDuplicateTotals(t *testing.T) {
	a := controlsFromYAML(t, `
---
type: "master"
id: "1"
groups:
- id: "1.1"
  checks:
  - id: "X1"
    scored: true
`, "master")
	a.RunChecks(runnerFunc(func(c *Check) State { return PASS }), allChecks, map[string]bool{})

	b := controlsFromYAML(t, `
---
type: "controlplane"
id: "3"
groups:
- id: "3.1"
  checks:
  - id: "X1"
    scored: true
`, "controlplane")
	b.RunChecks(runnerFunc(func(c *Check) State { return PASS }), allChecks, map[string]bool{})

	total := Deduplicate([]*Controls{a, b}, nil)
	assert.Equal(t, 1, total)
	a.RecalculateSummary()
	b.RecalculateSummary()
	assert.Equal(t, 1, a.Pass+b.Pass, "a de-duplicated check is counted exactly once")

	kept := findCheck(a, "X1")
	require.NotNil(t, kept)
	assert.ElementsMatch(t, []string{"master", "controlplane"}, kept.Sources)
}

func TestDeduplicate_LeavesClusterScopedTargetsAlone(t *testing.T) {
	master := controlsFromYAML(t, `
---
type: "master"
id: "1"
groups:
- id: "1.1"
  checks:
  - id: "X1"
    scored: true
`, "master")
	master.RunChecks(runnerFunc(func(c *Check) State { return PASS }), allChecks, map[string]bool{})

	policies := controlsFromYAML(t, `
---
type: "policies"
id: "5"
groups:
- id: "5.1"
  checks:
  - id: "X1"
    scored: true
`, "policies")
	policies.RunChecks(runnerFunc(func(c *Check) State { return FAIL }), allChecks, map[string]bool{})

	removed := Deduplicate([]*Controls{master, policies}, func(c *Controls) bool {
		return c.Type == MASTER || c.Type == CONTROLPLANE || c.Type == NODE || c.Type == ETCD
	})
	assert.Equal(t, 0, removed)
	assert.Contains(t, collectIDs(policies), "X1")
	assert.Contains(t, collectIDs(master), "X1")
}

func TestJUnit_NotApplicableIsSkippedNotFailed(t *testing.T) {
	controls := &Controls{
		Summary: Summary{NotApplicable: 3},
		Groups: []*Group{{
			ID:     "g1",
			Checks: []*Check{{ID: "na", Text: "not applicable", State: NOT_APPLICABLE}},
		}},
	}
	out, err := controls.JUnit()
	require.NoError(t, err)
	s := string(out)
	assert.Contains(t, s, "tests=\"3\"")
	assert.Contains(t, s, "failures=\"0\"")
	assert.Contains(t, s, "<skipped></skipped>")
}

func TestJSON_NewStateIsSelfDescribing(t *testing.T) {
	c := &Check{ID: "1.1.1", State: NOT_APPLICABLE, ReasonCode: ReasonRoleNotObserved, Reason: "role absent"}
	b, err := json.Marshal(c)
	require.NoError(t, err)
	assert.Contains(t, string(b), `"status":"NOT_APPLICABLE"`)
	assert.Contains(t, string(b), `"reason_code":"role_not_observed"`)

	// An old consumer looking only for FAIL must not mistake it for a failure.
	var decoded struct {
		Status string `json:"status"`
	}
	require.NoError(t, json.Unmarshal(b, &decoded))
	assert.NotEqual(t, string(FAIL), decoded.Status)
}

// runnerFunc adapts a function to the Runner interface. Like the real
// defaultRunner it also records the state on the check, which de-duplication
// and report rendering rely on.
type runnerFunc func(*Check) State

func (f runnerFunc) Run(c *Check) State {
	c.State = f(c)
	return c.State
}

func collectIDs(c *Controls) []string {
	var ids []string
	for _, g := range c.Groups {
		for _, ch := range g.Checks {
			ids = append(ids, ch.ID)
		}
	}
	return ids
}

func findCheck(c *Controls, id string) *Check {
	for _, g := range c.Groups {
		for _, ch := range g.Checks {
			if ch.ID == id {
				return ch
			}
		}
	}
	return nil
}
