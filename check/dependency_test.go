package check

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type functionRunner func(*Check) State

func (f functionRunner) Run(check *Check) State {
	return f(check)
}

func TestValidateDependenciesRejectsMissingAndCyclesAtLoad(t *testing.T) {
	t.Run("missing dependency", func(t *testing.T) {
		input := []byte(`
type: master
groups:
- id: G1
  checks:
  - id: A
    depends_on: missing
`)
		_, err := NewControls(MASTER, input, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), `check "A" depends on missing check "missing"`)
	})

	t.Run("cycle lists the complete loop", func(t *testing.T) {
		input := []byte(`
type: master
groups:
- id: G1
  checks:
  - id: A
    depends_on: [B]
  - id: B
    requires:
    - id: C
  - id: C
    depends_on: A
`)
		_, err := NewControls(MASTER, input, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "dependency cycle detected: A -> B -> C -> A")
	})
}

func TestRunChecksWithDependenciesGatesAndAuditsTransitions(t *testing.T) {
	input := []byte(`
version: "cis-test"
type: master
groups:
- id: G1
  checks:
  - id: A
  - id: B
    depends_on: [A]
  - id: C
    depends_on: [B]
  - id: D
    type: skip
  - id: E
    applicable: false
  - id: F
`)
	controls, err := NewControls(MASTER, input, "")
	require.NoError(t, err)

	runAll := func(*Group, *Check) bool { return true }
	dependencyFail := functionRunner(func(check *Check) State {
		if check.ID == "A" {
			return FAIL
		}
		return PASS
	})

	summary := controls.RunChecksWithOptions(dependencyFail, runAll, nil, RunOptions{DependencyChecking: true})
	assert.Equal(t, 1, summary.Pass)
	assert.Equal(t, 1, summary.Fail)
	assert.Equal(t, 2, summary.NotExecuted)
	assert.Equal(t, 1, summary.Skip)
	assert.Equal(t, 1, summary.NotApplicable)
	assert.Equal(t, 2, summary.NotExecutedReasons[ReasonPrerequisiteFailed])

	checks := checksByID(controls)
	assert.Equal(t, NOT_EXECUTED, checks["B"].State)
	assert.Equal(t, ReasonPrerequisiteFailed, checks["B"].ReasonCategory)
	assert.Equal(t, NOT_EXECUTED, checks["C"].State)
	assert.Equal(t, SKIPPED, checks["D"].State)
	assert.Equal(t, NOT_APPLICABLE, checks["E"].State)
	assert.Equal(t, PASS, checks["F"].State)

	bAudit := controls.AuditByCheckID("B")
	require.NotEmpty(t, bAudit)
	assert.Equal(t, NOT_EXECUTED, bAudit[len(bAudit)-1].To)
	assert.Equal(t, ReasonPrerequisiteFailed, bAudit[len(bAudit)-1].ReasonCategory)

	dependencyPass := functionRunner(func(*Check) State { return PASS })
	summary = controls.RunChecksWithOptions(dependencyPass, runAll, nil, RunOptions{DependencyChecking: true})
	assert.Equal(t, 4, summary.Pass)
	assert.Equal(t, 0, summary.NotExecuted)

	bAudit = controls.AuditByCheckID("B")
	last := bAudit[len(bAudit)-1]
	assert.Equal(t, NOT_EXECUTED, last.From)
	assert.Equal(t, PASS, last.To)
	assert.Contains(t, last.Condition, "previously blocked by A")
}

func TestRunChecksWithDependenciesReportsMissingSelectedDependency(t *testing.T) {
	input := []byte(`
type: master
groups:
- id: G1
  checks:
  - id: A
  - id: B
    depends_on: [A]
`)
	controls, err := NewControls(MASTER, input, "")
	require.NoError(t, err)

	onlyB := func(_ *Group, check *Check) bool { return check.ID == "B" }
	runner := functionRunner(func(*Check) State { return PASS })
	summary := controls.RunChecksWithOptions(runner, onlyB, nil, RunOptions{DependencyChecking: true})

	assert.Equal(t, 1, summary.NotExecuted)
	check := checksByID(controls)["B"]
	assert.Equal(t, NOT_EXECUTED, check.State)
	assert.Equal(t, ReasonDependencyMissing, check.ReasonCategory)
}

func TestCheckTimeoutIsNotExecuted(t *testing.T) {
	check := Check{
		ID:      "slow",
		Scored:  true,
		Audit:   "sleep 2",
		Timeout: "20ms",
		Tests: &tests{TestItems: []*testItem{{
			Flag: "anything",
			Set:  true,
		}}},
	}

	start := time.Now()
	state := check.run()
	elapsed := time.Since(start)
	assert.Equal(t, NOT_EXECUTED, state)
	assert.Equal(t, ReasonTimeout, check.ReasonCategory)
	assert.Less(t, elapsed, time.Second)
}

func TestMissingAuditConfigIsSkippedInDependencyMode(t *testing.T) {
	check := Check{
		ID:                "config-dependent",
		Scored:            true,
		Audit:             "echo hello",
		AuditConfig:       "/test/does-not-exist.yaml",
		DistinguishStates: true,
		Tests: &tests{TestItems: []*testItem{{
			Flag: "hello",
			Set:  true,
		}}},
	}

	state := check.run()
	assert.Equal(t, SKIPPED, state)
	assert.Equal(t, ReasonConfigurationUnavailable, check.ReasonCategory)
}

func TestRunOptionsTimeoutAppliesToChecksWithoutOwnTimeout(t *testing.T) {
	input := []byte(`
type: master
groups:
- id: G1
  checks:
  - id: slow
    scored: true
    audit: sleep 2
    tests:
      test_items:
      - flag: anything
        set: true
`)
	controls, err := NewControls(MASTER, input, "")
	require.NoError(t, err)
	runner := NewRunner()
	runAll := func(*Group, *Check) bool { return true }

	summary := controls.RunChecksWithOptions(runner, runAll, nil, RunOptions{
		DependencyChecking: true,
		Timeout:            20 * time.Millisecond,
	})
	assert.Equal(t, 1, summary.NotExecuted)
	assert.Equal(t, 1, summary.NotExecutedReasons[ReasonTimeout])
}

func TestBuildDistributionsKeepsEveryNodeResult(t *testing.T) {
	makeControls := func(node string, state State) *Controls {
		return &Controls{
			Type:     NODE,
			NodeName: node,
			Groups: []*Group{{
				ID: "G1",
				Checks: []*Check{{
					ID:    "4.1.1",
					State: state,
				}},
			}},
		}
	}

	distributions := BuildDistributions([]*Controls{
		makeControls("node-a", PASS),
		makeControls("node-b", FAIL),
		makeControls("node-c", PASS),
	})

	require.Len(t, distributions, 1)
	assert.Equal(t, 3, distributions[0].Total)
	assert.Equal(t, 2, distributions[0].States[PASS])
	assert.Equal(t, 1, distributions[0].States[FAIL])
	assert.Equal(t, 1, distributions[0].Nodes["node-b"][FAIL])
}

func TestCompareScansRejectsCrossVersionComparison(t *testing.T) {
	before := &Controls{
		Version:         "cis-1.23",
		BaselineVersion: "cis-1.23",
		CheckVersion:    "cis-1.23",
	}
	after := &Controls{
		Version:         "cis-1.24",
		BaselineVersion: "cis-1.24",
		CheckVersion:    "cis-1.24",
	}

	report := CompareScans([]*Controls{before}, []*Controls{after})
	assert.False(t, report.Comparable)
	assert.Equal(t, "NOT_COMPARABLE", report.Status)
	assert.Contains(t, report.Message, "不可跨版本比对")
	assert.Empty(t, report.Items)
}

func TestCompareScansExplainsDependencyDifference(t *testing.T) {
	before := &Controls{
		Version:         "cis-test",
		BaselineVersion: "cis-test",
		CheckVersion:    "cis-test",
		Groups: []*Group{{
			ID: "G1",
			Checks: []*Check{
				{ID: "A", State: PASS},
				{ID: "B", State: PASS},
			},
		}},
	}
	after := &Controls{
		Version:         "cis-test",
		BaselineVersion: "cis-test",
		CheckVersion:    "cis-test",
		Groups: []*Group{{
			ID: "G1",
			Checks: []*Check{
				{ID: "A", State: FAIL},
				{
					ID:             "B",
					State:          NOT_EXECUTED,
					ReasonCategory: ReasonPrerequisiteFailed,
					Reason:         "dependency A is FAIL",
				},
			},
		}},
	}

	report := CompareScans([]*Controls{before}, []*Controls{after})
	require.True(t, report.Comparable)
	require.Len(t, report.Items, 2)
	assert.True(t, strings.Contains(report.Items[1].Explanation, ReasonPrerequisiteFailed))
}

func TestCheckVersionMismatchIsReported(t *testing.T) {
	input := []byte(`
version: "cis-1.24"
type: master
groups:
- id: G1
  checks:
  - id: A
    version: "cis-1.23"
`)
	controls, err := NewControls(MASTER, input, "")
	require.NoError(t, err)
	assert.True(t, controls.VersionMismatch)
	assert.False(t, controls.VersionComparable)
	assert.Equal(t, "cis-1.23", controls.CheckVersion)
	assert.True(t, controls.Groups[0].Checks[0].VersionMismatch)
}

func checksByID(controls *Controls) map[string]*Check {
	result := make(map[string]*Check)
	for _, group := range controls.Groups {
		for _, check := range group.Checks {
			result[check.ID] = check
		}
	}
	return result
}

func TestTimeoutDurationAcceptsSecondsAndDuration(t *testing.T) {
	check := Check{Timeout: "5"}
	duration, err := check.TimeoutDuration()
	require.NoError(t, err)
	assert.Equal(t, 5*time.Second, duration)

	check.Timeout = "250ms"
	duration, err = check.TimeoutDuration()
	require.NoError(t, err)
	assert.Equal(t, 250*time.Millisecond, duration)

	input := []byte(`
type: master
groups:
- id: G1
  checks:
  - id: A
    timeout: 5
`)
	controls, err := NewControls(MASTER, input, "")
	require.NoError(t, err)
	duration, err = controls.Groups[0].Checks[0].TimeoutDuration()
	require.NoError(t, err)
	assert.Equal(t, 5*time.Second, duration)
}

func TestDependencyModeJSONIncludesZeroStateCounts(t *testing.T) {
	controls := Controls{Summary: Summary{DependencyMode: true}}
	data, err := json.Marshal(controls)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"total_skip":0`)
	assert.Contains(t, string(data), `"total_not_applicable":0`)
	assert.Contains(t, string(data), `"total_not_executed":0`)

	controls.Summary.DependencyMode = false
	data, err = json.Marshal(controls)
	require.NoError(t, err)
	assert.NotContains(t, string(data), `"total_skip"`)
}
