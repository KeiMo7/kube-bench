package cmd

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/kube-bench/check"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeProbe installs a fake process table and detection command for the
// duration of a test. The process table is a set of executable names that are
// "running" on the simulated machine.
func fakeProbe(t *testing.T, running ...string) {
	t.Helper()

	oldPS, oldDetection := psFunc, roleDetectionAvailable
	runningSet := make(map[string]bool, len(running))
	for _, name := range running {
		runningSet[name] = true
	}

	psFunc = func(proc string) string {
		if runningSet[proc] {
			return "/usr/bin/" + proc + " --some-flag"
		}
		return ""
	}
	roleDetectionAvailable = func() (string, error) { return "/bin/ps", nil }

	t.Cleanup(func() {
		psFunc, roleDetectionAvailable = oldPS, oldDetection
	})
}

func loadRoleConfig(t *testing.T) *viper.Viper {
	t.Helper()
	v := viper.New()
	v.SetConfigFile("../cfg/config.yaml")
	require.NoError(t, v.ReadInConfig())
	return v
}

func TestDetectRoles_WorkloadOnly(t *testing.T) {
	fakeProbe(t, "kubelet", "kube-proxy")
	report := detectRoles(loadRoleConfig(t), nil)

	assert.Equal(t, []string{RoleWorker}, report.Roles)
	assert.True(t, report.Determined)
	assert.Equal(t, "observed", report.Source)
	assert.False(t, report.Fallback)
	assert.NotEmpty(t, report.Evidence, "the determination must carry evidence")

	manual := map[check.NodeType]bool{}
	assert.Equal(t, check.ApplicabilityNotApplicable,
		decideApplicability(check.MASTER, report, manual).State)
	assert.Equal(t, check.ApplicabilityNotApplicable,
		decideApplicability(check.CONTROLPLANE, report, manual).State)
	assert.Equal(t, check.ApplicabilityCovered,
		decideApplicability(check.NODE, report, manual).State)
}

func TestDetectRoles_ControlPlaneOnly(t *testing.T) {
	fakeProbe(t, "kube-apiserver", "kube-scheduler", "kube-controller-manager")
	report := detectRoles(loadRoleConfig(t), nil)

	assert.Equal(t, []string{RoleControlPlane}, report.Roles)
	assert.True(t, report.Determined)

	manual := map[check.NodeType]bool{}
	assert.Equal(t, check.ApplicabilityCovered,
		decideApplicability(check.MASTER, report, manual).State)
	assert.Equal(t, check.ApplicabilityNotApplicable,
		decideApplicability(check.NODE, report, manual).State)
}

func TestDetectRoles_MixedCoversBoth(t *testing.T) {
	fakeProbe(t, "kube-apiserver", "kube-scheduler", "kube-controller-manager", "kubelet", "etcd")
	report := detectRoles(loadRoleConfig(t), nil)

	assert.ElementsMatch(t, []string{RoleControlPlane, RoleWorker, RoleEtcd}, report.Roles)
	assert.True(t, report.Determined)

	manual := map[check.NodeType]bool{}
	for _, target := range []check.NodeType{check.MASTER, check.CONTROLPLANE, check.NODE, check.ETCD} {
		assert.Equal(t, check.ApplicabilityCovered, decideApplicability(target, report, manual).State,
			"mixed machine must cover %s", target)
	}
}

func TestDetectRoles_DetectionCommandUnavailable(t *testing.T) {
	oldPS, oldDetection := psFunc, roleDetectionAvailable
	t.Cleanup(func() { psFunc, roleDetectionAvailable = oldPS, oldDetection })
	psFunc = func(string) string { return "" }
	roleDetectionAvailable = func() (string, error) {
		return "", errors.New("/bin/ps: permission denied")
	}

	report := detectRoles(loadRoleConfig(t), nil)

	assert.False(t, report.Determined)
	assert.Equal(t, "unavailable", report.Source)
	assert.True(t, report.Fallback)
	assert.Equal(t, check.ReasonRoleDetectionUnavailable, report.ReasonCode)
	assert.Contains(t, report.Reason, "permission denied")
	assert.NotEmpty(t, report.Evidence)

	// The default is explicit: every role target still runs, reported as
	// undetermined rather than silently not applicable.
	manual := map[check.NodeType]bool{}
	for _, target := range []check.NodeType{check.MASTER, check.CONTROLPLANE, check.NODE, check.ETCD} {
		decision := decideApplicability(target, report, manual)
		assert.Equal(t, check.ApplicabilityUndetermined, decision.State)
		assert.Equal(t, check.ReasonRoleDetectionUnavailable, decision.ReasonCode)
		assert.NotEmpty(t, decision.Reason)
	}
}

func TestDetectRoles_NoComponentsObserved(t *testing.T) {
	fakeProbe(t)
	report := detectRoles(loadRoleConfig(t), nil)

	assert.False(t, report.Determined)
	assert.True(t, report.Fallback)
	assert.Equal(t, check.ReasonNoComponentsObserved, report.ReasonCode)

	decision := decideApplicability(check.MASTER, report, map[check.NodeType]bool{})
	assert.Equal(t, check.ApplicabilityUndetermined, decision.State,
		"an empty probe result must not be silently trimmed")
}

func TestDetectRoles_PhysicalCommandProbe(t *testing.T) {
	// Exercise the real detection-command probe: with PATH honoured by the
	// caller this must find an executable ps, and an unreadable path must be
	// reported as unavailable rather than silently treated as "no role".
	oldDetection := roleDetectionAvailable
	t.Cleanup(func() { roleDetectionAvailable = oldDetection })

	path, err := defaultRoleDetectionAvailable()
	if err == nil {
		assert.NotEmpty(t, path)
	}
}

func TestDetectRoles_Deterministic(t *testing.T) {
	fakeProbe(t, "kube-apiserver", "kubelet", "etcd", "kube-scheduler", "kube-controller-manager")

	first := detectRoles(loadRoleConfig(t), nil)
	for i := 0; i < 20; i++ {
		next := detectRoles(loadRoleConfig(t), nil)
		assert.Equal(t, first.Roles, next.Roles)
		assert.Equal(t, first.Source, next.Source)
		assert.Equal(t, first.Evidence, next.Evidence)
		assert.Equal(t, first.Determined, next.Determined)
	}
}

func TestManualScopeWinsButTrimmingStillApplies(t *testing.T) {
	// Worker-only machine, but the operator asks for the master target.
	fakeProbe(t, "kubelet")
	manual := map[check.NodeType]bool{check.MASTER: true}
	report := detectRoles(loadRoleConfig(t), []string{"master"})

	assert.Contains(t, report.Roles, RoleControlPlane, "manual scope is observable evidence")
	assert.Equal(t, check.ApplicabilityCovered,
		decideApplicability(check.MASTER, report, manual).State,
		"an explicitly requested target runs as before")

	// The node target was not requested explicitly, and the machine does run
	// kubelet, so it is covered too.
	assert.Equal(t, check.ApplicabilityCovered,
		decideApplicability(check.NODE, report, manual).State)

	// etcd is neither observed nor requested: trimming still applies.
	assert.Equal(t, check.ApplicabilityNotApplicable,
		decideApplicability(check.ETCD, report, manual).State)
}

func TestManualTargetAloneIsHonouredWhenDetectionWorks(t *testing.T) {
	// A worker machine: control-plane checks are not applicable, but if the
	// operator explicitly requests the controlplane target it must run.
	fakeProbe(t, "kubelet")
	manual := map[check.NodeType]bool{check.CONTROLPLANE: true}
	report := detectRoles(loadRoleConfig(t), []string{"controlplane"})

	assert.Equal(t, check.ApplicabilityCovered,
		decideApplicability(check.CONTROLPLANE, report, manual).State)
}

func TestTransferFunction_MarksNotApplicableWithoutFailing(t *testing.T) {
	controls, err := check.NewControls(check.NODE, []byte(`
---
type: "node"
id: "4"
groups:
- id: "4.1"
  checks:
  - id: "4.1.1"
    text: "kubelet service file permissions"
    audit: "echo permissions=644"
    tests:
      test_items:
      - flag: "permissions"
        compare:
          op: bitmask
          value: "600"
    remediation: "chmod 600"
    scored: true
`), "")
	require.NoError(t, err)

	decision := applicabilityDecision{State: check.ApplicabilityNotApplicable, ReasonCode: check.ReasonRoleNotObserved, Reason: "worker role not observed"}
	applyDecision(controls, decision, check.NewRunner(), func(*check.Group, *check.Check) bool { return true })

	assert.Equal(t, 0, controls.Summary.Fail, "a trimmed control-plane check must not fail")
	assert.Equal(t, 1, controls.Summary.NotApplicable)
	assert.Equal(t, check.NOT_APPLICABLE, controls.Groups[0].Checks[0].State)
	assert.Equal(t, check.ReasonRoleNotObserved, controls.Groups[0].Checks[0].ReasonCode)
	assert.Equal(t, "chmod 600", controls.Groups[0].Checks[0].Remediation,
		"the check's own remediation text is unchanged")
}

// --- end-to-end report tests over real benchmark files -------------------

// runScenario executes the benchmark targets for a simulated machine and
// returns the resulting collection plus the summary totals, mirroring what the
// command would report. candidateTargets are the targets the run considers;
// manualTargets are the ones explicitly named on the command line (empty for
// the root command, which uses automatic role detection only).
func runScenario(t *testing.T, running []string, candidateTargets, manualTargets []string) ([]*check.Controls, check.Summary) {
	t.Helper()

	fakeProbe(t, running...)

	oldDir, oldCollection := cfgDir, controlsCollection
	oldTotals, oldReport := noTotals, activeRoleReport
	oldManual := activeManualTargets
	cfgDir = "../cfg"
	controlsCollection = nil
	noTotals = true
	t.Cleanup(func() {
		cfgDir, controlsCollection = oldDir, oldCollection
		noTotals, activeRoleReport = oldTotals, oldReport
		activeManualTargets = oldManual
	})

	bv := "cis-1.9"
	viper.SetConfigFile(filepath.Join("../cfg", "config.yaml"))
	require.NoError(t, viper.ReadInConfig())
	require.NoError(t, mergeConfig(filepath.Join(cfgDir, bv)))

	unknown := "none"
	detecetedKubeVersion = unknown

	report := newRoleReport(viper.GetViper(), manualTargets)
	setRunContext(report, manualTargets)

	for _, target := range candidateTargets {
		runChecks(check.NodeType(translate(target)), loadConfig(check.NodeType(translate(target)), bv), unknown)
	}
	finalizeCollection(controlsCollection)

	return controlsCollection, getSummaryTotals(controlsCollection)
}

func findByType(collection []*check.Controls, t check.NodeType) *check.Controls {
	for _, c := range collection {
		if c.Type == t {
			return c
		}
	}
	return nil
}

func TestReport_WorkloadOnlyMachine(t *testing.T) {
	collection, totals := runScenario(t,
		[]string{"kubelet", "kube-proxy"},
		[]string{"master", "controlplane", "node", "etcd"}, nil)

	master := findByType(collection, check.MASTER)
	controlplane := findByType(collection, check.CONTROLPLANE)
	node := findByType(collection, check.NODE)

	require.NotNil(t, master)
	require.NotNil(t, controlplane)
	require.NotNil(t, node)

	assert.Equal(t, check.ApplicabilityNotApplicable, master.Applicability.State)
	assert.Equal(t, 0, master.Summary.Fail, "control-plane checks must not fail on a workload-only machine")
	assert.Equal(t, 0, node.Summary.NotApplicable, "worker checks still run")

	for _, g := range master.Groups {
		for _, c := range g.Checks {
			assert.Equal(t, check.NOT_APPLICABLE, c.State)
		}
	}

	// Trimming is counted separately and never contributes to FAIL.
	assert.Greater(t, totals.NotApplicable, 0)
	notApplicableInMaster := master.Summary.NotApplicable
	assert.Greater(t, notApplicableInMaster, 0)
	assert.Equal(t, sumFail(collection), totals.Fail)
	assert.Less(t, totals.Fail, totals.Fail+totals.NotApplicable)
}

func TestReport_ControlPlaneOnlyMachine(t *testing.T) {
	collection, totals := runScenario(t,
		[]string{"kube-apiserver", "kube-scheduler", "kube-controller-manager"},
		[]string{"master", "controlplane", "node", "etcd"}, nil)

	node := findByType(collection, check.NODE)
	require.NotNil(t, node)
	assert.Equal(t, check.ApplicabilityNotApplicable, node.Applicability.State)
	assert.Equal(t, 0, node.Summary.Fail, "worker checks must not fail on a control-plane-only machine")
	assert.Equal(t, 0, node.Summary.Pass)
	assert.Greater(t, totals.NotApplicable, node.Summary.NotApplicable,
		"etcd trimming is counted too")

	// Every failure in the report comes from a covered target: trimmed checks
	// are excluded from the fail total.
	assert.Equal(t, sumFailOfCovered(collection), totals.Fail,
		"not-applicable checks must never enter the fail total")

	// Exit code follows real failures only.
	oldExit := exitCode
	exitCode = 42
	t.Cleanup(func() { exitCode = oldExit })
	assert.Equal(t, 0, exitCodeSelection([]*check.Controls{node}),
		"a control target holding only trimmed checks must not trip the exit code")
}

func TestReport_MixedMachineDeduplicates(t *testing.T) {
	collection, _ := runScenario(t,
		[]string{"kube-apiserver", "kube-scheduler", "kube-controller-manager", "kubelet"},
		[]string{"master", "controlplane", "node", "etcd"}, nil)

	master := findByType(collection, check.MASTER)
	node := findByType(collection, check.NODE)
	require.NotNil(t, master)
	require.NotNil(t, node)

	assert.Equal(t, check.ApplicabilityCovered, master.Applicability.State)
	assert.Equal(t, check.ApplicabilityCovered, node.Applicability.State)
	assert.Equal(t, 0, master.Summary.NotApplicable)
	assert.Equal(t, 0, node.Summary.NotApplicable)

	// Both targets reached a conclusion: they have real, non-trimmed results.
	assert.Greater(t, master.Pass+master.Fail+master.Warn+master.Info, 0)
	assert.Greater(t, node.Pass+node.Fail+node.Warn+node.Info, 0)

	// Identifiers are unique across the whole report.
	seen := map[string]string{}
	for _, controls := range collection {
		for _, g := range controls.Groups {
			for _, c := range g.Checks {
				if prev, ok := seen[c.ID]; ok {
					t.Fatalf("check %s appears in both %s and %s after de-duplication", c.ID, prev, controls.Type)
				}
				seen[c.ID] = string(controls.Type)
			}
		}
	}
}

func TestReport_SourceMarkingOnCollision(t *testing.T) {
	// Two synthetic role targets sharing one identifier, as happens in
	// benchmarks where control plane and policies overlap.
	a, err := check.NewControls(check.MASTER, []byte(`
---
type: "master"
id: "1"
groups:
- id: "1.1"
  checks:
  - id: "DUP-1"
    scored: true
`), "")
	require.NoError(t, err)
	b, err := check.NewControls(check.CONTROLPLANE, []byte(`
---
type: "controlplane"
id: "3"
groups:
- id: "3.1"
  checks:
  - id: "DUP-1"
    scored: true
`), "")
	require.NoError(t, err)

	a.RunChecks(check.NewRunner(), allPredicate, map[string]bool{})
	b.RunChecks(check.NewRunner(), allPredicate, map[string]bool{})

	removed := check.Deduplicate([]*check.Controls{a, b}, isRoleTargetControls)
	assert.Equal(t, 1, removed)

	var kept *check.Check
	for _, controls := range []*check.Controls{a, b} {
		for _, g := range controls.Groups {
			for _, c := range g.Checks {
				if c.ID == "DUP-1" {
					kept = c
				}
			}
		}
	}
	require.NotNil(t, kept)
	assert.ElementsMatch(t, []string{"master", "controlplane"}, kept.Sources)
	assert.NotEmpty(t, kept.SourceStates)
}

func TestReport_JSONCarriesRoleCoverageAndNewState(t *testing.T) {
	fakeProbe(t, "kubelet")
	report := detectRoles(loadRoleConfig(t), nil)
	setRunContext(report, nil)
	t.Cleanup(func() { activeRoleReport = nil; activeManualTargets = nil })

	controls, err := check.NewControls(check.NODE, []byte(`
---
type: "node"
id: "4"
groups:
- id: "4.1"
  checks:
  - id: "4.1.1"
    scored: true
`), "")
	require.NoError(t, err)
	dec := applicabilityDecision{State: check.ApplicabilityNotApplicable, ReasonCode: check.ReasonRoleNotObserved, Reason: "worker role not observed"}
	applyDecision(controls, dec, check.NewRunner(), allPredicate)

	controlsCollection = []*check.Controls{controls}
	t.Cleanup(func() { controlsCollection = nil })

	out, err := json.Marshal(struct {
		Controls []*check.Controls `json:"Controls"`
		Totals   check.Summary     `json:"Totals"`
		Role     *check.RoleReport `json:"role"`
		Coverage *check.Coverage   `json:"coverage"`
	}{
		Controls: controlsCollection,
		Totals:   getSummaryTotals(controlsCollection),
		Role:     activeRoleReport,
		Coverage: buildCoverage(controlsCollection),
	})
	require.NoError(t, err)

	var decoded map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &decoded))
	assert.Contains(t, string(out), `"status":"NOT_APPLICABLE"`)
	assert.Contains(t, string(out), `"reason_code":"role_not_observed"`)
	assert.Contains(t, string(out), `"total_not_applicable":1`)
	assert.Contains(t, string(out), `"roles"`)
	assert.Contains(t, string(out), `"evidence"`)
	assert.Contains(t, string(out), `"covered"`)
}

func TestReport_ExitCodeIgnoresTrimmedChecks(t *testing.T) {
	oldExit := exitCode
	exitCode = 7
	t.Cleanup(func() { exitCode = oldExit })

	trimmed := &check.Controls{Summary: check.Summary{NotApplicable: 25}}
	assert.Equal(t, 0, exitCodeSelection([]*check.Controls{trimmed}),
		"not-applicable checks must not produce a failure exit code")

	failed := &check.Controls{Summary: check.Summary{Fail: 1, NotApplicable: 25}}
	assert.Equal(t, 7, exitCodeSelection([]*check.Controls{failed}),
		"a real failure still produces the configured exit code")
}

func TestReport_DuplicateOnlyInOneTargetKeepsOriginalOutput(t *testing.T) {
	// A single-role machine produces no collisions, so totals are unchanged
	// from before role-awareness: trimmed=0 and every check keeps its verdict.
	collection, totals := runScenario(t,
		[]string{"kube-apiserver", "kube-scheduler", "kube-controller-manager", "etcd"},
		[]string{"master", "controlplane", "node", "etcd"}, nil)

	node := findByType(collection, check.NODE)
	require.NotNil(t, node)
	assert.Equal(t, check.ApplicabilityNotApplicable, node.Applicability.State)
	assert.Equal(t, 0, node.Fail)
	assert.Equal(t, totals.Fail, sumFail(collection))
	assert.Equal(t, sumPass(collection), totals.Pass)
}

// TestReport_SummaryComparison prints the summary comparison for the three
// machine shapes required by the acceptance criteria. It is a normal test (its
// assertions run too) that also logs the table for `go test -v`.
func TestReport_SummaryComparison(t *testing.T) {
	type scenario struct {
		name    string
		running []string
	}
	scenarios := []scenario{
		{name: "control-plane-only", running: []string{"kube-apiserver", "kube-scheduler", "kube-controller-manager", "etcd"}},
		{name: "workload-only", running: []string{"kubelet", "kube-proxy"}},
		{name: "mixed", running: []string{"kube-apiserver", "kube-scheduler", "kube-controller-manager", "etcd", "kubelet", "kube-proxy"}},
	}

	t.Log("machine             | target      | state          | pass | fail | warn | info | n/a")
	t.Log("--------------------+-------------+----------------+------+------+------+------+----")
	for _, sc := range scenarios {
		collection, totals := runScenario(t, sc.running,
			[]string{"master", "controlplane", "node", "etcd"}, nil)
		for _, target := range []check.NodeType{check.MASTER, check.CONTROLPLANE, check.NODE, check.ETCD} {
			c := findByType(collection, target)
			require.NotNil(t, c)
			state := ""
			if c.Applicability != nil {
				state = string(c.Applicability.State)
			}
			t.Logf("%-19s | %-11s | %-14s | %4d | %4d | %4d | %4d | %3d",
				sc.name, target, state, c.Pass, c.Fail, c.Warn, c.Info, c.NotApplicable)
		}
		t.Logf("%-19s | TOTAL       |                | %4d | %4d | %4d | %4d | %3d",
			sc.name, totals.Pass, totals.Fail, totals.Warn, totals.Info, totals.NotApplicable)
		t.Log("--------------------+-------------+----------------+------+------+------+------+----")

		// Invariants that must hold for every scenario.
		assert.Equal(t, sumFailOfCovered(collection), totals.Fail)
		for _, c := range collection {
			if c.Applicability != nil && c.Applicability.State == check.ApplicabilityNotApplicable {
				assert.Equal(t, 0, c.Fail, "%s must contribute no failures", c.Type)
			}
		}
	}
}

// --- helpers -------------------------------------------------------------

func allPredicate(*check.Group, *check.Check) bool { return true }

func isRoleTargetControls(c *check.Controls) bool {
	return c.Type == check.MASTER || c.Type == check.CONTROLPLANE || c.Type == check.NODE || c.Type == check.ETCD
}

func sumFail(collection []*check.Controls) int {
	n := 0
	for _, c := range collection {
		n += c.Fail
	}
	return n
}

func sumPass(collection []*check.Controls) int {
	n := 0
	for _, c := range collection {
		n += c.Pass
	}
	return n
}

// sumFailOfCovered sums the failures of targets that were actually covered.
func sumFailOfCovered(collection []*check.Controls) int {
	n := 0
	for _, c := range collection {
		if c.Applicability != nil && c.Applicability.State == check.ApplicabilityNotApplicable {
			continue
		}
		n += c.Fail
	}
	return n
}

var _ = os.Getenv
