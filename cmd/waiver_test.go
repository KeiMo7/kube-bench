package cmd

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aquasecurity/kube-bench/check"
	"github.com/fatih/color"
	"github.com/onsi/ginkgo/reporters"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newWaiverTestCollection builds a collection with real file-like structure and
// one failing scored check.
func newWaiverTestCollection() []*check.Controls {
	master := &check.Controls{
		ID:      "1",
		Version: "cis-test-1.0",
		Text:    "Control Plane Security Configuration",
		Type:    check.MASTER,
		Groups: []*check.Group{
			{
				ID:   "1.1",
				Text: "Control Plane Node Configuration Files",
				Checks: []*check.Check{
					{ID: "1.1.1", Text: "passes", State: check.PASS, Scored: true},
					{ID: "1.1.2", Text: "fails", State: check.FAIL, Scored: true, Remediation: "fix it"},
				},
				Pass: 1,
				Fail: 1,
			},
		},
		Summary: check.Summary{Pass: 1, Fail: 1},
	}
	node := &check.Controls{
		ID:      "4",
		Version: "cis-test-1.0",
		Text:    "Worker Node Security Configuration",
		Type:    check.NODE,
		Groups: []*check.Group{
			{
				ID:   "4.1",
				Text: "Worker Node Configuration Files",
				Checks: []*check.Check{
					{ID: "1.1.2", Text: "same number, different node type", State: check.FAIL, Scored: true},
				},
				Fail: 1,
			},
		},
		Summary: check.Summary{Fail: 1},
	}
	return []*check.Controls{master, node}
}

// resetWaiverState makes each test independent of the package-level wiring.
func resetWaiverState(t *testing.T) {
	t.Helper()
	oldFile, oldSet, oldScopes, oldResult := waiverFile, waiverSet, waiverScopes, waiverResult
	oldLoaded, oldNow, oldBench := waiverLoaded, waiverNow, waiverBenchmark
	oldCollection := controlsCollection
	t.Cleanup(func() {
		waiverFile, waiverSet, waiverScopes, waiverResult = oldFile, oldSet, oldScopes, oldResult
		waiverLoaded, waiverNow, waiverBenchmark = oldLoaded, oldNow, oldBench
		controlsCollection = oldCollection
	})
	waiverFile = ""
	waiverSet = nil
	waiverScopes = nil
	waiverResult = check.ApplyResult{}
	waiverLoaded = false
	waiverBenchmark = ""
	waiverNow = func() time.Time { return time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC) }
}

func loadWaiverForTest(t *testing.T, body string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "waivers.yaml")
	require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	set, err := check.LoadWaivers(p)
	require.NoError(t, err)
	waiverSet = set
	for _, c := range newWaiverTestCollection() {
		waiverScopes = append(waiverScopes, check.NewScope(c))
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	old := os.Stdout
	oldColor := color.Output
	os.Stdout = w
	color.Output = w
	defer func() { os.Stdout = old; color.Output = oldColor }()
	fn()
	require.NoError(t, w.Close())
	var buf bytes.Buffer
	_, err = buf.ReadFrom(r)
	require.NoError(t, err)
	return buf.String()
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	old := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = old }()
	fn()
	require.NoError(t, w.Close())
	var buf bytes.Buffer
	_, err = buf.ReadFrom(r)
	require.NoError(t, err)
	return buf.String()
}

const acceptedRiskBody = `benchmark: cis-test-1.0
waivers:
  - name: accept-1.1.2
    node_type: master
    check: "1.1.2"
    kind: accepted-risk
    reason: "compensating control in place"
    requester: "alice"
    approver: "bob"
    expires: "2030-01-01"
`

// ---------------------------------------------------------------------------
// Exit code: only a real FAIL drives it, never a waiver.
// ---------------------------------------------------------------------------

func TestWaiver_ExitCodeFromRealFailuresOnly(t *testing.T) {
	resetWaiverState(t)
	oldExit := exitCode
	exitCode = 42
	t.Cleanup(func() { exitCode = oldExit })

	// Waive the master failure only. The node check with the same ID must keep
	// failing (node-type isolation), so the run still exits non-zero.
	loadWaiverForTest(t, acceptedRiskBody)
	controlsCollection = newWaiverTestCollection()
	applyWaivers()

	assert.Equal(t, 42, exitCodeSelection(controlsCollection),
		"a failure on another node type must still drive the exit code")

	// Now waive every failure explicitly; exit code must become 0.
	resetWaiverState(t)
	loadWaiverForTest(t, `benchmark: cis-test-1.0
waivers:
  - name: accept-master
    node_type: master
    check: "1.1.2"
    kind: accepted-risk
    reason: "compensating control"
    requester: "alice"
    approver: "bob"
    expires: "2030-01-01"
  - name: na-node
    node_type: node
    check: "1.1.2"
    kind: not-applicable
    reason: "managed node"
    requester: "carol"
    approver: "dave"
    expires: "2030-01-01"
`)
	controlsCollection = newWaiverTestCollection()
	applyWaivers()
	assert.Equal(t, 0, exitCodeSelection(controlsCollection),
		"when every failure is waived the exit code is clean")
}

func TestWaiver_ExpiredFailureDrivesExitCode(t *testing.T) {
	resetWaiverState(t)
	oldExit := exitCode
	exitCode = 42
	t.Cleanup(func() { exitCode = oldExit })

	loadWaiverForTest(t, `benchmark: cis-test-1.0
waivers:
  - name: expired
    node_type: master
    check: "1.1.2"
    kind: accepted-risk
    reason: "expired last year"
    requester: "alice"
    approver: "bob"
    starts: "2024-01-01"
    expires: "2025-01-01"
`)
	controlsCollection = newWaiverTestCollection()
	applyWaivers()

	master := controlsCollection[0]
	assert.Equal(t, check.FAIL, master.Groups[0].Checks[1].State,
		"expired waiver must return the check to FAIL")
	assert.Nil(t, master.Groups[0].Checks[1].Waiver, "no audit entry is attached to an expired waiver")
	assert.Equal(t, 42, exitCodeSelection(controlsCollection))

	// The expiry must be visible in the structured report as a FAIL again.
	out := captureStdout(t, func() {
		oldNoTotals, oldJSON := noTotals, jsonFmt
		noTotals, jsonFmt, outputFile = false, true, ""
		defer func() { noTotals, jsonFmt = oldNoTotals, oldJSON }()
		writeJSONOutput(controlsCollection)
	})
	var decoded struct {
		Controls []*check.Controls
		Totals   check.Summary
		Waivers  *check.WaiverReport `json:"Waivers"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &decoded))
	assert.Equal(t, 2, decoded.Totals.Fail, "expired check reappears among failures")
	assert.Equal(t, 0, decoded.Totals.AcceptedRisk)
	require.NotNil(t, decoded.Waivers)
	assert.Contains(t, strings.Join(decoded.Waivers.Diagnostics, "\n"), "expired on 2025-01-01")
}

// ---------------------------------------------------------------------------
// Missing / malformed waiver files fail explicitly.
// ---------------------------------------------------------------------------

// captureFatal runs fn with a recorder in place of exitWithError and returns
// the error it was handed, or nil if it was not called.
func captureFatal(t *testing.T, fn func()) error {
	t.Helper()
	old := exitWithErrorFunc
	var got error
	exitWithErrorFunc = func(err error) { got = err }
	t.Cleanup(func() { exitWithErrorFunc = old })
	fn()
	return got
}

func TestInitWaivers_MissingFileFails(t *testing.T) {
	resetWaiverState(t)
	waiverFile = filepath.Join(t.TempDir(), "absent.yaml")

	err := captureFatal(t, initWaivers)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unable to read waiver file")
	assert.Nil(t, waiverSet, "a missing file must not leave an empty set behind")
}

func TestInitWaivers_MalformedFileFails(t *testing.T) {
	resetWaiverState(t)
	p := filepath.Join(t.TempDir(), "bad.yaml")
	require.NoError(t, os.WriteFile(p, []byte("waivers: [\n"), 0o600))
	waiverFile = p

	err := captureFatal(t, initWaivers)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unable to parse waiver file")
	assert.Nil(t, waiverSet)
}

func TestPrepareWaiverScopes_FailsWithoutBenchmark(t *testing.T) {
	resetWaiverState(t)
	loadWaiverForTest(t, acceptedRiskBody)
	oldCfgDir := cfgDir
	cfgDir = t.TempDir()
	t.Cleanup(func() { cfgDir = oldCfgDir })

	t.Run("missing benchmark directory", func(t *testing.T) {
		resetWaiverState(t)
		loadWaiverForTest(t, acceptedRiskBody)
		waiverScopes = nil
		err := captureFatal(t, func() { prepareWaiverScopes("bench-test") })
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unable to build waiver validation scope")
	})

	t.Run("benchmark directory with no controls files", func(t *testing.T) {
		resetWaiverState(t)
		loadWaiverForTest(t, acceptedRiskBody)
		waiverScopes = nil
		require.NoError(t, os.Mkdir(filepath.Join(cfgDir, "bench-test"), 0o755))
		err := captureFatal(t, func() { prepareWaiverScopes("bench-test") })
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no controls files found")
	})
}

func TestApplyWaivers_ContradictionFails(t *testing.T) {
	resetWaiverState(t)
	loadWaiverForTest(t, `benchmark: cis-test-1.0
waivers:
  - name: risk
    node_type: master
    check: "1.1.2"
    kind: accepted-risk
    reason: "risk accepted"
    requester: "alice"
    approver: "bob"
    expires: "2030-01-01"
  - name: na
    node_type: master
    check: "1.1.2"
    kind: not-applicable
    reason: "not applicable"
    requester: "carol"
    approver: "dave"
    expires: "2030-01-01"
`)
	controlsCollection = newWaiverTestCollection()

	err := captureFatal(t, applyWaivers)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "contradict")
}

func TestApplyWaivers_UnknownCheckFails(t *testing.T) {
	resetWaiverState(t)
	loadWaiverForTest(t, `benchmark: cis-test-1.0
waivers:
  - name: ghost
    node_type: master
    check: "9.9.9"
    kind: accepted-risk
    reason: "typo"
    requester: "alice"
    approver: "bob"
`)
	controlsCollection = newWaiverTestCollection()

	err := captureFatal(t, applyWaivers)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not exist")
}

// ---------------------------------------------------------------------------
// stdout: waived checks carry reason and expiry; summaries stay distinct.
// ---------------------------------------------------------------------------

func TestWaiver_StdoutReportsReasonAndExpiry(t *testing.T) {
	resetWaiverState(t)
	loadWaiverForTest(t, acceptedRiskBody)
	controlsCollection = newWaiverTestCollection()
	applyWaivers()

	out := captureStdout(t, func() {
		oldNoResults, oldNoSummary, oldNoRemediations, oldNoTotals := noResults, noSummary, noRemediations, noTotals
		noResults, noSummary, noRemediations, noTotals = false, false, false, false
		defer func() {
			noResults, noSummary, noRemediations, noTotals = oldNoResults, oldNoSummary, oldNoRemediations, oldNoTotals
		}()
		writeStdoutOutput(controlsCollection)
	})

	assert.Contains(t, out, "[ACCEPTED RISK] 1.1.2 fails")
	assert.Contains(t, out, "compensating control in place")
	assert.Contains(t, out, "expires: 2030-01-01")
	assert.Contains(t, out, "alice")
	assert.Contains(t, out, "bob")
	assert.Contains(t, out, "1 checks ACCEPTED RISK")
	assert.Contains(t, out, "== Waivers ==")
}

func TestWaiver_StdoutNoWaiverIsByteStable(t *testing.T) {
	// Without a waiver file the output must not gain any waiver lines.
	resetWaiverState(t)
	controlsCollection = newWaiverTestCollection()

	out := captureStdout(t, func() {
		oldNoResults, oldNoSummary, oldNoRemediations := noResults, noSummary, noRemediations
		noResults, noSummary, noRemediations = false, false, false
		defer func() { noResults, noSummary, noRemediations = oldNoResults, oldNoSummary, oldNoRemediations }()
		writeStdoutOutput(controlsCollection)
	})

	assert.NotContains(t, out, "== Waivers ==")
	assert.NotContains(t, out, "ACCEPTED RISK")
	assert.NotContains(t, out, "NOT APPLICABLE")
	assert.Contains(t, out, "1 checks PASS\n2 checks FAIL\n0 checks WARN\n0 checks INFO\n\n")
}

func TestWaiver_StdoutByteIdenticalWithoutWaivers(t *testing.T) {
	render := func() string {
		resetWaiverState(t)
		controlsCollection = newWaiverTestCollection()
		return captureStdout(t, func() {
			oldNoResults, oldNoSummary, oldNoRemediations, oldNoTotals, oldInclude := noResults, noSummary, noRemediations, noTotals, includeTestOutput
			noResults, noSummary, noRemediations, noTotals, includeTestOutput = false, false, false, false, false
			defer func() {
				noResults, noSummary, noRemediations, noTotals, includeTestOutput = oldNoResults, oldNoSummary, oldNoRemediations, oldNoTotals, oldInclude
			}()
			writeStdoutOutput(controlsCollection)
		})
	}
	// Two independent renders of the same waiver-free input must be identical
	// and must not mention waivers.
	first := render()
	second := render()
	assert.Equal(t, first, second)
	assert.NotContains(t, first, "waiver")
}

// ---------------------------------------------------------------------------
// JSON: one waiver object per check plus the file-level report.
// ---------------------------------------------------------------------------

func TestWaiver_JSONCarriesAuditTrail(t *testing.T) {
	resetWaiverState(t)
	loadWaiverForTest(t, acceptedRiskBody)
	controlsCollection = newWaiverTestCollection()
	applyWaivers()

	out := captureStdout(t, func() {
		oldNoTotals, oldJSON := noTotals, jsonFmt
		noTotals, jsonFmt, outputFile = false, true, ""
		defer func() { noTotals, jsonFmt = oldNoTotals, oldJSON }()
		writeJSONOutput(controlsCollection)
	})

	var decoded struct {
		Controls []*check.Controls
		Totals   check.Summary
		Waivers  *check.WaiverReport `json:"Waivers"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &decoded))
	require.NotNil(t, decoded.Waivers)
	assert.Equal(t, 1, decoded.Waivers.Total)
	assert.Equal(t, 1, decoded.Waivers.Applied)
	assert.Equal(t, 1, decoded.Waivers.AcceptedRisk)
	assert.Equal(t, 0, decoded.Waivers.NotApplicable)

	var waived *check.Check
	for _, c := range decoded.Controls {
		for _, g := range c.Groups {
			for _, ch := range g.Checks {
				if ch.Waiver != nil {
					waived = ch
				}
			}
		}
	}
	require.NotNil(t, waived)
	assert.Equal(t, "1.1.2", waived.ID)
	assert.Equal(t, check.ACCEPTEDRISK, waived.State)
	assert.Equal(t, "compensating control in place", waived.Waiver.Reason)
	assert.Equal(t, "2030-01-01", waived.Waiver.Expires)
	assert.Equal(t, "FAIL", waived.Waiver.MeasuredState)
	assert.Equal(t, 1, decoded.Totals.AcceptedRisk)
	assert.Equal(t, 1, decoded.Totals.Fail, "the unwaived node failure still counts")
}

func TestWaiver_JSONWithoutWaiversHasNoWaiverKeys(t *testing.T) {
	resetWaiverState(t)
	controlsCollection = newWaiverTestCollection()

	out := captureStdout(t, func() {
		oldNoTotals, oldJSON := noTotals, jsonFmt
		noTotals, jsonFmt, outputFile = false, true, ""
		defer func() { noTotals, jsonFmt = oldNoTotals, oldJSON }()
		writeJSONOutput(controlsCollection)
	})

	assert.NotContains(t, out, `"Waivers"`)
	assert.NotContains(t, out, `"waiver"`)
	assert.NotContains(t, out, `"not_applicable"`)
	assert.NotContains(t, out, `"accepted_risk"`)
	assert.Contains(t, out, `"total_fail":2`)
}

// ---------------------------------------------------------------------------
// JUnit: waived checks are skipped but keep the reason and expiry.
// ---------------------------------------------------------------------------

func TestWaiver_JUnitCarriesReasonAndExpiry(t *testing.T) {
	resetWaiverState(t)
	loadWaiverForTest(t, acceptedRiskBody)
	controlsCollection = newWaiverTestCollection()
	applyWaivers()

	master := controlsCollection[0]
	junit, err := master.JUnit()
	require.NoError(t, err)

	var suite reporters.JUnitTestSuite
	require.NoError(t, xml.Unmarshal(junit, &suite))
	require.Len(t, suite.TestCases, 2)
	assert.NotNil(t, suite.TestCases[1].Skipped)
	assert.Contains(t, suite.TestCases[1].Skipped.Message, "ACCEPTED RISK")
	assert.Contains(t, suite.TestCases[1].Skipped.Message, "compensating control in place")
	assert.Contains(t, suite.TestCases[1].Skipped.Message, "expires: 2030-01-01")
}

// ---------------------------------------------------------------------------
// All three formats agree on the wording of the same result.
// ---------------------------------------------------------------------------

func TestWaiver_ThreeFormatsAgree(t *testing.T) {
	resetWaiverState(t)
	loadWaiverForTest(t, acceptedRiskBody)
	controlsCollection = newWaiverTestCollection()
	applyWaivers()

	master := controlsCollection[0]
	var waived *check.Check
	for _, g := range master.Groups {
		for _, c := range g.Checks {
			if c.Waiver != nil {
				waived = c
			}
		}
	}
	require.NotNil(t, waived)
	want := waived.Waiver.Summary()

	// 1. stdout
	stdoutOut := captureStdout(t, func() {
		oldNoResults, oldNoSummary, oldNoRemediations, oldNoTotals := noResults, noSummary, noRemediations, noTotals
		noResults, noSummary, noRemediations, noTotals = false, false, false, false
		defer func() {
			noResults, noSummary, noRemediations, noTotals = oldNoResults, oldNoSummary, oldNoRemediations, oldNoTotals
		}()
		writeStdoutOutput(controlsCollection)
	})
	assert.Contains(t, stdoutOut, want)

	// 2. JSON
	jsonOut := captureStdout(t, func() {
		oldNoTotals, oldJSON := noTotals, jsonFmt
		noTotals, jsonFmt, outputFile = false, true, ""
		defer func() { noTotals, jsonFmt = oldNoTotals, oldJSON }()
		writeJSONOutput(controlsCollection)
	})
	var decoded struct{ Controls []*check.Controls }
	require.NoError(t, json.Unmarshal([]byte(jsonOut), &decoded))
	var jsonWaived *check.WaiverInfo
	for _, c := range decoded.Controls {
		for _, g := range c.Groups {
			for _, ch := range g.Checks {
				if ch.Waiver != nil {
					jsonWaived = ch.Waiver
				}
			}
		}
	}
	require.NotNil(t, jsonWaived)
	assert.Equal(t, want, jsonWaived.Summary())

	// 3. JUnit
	junitOut, err := master.JUnit()
	require.NoError(t, err)
	var suite reporters.JUnitTestSuite
	require.NoError(t, xml.Unmarshal(junitOut, &suite))
	var msg string
	for _, tc := range suite.TestCases {
		if tc.Skipped != nil && strings.Contains(tc.Skipped.Message, "ACCEPTED RISK") {
			msg = tc.Skipped.Message
		}
	}
	require.NotEmpty(t, msg)
	assert.Equal(t, want, strings.TrimPrefix(msg, "ACCEPTED RISK: "))
}

// ---------------------------------------------------------------------------
// Diagnostics reach stderr.
// ---------------------------------------------------------------------------

func TestWaiver_DiagnosticsGoToStderr(t *testing.T) {
	resetWaiverState(t)
	loadWaiverForTest(t, `benchmark: cis-test-1.0
waivers:
  - name: expired
    node_type: master
    check: "1.1.2"
    kind: accepted-risk
    reason: "expired"
    requester: "alice"
    approver: "bob"
    starts: "2024-01-01"
    expires: "2025-01-01"
`)
	controlsCollection = newWaiverTestCollection()

	errOut := captureStderr(t, applyWaivers)
	assert.Contains(t, errOut, "[WARN] waiver:")
	assert.Contains(t, errOut, "expired on 2025-01-01")
}
