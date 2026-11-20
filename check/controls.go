// Copyright © 2017 Aqua Security Software Ltd. <info@aquasec.com>
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
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
	"github.com/golang/glog"
	"github.com/onsi/ginkgo/reporters"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

const (
	// UNKNOWN is when the AWS account can't be found
	UNKNOWN = "Unknown"
	// ARN for the AWS Security Hub service
	ARN = "arn:aws:securityhub:%s::product/aqua-security/kube-bench"
	// SCHEMA for the AWS Security Hub service
	SCHEMA = "2018-10-08"
	// TYPE is type of Security Hub finding
	TYPE = "Software and Configuration Checks/Industry and Regulatory Standards/CIS Kubernetes Benchmark"
)

type OverallControls struct {
	Controls      []*Controls
	Totals        Summary
	Distributions []CheckDistribution `json:"Distributions,omitempty"`
}

// Controls holds all controls to check for master nodes.
type Controls struct {
	ID                 string       `yaml:"id" json:"id"`
	Version            string       `json:"version"`
	DetectedVersion    string       `json:"detected_version,omitempty"`
	BaselineVersion    string       `json:"baseline_version,omitempty"`
	CheckVersion       string       `json:"check_version,omitempty"`
	VersionComparable  bool         `json:"version_comparable,omitempty"`
	VersionMismatch    bool         `json:"version_mismatch,omitempty"`
	Text               string       `json:"text"`
	Type               NodeType     `json:"node_type"`
	NodeName           string       `json:"node_name,omitempty"`
	DependencyChecking bool         `json:"dependency_checking,omitempty"`
	Groups             []*Group     `json:"tests"`
	AuditTrail         []AuditEvent `json:"audit_trail,omitempty"`
	Summary
}

// Group is a collection of similar checks.
type Group struct {
	ID            string   `yaml:"id" json:"section"`
	Type          string   `yaml:"type" json:"type"`
	Pass          int      `json:"pass"`
	Fail          int      `json:"fail"`
	Warn          int      `json:"warn"`
	Info          int      `json:"info"`
	Skip          int      `json:"skip"`
	NotApplicable int      `json:"not_applicable"`
	NotExecuted   int      `json:"not_executed"`
	Text          string   `json:"desc"`
	Checks        []*Check `json:"results"`
}

// Summary is a summary of the results of control checks run.
type Summary struct {
	Pass               int            `json:"total_pass"`
	Fail               int            `json:"total_fail"`
	Warn               int            `json:"total_warn"`
	Info               int            `json:"total_info"`
	Skip               int            `json:"total_skip,omitempty"`
	NotApplicable      int            `json:"total_not_applicable,omitempty"`
	NotExecuted        int            `json:"total_not_executed,omitempty"`
	NotExecutedReasons map[string]int `json:"not_executed_reasons,omitempty"`
	DependencyMode     bool           `json:"-"`
}

// Total returns the number of checks represented by this summary.
func (s Summary) Total() int {
	return s.Pass + s.Fail + s.Warn + s.Info + s.Skip + s.NotApplicable + s.NotExecuted
}

// MarshalJSON omits dependency-only counters in legacy mode while preserving
// complete zero-valued counters when dependency reporting is enabled.
func (s Summary) MarshalJSON() ([]byte, error) {
	type legacySummary struct {
		Pass int `json:"total_pass"`
		Fail int `json:"total_fail"`
		Warn int `json:"total_warn"`
		Info int `json:"total_info"`
	}
	legacy := legacySummary{Pass: s.Pass, Fail: s.Fail, Warn: s.Warn, Info: s.Info}
	if !s.DependencyMode && s.Skip == 0 && s.NotApplicable == 0 && s.NotExecuted == 0 && len(s.NotExecutedReasons) == 0 {
		return json.Marshal(legacy)
	}

	type extendedSummary struct {
		legacySummary
		Skip               int            `json:"total_skip"`
		NotApplicable      int            `json:"total_not_applicable"`
		NotExecuted        int            `json:"total_not_executed"`
		NotExecutedReasons map[string]int `json:"not_executed_reasons,omitempty"`
	}
	return json.Marshal(extendedSummary{
		legacySummary:      legacy,
		Skip:               s.Skip,
		NotApplicable:      s.NotApplicable,
		NotExecuted:        s.NotExecuted,
		NotExecutedReasons: s.NotExecutedReasons,
	})
}

// MarshalJSON keeps the controls payload intact despite Summary implementing
// its own marshaller for aggregate totals.
func (controls Controls) MarshalJSON() ([]byte, error) {
	type controlsJSON struct {
		ID                 string         `json:"id"`
		Version            string         `json:"version"`
		DetectedVersion    string         `json:"detected_version,omitempty"`
		BaselineVersion    string         `json:"baseline_version,omitempty"`
		CheckVersion       string         `json:"check_version,omitempty"`
		VersionComparable  bool           `json:"version_comparable,omitempty"`
		VersionMismatch    bool           `json:"version_mismatch,omitempty"`
		Text               string         `json:"text"`
		Type               NodeType       `json:"node_type"`
		NodeName           string         `json:"node_name,omitempty"`
		DependencyChecking bool           `json:"dependency_checking,omitempty"`
		Groups             []*Group       `json:"tests"`
		AuditTrail         []AuditEvent   `json:"audit_trail,omitempty"`
		Pass               int            `json:"total_pass"`
		Fail               int            `json:"total_fail"`
		Warn               int            `json:"total_warn"`
		Info               int            `json:"total_info"`
		Skip               *int           `json:"total_skip,omitempty"`
		NotApplicable      *int           `json:"total_not_applicable,omitempty"`
		NotExecuted        *int           `json:"total_not_executed,omitempty"`
		NotExecutedReasons map[string]int `json:"not_executed_reasons,omitempty"`
	}

	var skip, notApplicable, notExecuted *int
	reasons := controls.Summary.NotExecutedReasons
	if controls.Summary.DependencyMode || controls.Summary.Skip != 0 {
		skip = &controls.Summary.Skip
	}
	if controls.Summary.DependencyMode || controls.Summary.NotApplicable != 0 {
		notApplicable = &controls.Summary.NotApplicable
	}
	if controls.Summary.DependencyMode || controls.Summary.NotExecuted != 0 {
		notExecuted = &controls.Summary.NotExecuted
	}

	return json.Marshal(controlsJSON{
		ID:                 controls.ID,
		Version:            controls.Version,
		DetectedVersion:    controls.DetectedVersion,
		BaselineVersion:    controls.BaselineVersion,
		CheckVersion:       controls.CheckVersion,
		VersionComparable:  controls.VersionComparable,
		VersionMismatch:    controls.VersionMismatch,
		Text:               controls.Text,
		Type:               controls.Type,
		NodeName:           controls.NodeName,
		DependencyChecking: controls.DependencyChecking,
		Groups:             controls.Groups,
		AuditTrail:         controls.AuditTrail,
		Pass:               controls.Summary.Pass,
		Fail:               controls.Summary.Fail,
		Warn:               controls.Summary.Warn,
		Info:               controls.Summary.Info,
		Skip:               skip,
		NotApplicable:      notApplicable,
		NotExecuted:        notExecuted,
		NotExecutedReasons: reasons,
	})
}

// Predicate a predicate on the given Group and Check arguments.
type Predicate func(group *Group, check *Check) bool

// NewControls instantiates a new master Controls object.
func NewControls(t NodeType, in []byte, detectedVersion string) (*Controls, error) {
	c := new(Controls)

	err := yaml.Unmarshal(in, c)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML: %s", err)
	}

	if t != c.Type {
		return nil, fmt.Errorf("non-%s controls file specified", t)
	}
	c.DetectedVersion = detectedVersion
	c.BaselineVersion = c.Version
	c.reconcileVersions()

	if err := ValidateDependencies(c.Groups); err != nil {
		return nil, err
	}
	for _, group := range c.Groups {
		for _, check := range group.Checks {
			if _, err := check.TimeoutDuration(); err != nil {
				return nil, err
			}
		}
	}
	return c, nil
}

// SetBaselineVersion verifies that the loaded benchmark matches the benchmark
// selected for the run.
func (controls *Controls) SetBaselineVersion(version string) {
	if version != "" {
		controls.BaselineVersion = version
	}
	controls.reconcileVersions()
}

func (controls *Controls) reconcileVersions() {
	if controls.BaselineVersion == "" {
		controls.BaselineVersion = controls.Version
	}

	declared := make([]string, 0)
	seen := make(map[string]bool)
	for _, group := range controls.Groups {
		for _, check := range group.Checks {
			check.BaselineVersion = controls.BaselineVersion
			if check.Version == "" {
				continue
			}
			if !seen[check.Version] {
				seen[check.Version] = true
				declared = append(declared, check.Version)
			}
			check.VersionMismatch = controls.BaselineVersion == "" || check.Version != controls.BaselineVersion
		}
	}

	switch len(declared) {
	case 0:
		controls.CheckVersion = controls.Version
		if controls.CheckVersion == "" {
			controls.CheckVersion = controls.BaselineVersion
		}
	case 1:
		controls.CheckVersion = declared[0]
	default:
		controls.CheckVersion = "mixed:" + strings.Join(declared, ",")
	}

	controls.VersionMismatch = controls.BaselineVersion == "" && controls.CheckVersion != "" ||
		controls.BaselineVersion != "" &&
			(controls.Version != "" && controls.Version != controls.BaselineVersion ||
				controls.CheckVersion != "" && controls.CheckVersion != controls.BaselineVersion)
	controls.VersionComparable = !controls.VersionMismatch && controls.BaselineVersion != ""
}

// RunOptions controls the dependency-aware execution mode.
type RunOptions struct {
	// DependencyChecking enables explicit check dependencies, four-state
	// reporting, and execution audit records.
	DependencyChecking bool
	// EnableDependencies is an alias accepted by callers that use the CLI flag
	// spelling in code.
	EnableDependencies bool
	// CheckDependencies is an alias for DependencyChecking.
	CheckDependencies bool
	// Timeout is applied to checks that do not declare their own timeout.
	Timeout time.Duration
}

func (opts RunOptions) dependencyChecking() bool {
	return opts.DependencyChecking || opts.EnableDependencies || opts.CheckDependencies
}

// RunChecks runs the checks with the given Runner. Only checks for which the filter Predicate returns `true` will run.
func (controls *Controls) RunChecks(runner Runner, filter Predicate, skipIDMap map[string]bool) Summary {
	return controls.RunChecksWithOptions(runner, filter, skipIDMap, RunOptions{
		DependencyChecking: controls.DependencyChecking,
	})
}

// RunChecksWithOptions runs checks using the same Runner as RunChecks while
// optionally enforcing dependencies from the check declarations.
func (controls *Controls) RunChecksWithOptions(runner Runner, filter Predicate, skipIDMap map[string]bool, opts RunOptions) Summary {
	summary, err := controls.RunChecksWithOptionsChecked(runner, filter, skipIDMap, opts)
	if err != nil {
		glog.Errorf("invalid check dependency graph: %v", err)
	}
	return summary
}

// RunChecksWithOptionsChecked is the error-returning variant of
// RunChecksWithOptions, useful when checks were constructed without NewControls.
func (controls *Controls) RunChecksWithOptionsChecked(runner Runner, filter Predicate, skipIDMap map[string]bool, opts RunOptions) (Summary, error) {
	controls.DependencyChecking = opts.dependencyChecking()
	controls.resetSummary()
	controls.Summary.DependencyMode = controls.DependencyChecking

	if err := ValidateDependencies(controls.Groups); err != nil {
		return controls.Summary, err
	}

	if controls.DependencyChecking {
		return controls.runChecksWithDependencies(runner, filter, skipIDMap, opts), nil
	}
	return controls.runChecksLegacy(runner, filter, skipIDMap, opts), nil
}

func (controls *Controls) resetSummary() {
	controls.Summary = Summary{}
}

func (controls *Controls) runChecksLegacy(runner Runner, filter Predicate, skipIDMap map[string]bool, opts RunOptions) Summary {
	var g []*Group
	m := make(map[string]*Group)

	for _, group := range controls.Groups {
		for _, check := range group.Checks {

			if !filter(group, check) {
				continue
			}

			_, groupSkippedViaCmd := skipIDMap[group.ID]
			_, checkSkippedViaCmd := skipIDMap[check.ID]

			if group.Type == SKIP || groupSkippedViaCmd || checkSkippedViaCmd {
				check.Type = SKIP
			}

			check.timeout = opts.Timeout
			state := runner.Run(check)
			check.State = state

			check.TestInfo = append(check.TestInfo, check.Remediation)

			// Check if we have already added this checks group.
			if v, ok := m[group.ID]; !ok {
				// Create a group with same info
				w := &Group{
					ID:     group.ID,
					Text:   group.Text,
					Checks: []*Check{},
				}

				// Add this check to the new group
				w.Checks = append(w.Checks, check)
				summarizeGroup(w, state)

				// Add to groups we have visited.
				m[w.ID] = w
				g = append(g, w)
			} else {
				v.Checks = append(v.Checks, check)
				summarizeGroup(v, state)
			}

			summarize(controls, state)
		}
	}

	controls.Groups = g
	controls.collectReasonCounts()
	return controls.Summary
}

type checkSelection struct {
	group *Group
	check *Check
}

func (controls *Controls) runChecksWithDependencies(runner Runner, filter Predicate, skipIDMap map[string]bool, opts RunOptions) Summary {
	var selected []checkSelection
	selectedByID := make(map[string]*Check)

	for _, group := range controls.Groups {
		for _, check := range group.Checks {
			if !filter(group, check) {
				continue
			}

			_, groupSkippedViaCmd := skipIDMap[group.ID]
			_, checkSkippedViaCmd := skipIDMap[check.ID]
			if group.Type == SKIP || groupSkippedViaCmd || checkSkippedViaCmd {
				check.Type = SKIP
			}

			selected = append(selected, checkSelection{group: group, check: check})
			if _, exists := selectedByID[check.ID]; !exists {
				selectedByID[check.ID] = check
			}
		}
	}

	ordered := orderSelectedChecks(selected, selectedByID)
	groupOrder := make([]*Group, 0)
	groupResults := make(map[string]*Group)
	states := make(map[string]State)

	for _, selection := range ordered {
		group := selection.group
		check := selection.check
		check.timeout = opts.Timeout
		check.DistinguishStates = true

		previousState := check.State
		previousBlocked := check.WasBlocked

		if state, reason, category, declared := declaredCheckState(check); declared {
			check.State = state
			check.Reason = reason
			check.ReasonCategory = category
			controls.recordAudit(check, previousState, state, "declared by check configuration", category, check.BlockedBy)
			controls.addCheckResult(group, check, state, &groupOrder, groupResults)
			states[check.ID] = state
			continue
		}

		if shouldEvaluateDependencies(check) {
			category, reason, blockedBy := dependencyBlock(check, selectedByID, states)
			if category != "" {
				check.State = NOT_EXECUTED
				check.ReasonCategory = category
				check.Reason = reason
				check.BlockedBy = uniqueStrings(append(check.BlockedBy, blockedBy...))
				check.WasBlocked = true
				controls.recordAudit(check, previousState, check.State, "dependency prerequisites not satisfied", category, blockedBy)
				controls.addCheckResult(group, check, check.State, &groupOrder, groupResults)
				states[check.ID] = check.State
				continue
			}
		}

		check.Reason = ""
		check.ReasonCategory = ""
		state := runner.Run(check)
		if state == "" {
			state = check.State
		}
		check.State = state

		condition := "check executed"
		if previousState == NOT_EXECUTED && state == PASS {
			condition = "dependencies satisfied after previous block"
			if previousBlocked && len(check.BlockedBy) > 0 {
				condition = "dependencies satisfied; previously blocked by " + strings.Join(check.BlockedBy, ",")
			}
		}
		controls.recordAudit(check, previousState, state, condition, check.ReasonCategory, check.BlockedBy)
		controls.addCheckResult(group, check, state, &groupOrder, groupResults)
		states[check.ID] = state
	}

	controls.Groups = groupOrder
	controls.collectReasonCounts()
	return controls.Summary
}

func (controls *Controls) collectReasonCounts() {
	controls.Summary.NotExecutedReasons = nil
	for _, group := range controls.Groups {
		for _, check := range group.Checks {
			if check.State != NOT_EXECUTED {
				continue
			}
			if controls.Summary.NotExecutedReasons == nil {
				controls.Summary.NotExecutedReasons = make(map[string]int)
			}
			category := check.ReasonCategory
			if category == "" {
				category = "unspecified"
			}
			controls.Summary.NotExecutedReasons[category]++
		}
	}
}

func declaredCheckState(check *Check) (State, string, string, bool) {
	if check.Type == SKIP {
		return SKIPPED, "Test marked as skip", ReasonExplicitSkip, true
	}
	if strings.EqualFold(check.Type, NOT_APPLICABLE_TYPE) ||
		strings.EqualFold(check.Type, "not-applicable") ||
		strings.EqualFold(check.Type, "n/a") {
		return NOT_APPLICABLE, "Test marked as not applicable", ReasonNotApplicable, true
	}
	if check.Applicable != nil && !*check.Applicable {
		return NOT_APPLICABLE, "Check is not applicable to this target", ReasonNotApplicable, true
	}
	if check.Enabled != nil && !*check.Enabled {
		return NOT_EXECUTED, "Check disabled by configuration", ReasonConfigurationDisallowed, true
	}
	return "", "", "", false
}

func orderSelectedChecks(selected []checkSelection, selectedByID map[string]*Check) []checkSelection {
	byCheck := make(map[*Check]checkSelection, len(selected))
	for _, selection := range selected {
		byCheck[selection.check] = selection
	}

	visited := make(map[*Check]bool, len(selected))
	ordered := make([]checkSelection, 0, len(selected))
	var visit func(*Check)
	visit = func(check *Check) {
		if check == nil || visited[check] {
			return
		}
		visited[check] = true
		for _, dependencyID := range check.Dependencies() {
			visit(selectedByID[dependencyID])
		}
		ordered = append(ordered, byCheck[check])
	}
	for _, selection := range selected {
		visit(selection.check)
	}
	return ordered
}

func shouldEvaluateDependencies(check *Check) bool {
	if check.Type == SKIP || strings.EqualFold(check.Type, NOT_APPLICABLE_TYPE) ||
		strings.EqualFold(check.Type, "not-applicable") || strings.EqualFold(check.Type, "n/a") {
		return false
	}
	if check.Applicable != nil && !*check.Applicable {
		return false
	}
	if check.Enabled != nil && !*check.Enabled {
		return false
	}
	return len(check.Dependencies()) > 0
}

func dependencyBlock(check *Check, selectedByID map[string]*Check, states map[string]State) (category, reason string, blockedBy []string) {
	for _, dependencyID := range check.Dependencies() {
		dependency, selected := selectedByID[dependencyID]
		if !selected {
			blockedBy = append(blockedBy, dependencyID)
			category = ReasonDependencyMissing
			reason = fmt.Sprintf("dependency %s was not selected for this run", dependencyID)
			continue
		}

		state, executed := states[dependencyID]
		if !executed {
			blockedBy = append(blockedBy, dependencyID)
			category = ReasonDependencyMissing
			reason = fmt.Sprintf("dependency %s was not executed", dependencyID)
			continue
		}
		if state != PASS {
			blockedBy = append(blockedBy, dependencyID)
			category = ReasonPrerequisiteFailed
			reason = fmt.Sprintf("dependency %s is %s", dependencyID, state)
			if dependency != nil && dependency.State != "" {
				reason = fmt.Sprintf("dependency %s is %s", dependencyID, dependency.State)
			}
		}
	}
	return category, reason, uniqueStrings(blockedBy)
}

func (controls *Controls) addCheckResult(group *Group, check *Check, state State, groupOrder *[]*Group, groupResults map[string]*Group) {
	check.TestInfo = append(check.TestInfo, check.Remediation)

	resultGroup, exists := groupResults[group.ID]
	if !exists {
		resultGroup = &Group{
			ID:     group.ID,
			Type:   group.Type,
			Text:   group.Text,
			Checks: []*Check{},
		}
		groupResults[group.ID] = resultGroup
		*groupOrder = append(*groupOrder, resultGroup)
	}
	resultGroup.Checks = append(resultGroup.Checks, check)
	summarizeGroup(resultGroup, state)
	summarize(controls, state)
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

// JSON encodes the results of last run to JSON.
func (controls *Controls) JSON() ([]byte, error) {
	return json.Marshal(controls)
}

// JUnit encodes the results of last run to JUnit.
func (controls *Controls) JUnit() ([]byte, error) {
	suite := reporters.JUnitTestSuite{
		Name:      controls.Text,
		TestCases: []reporters.JUnitTestCase{},
		Tests:     controls.Summary.Total(),
		Failures:  controls.Summary.Fail,
	}
	for _, g := range controls.Groups {
		for _, check := range g.Checks {
			jsonCheck := ""
			jsonBytes, err := json.Marshal(check)
			if err != nil {
				jsonCheck = fmt.Sprintf("Failed to marshal test into JSON: %v. Test as text: %#v", err, check)
			} else {
				jsonCheck = string(jsonBytes)
			}
			tc := reporters.JUnitTestCase{
				Name:      fmt.Sprintf("%v %v", check.ID, check.Text),
				ClassName: g.Text,

				// Store the entire json serialization as system out so we don't lose data in cases where deeper debugging is necessary.
				SystemOut: jsonCheck,
			}

			switch check.State {
			case FAIL:
				tc.FailureMessage = &reporters.JUnitFailureMessage{Message: check.Remediation}
			case WARN, INFO, SKIPPED, NOT_APPLICABLE, NOT_EXECUTED,
				State(SKIP), "SKIPPED", "skipped", "not_applicable", "NOT EXECUTED", "not_executed":
				// WARN and INFO are two different versions of skipped tests. Either way it would be a false positive/negative to report
				// it any other way.
				tc.Skipped = &reporters.JUnitSkipped{}
			case PASS:
			default:
				glog.Warningf("Unrecognized state %s", check.State)
			}

			suite.TestCases = append(suite.TestCases, tc)
		}
	}

	var b bytes.Buffer
	encoder := xml.NewEncoder(&b)
	encoder.Indent("", "    ")
	err := encoder.Encode(suite)
	if err != nil {
		return nil, fmt.Errorf("Failed to generate JUnit report: %s", err.Error())
	}

	return b.Bytes(), nil
}

// ASFF encodes the results of last run to AWS Security Finding Format(ASFF).
func (controls *Controls) ASFF() ([]types.AwsSecurityFinding, error) {
	fs := []types.AwsSecurityFinding{}
	account, err := getConfig("AWS_ACCOUNT")
	if err != nil {
		return nil, err
	}
	cluster, err := getConfig("CLUSTER_ARN")
	if err != nil {
		return nil, err
	}
	region, err := getConfig("AWS_REGION")
	if err != nil {
		return nil, err
	}
	nodeName, _ := getConfig("NODE_NAME")
	arn := fmt.Sprintf(ARN, region)

	ti := time.Now()
	tf := ti.Format(time.RFC3339)
	for _, g := range controls.Groups {
		for _, check := range g.Checks {
			if check.State == FAIL || check.State == WARN {
				// ASFF ProductFields['Actual result'] can't be longer than 1024 characters
				actualValue := check.ActualValue
				remediation := check.Remediation
				reason := check.Reason

				if len(check.ActualValue) > 1024 {
					actualValue = check.ActualValue[0:1023]
				}

				// Fix issue https://github.com/aquasecurity/kube-bench/issues/903
				if len(check.Remediation) > 512 {
					remediation = check.Remediation[0:511]
				}

				if len(check.Reason) > 1024 {
					reason = check.Reason[0:1023]
				}
				id := aws.String(fmt.Sprintf("%s%sEKSnodeID+%s+%s", arn, account, check.ID, cluster))
				if nodeName != "" {
					id = aws.String(fmt.Sprintf("%s%sEKSnodeID+%s+%s+%s", arn, account, check.ID, cluster, nodeName))
				}

				f := types.AwsSecurityFinding{
					AwsAccountId:  aws.String(account),
					Confidence:    aws.Int32(100),
					GeneratorId:   aws.String(fmt.Sprintf("%s/cis-kubernetes-benchmark/%s/%s", arn, controls.Version, check.ID)),
					Id:            id,
					CreatedAt:     aws.String(tf),
					Description:   aws.String(check.Text),
					ProductArn:    aws.String(arn),
					SchemaVersion: aws.String(SCHEMA),
					Title:         aws.String(fmt.Sprintf("%s %s", check.ID, check.Text)),
					UpdatedAt:     aws.String(tf),
					Types:         []string{*aws.String(TYPE)},
					Severity: &types.Severity{
						Label: types.SeverityLabelHigh,
					},
					Remediation: &types.Remediation{
						Recommendation: &types.Recommendation{
							Text: aws.String(remediation),
						},
					},
					ProductFields: map[string]string{
						"Reason":          reason,
						"Actual result":   actualValue,
						"Expected result": check.ExpectedResult,
						"Section":         fmt.Sprintf("%s %s", controls.ID, controls.Text),
						"Subsection":      fmt.Sprintf("%s %s", g.ID, g.Text),
					},
					Resources: []types.Resource{
						{
							Id:   aws.String(cluster),
							Type: aws.String(TYPE),
						},
					},
				}
				fs = append(fs, f)
			}
		}
	}
	return fs, nil
}

func getConfig(name string) (string, error) {
	r := viper.GetString(name)
	if len(r) == 0 {
		return "", fmt.Errorf("%s not set", name)
	}
	return r, nil
}

func summarize(controls *Controls, state State) {
	switch state {
	case PASS:
		controls.Summary.Pass++
	case FAIL:
		controls.Summary.Fail++
	case WARN:
		controls.Summary.Warn++
	case INFO:
		controls.Summary.Info++
	case SKIPPED, State(SKIP), "SKIPPED", "skipped":
		controls.Summary.Skip++
	case NOT_APPLICABLE, "not_applicable":
		controls.Summary.NotApplicable++
	case NOT_EXECUTED, "not_executed":
		controls.Summary.NotExecuted++
	default:
		glog.Warningf("Unrecognized state %s", state)
	}
}

func summarizeGroup(group *Group, state State) {
	switch state {
	case PASS:
		group.Pass++
	case FAIL:
		group.Fail++
	case WARN:
		group.Warn++
	case INFO:
		group.Info++
	case SKIPPED, State(SKIP), "SKIPPED", "skipped":
		group.Skip++
	case NOT_APPLICABLE, "not_applicable":
		group.NotApplicable++
	case NOT_EXECUTED, "not_executed":
		group.NotExecuted++
	default:
		glog.Warningf("Unrecognized state %s", state)
	}
}
