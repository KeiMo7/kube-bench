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
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
	"github.com/golang/glog"
	"github.com/onsi/ginkgo/reporters"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

const (
	// AWS_ACCOUNT_UNKNOWN is when the AWS account can't be found
	AWS_ACCOUNT_UNKNOWN = "Unknown"
	// ARN for the AWS Security Hub service
	ARN = "arn:aws:securityhub:%s::product/aqua-security/kube-bench"
	// SCHEMA for the AWS Security Hub service
	SCHEMA = "2018-10-08"
	// TYPE is type of Security Hub finding
	TYPE = "Software and Configuration Checks/Industry and Regulatory Standards/CIS Kubernetes Benchmark"
)

type OverallControls struct {
	Controls []*Controls
	Totals   Summary
}

// Controls holds all controls to check for master nodes.
type Controls struct {
	ID              string   `yaml:"id" json:"id"`
	Version         string   `json:"version"`
	DetectedVersion string   `json:"detected_version,omitempty"`
	Text            string   `json:"text"`
	Type            NodeType `json:"node_type"`
	Groups          []*Group `json:"tests"`
	Summary
}

// Group is a collection of similar checks.
type Group struct {
	ID      string   `yaml:"id" json:"section"`
	Type    string   `yaml:"type" json:"type"`
	Pass    int      `json:"pass"`
	Fail    int      `json:"fail"`
	Warn    int      `json:"warn"`
	Info    int      `json:"info"`
	Unknown int      `json:"unknown"`
	Text    string   `json:"desc"`
	Checks  []*Check `json:"results"`
}

// Summary is a summary of the results of control checks run.
type Summary struct {
	Pass int `json:"total_pass"`
	Fail int `json:"total_fail"`
	Warn int `json:"total_warn"`
	Info int `json:"total_info"`
	// Unknown counts checks that could not be evaluated. It is excluded
	// from the compliance-rate numerator and denominator.
	Unknown int `json:"total_unknown"`
}

// Evaluated returns the number of checks that reached an evaluated
// conclusion (PASS, FAIL, WARN or INFO).
func (s Summary) Evaluated() int {
	return s.Pass + s.Fail + s.Warn + s.Info
}

// Total returns the total number of checks: evaluated plus unable to
// evaluate. The two groups are mutually exclusive.
func (s Summary) Total() int {
	return s.Evaluated() + s.Unknown
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
	return c, nil
}

// RunChecks runs the checks with the given Runner. Only checks for which the filter Predicate returns `true` will run.
func (controls *Controls) RunChecks(runner Runner, filter Predicate, skipIDMap map[string]bool) Summary {
	var g []*Group
	m := make(map[string]*Group)
	controls.Summary.Pass, controls.Summary.Fail, controls.Summary.Warn, controls.Summary.Info, controls.Summary.Unknown = 0, 0, 0, 0, 0

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

			state := runner.Run(check)

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
	return controls.Summary
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
		Tests:     controls.Summary.Pass + controls.Summary.Fail + controls.Summary.Info + controls.Summary.Warn + controls.Summary.Unknown,
		Failures:  controls.Summary.Fail,
		Errors:    controls.Summary.Unknown,
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
			case WARN, INFO:
				// WARN and INFO are two different versions of skipped tests. Either way it would be a false positive/negative to report
				// it any other way.
				tc.Skipped = &reporters.JUnitSkipped{}
			case UNKNOWN:
				// UNKNOWN means the check could not be evaluated. JUnit has
				// no dedicated state for this; report it as a skipped test
				// with an explicit message rather than silently passing it.
				msg := check.Reason
				if msg == "" {
					msg = "check could not be evaluated"
				}
				tc.Skipped = &reporters.JUnitSkipped{Message: fmt.Sprintf("UNKNOWN: %s", msg)}
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
			// FAIL and WARN keep their historical HIGH severity so the
			// alerting chain keeps recognizing them; UNKNOWN findings are
			// reported as INFORMATIONAL so they stay visible without
			// paging as violations.
			severity := types.SeverityLabelHigh
			switch check.State {
			case FAIL, WARN:
			case UNKNOWN:
				severity = types.SeverityLabelInformational
			default:
				continue
			}
			{
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
						Label: severity,
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
						"State":           string(check.State),
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
	if !controls.Summary.add(state, 1) {
		glog.Warningf("Unrecognized state %s", state)
	}
}

func summarizeGroup(group *Group, state State) {
	if !group.add(state, 1) {
		glog.Warningf("Unrecognized state %s", state)
	}
}

// add adjusts the count for the given state by delta. It reports whether
// the state was recognized.
func (s *Summary) add(state State, delta int) bool {
	switch state {
	case PASS:
		s.Pass += delta
	case FAIL:
		s.Fail += delta
	case WARN:
		s.Warn += delta
	case INFO:
		s.Info += delta
	case UNKNOWN:
		s.Unknown += delta
	default:
		return false
	}
	return true
}

// add adjusts the group count for the given state by delta. It reports
// whether the state was recognized.
func (g *Group) add(state State, delta int) bool {
	switch state {
	case PASS:
		g.Pass += delta
	case FAIL:
		g.Fail += delta
	case WARN:
		g.Warn += delta
	case INFO:
		g.Info += delta
	case UNKNOWN:
		g.Unknown += delta
	default:
		return false
	}
	return true
}

// OverrideResult applies a manual review decision to the check with the
// given ID: the new conclusion replaces the old one, the original
// conclusion and reason are preserved on the check, and the summaries are
// adjusted so the counts stay consistent.
func (controls *Controls) OverrideResult(checkID string, state State, reason string) error {
	for _, g := range controls.Groups {
		for _, c := range g.Checks {
			if c.ID != checkID {
				continue
			}
			old := c.State
			c.Override(state, reason)
			if old != "" && old != state {
				controls.Summary.add(old, -1)
				controls.Summary.add(state, 1)
				g.add(old, -1)
				g.add(state, 1)
			} else if old == "" {
				controls.Summary.add(state, 1)
				g.add(state, 1)
			}
			return nil
		}
	}
	return fmt.Errorf("check %s not found", checkID)
}
