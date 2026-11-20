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
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/golang/glog"
)

// NodeType indicates the type of node (master, node).
type NodeType string

// State is the state of a control check.
type State string

const (
	// PASS check passed.
	PASS State = "PASS"
	// FAIL check failed.
	FAIL State = "FAIL"
	// WARN could not carry out check.
	WARN State = "WARN"
	// INFO informational message
	INFO State = "INFO"
	// SKIPPED check was explicitly skipped by configuration or command line.
	SKIPPED State = "SKIP"
	// NOT_APPLICABLE check does not apply to the scanned target.
	NOT_APPLICABLE State = "NOT_APPLICABLE"
	// NOT_EXECUTED check could not be executed because a prerequisite was not met.
	NOT_EXECUTED State = "NOT_EXECUTED"

	// SKIP for when a check should be skipped.
	SKIP = "skip"

	// NOT_APPLICABLE_TYPE marks a check as not applicable.
	NOT_APPLICABLE_TYPE = "not_applicable"

	// MASTER a master node
	MASTER NodeType = "master"
	// NODE a node
	NODE NodeType = "node"
	// FEDERATED a federated deployment.
	FEDERATED NodeType = "federated"

	// ETCD an etcd node
	ETCD NodeType = "etcd"
	// CONTROLPLANE a control plane node
	CONTROLPLANE NodeType = "controlplane"
	// POLICIES a node to run policies from
	POLICIES NodeType = "policies"
	// MANAGEDSERVICES a node to run managedservices from
	MANAGEDSERVICES = "managedservices"

	// MANUAL Check Type
	MANUAL string = "manual"
)

const (
	// ReasonPrerequisiteFailed means a dependency was executed but did not pass.
	ReasonPrerequisiteFailed = "prerequisite_failed"
	// ReasonDependencyMissing means a dependency was not selected for this run.
	ReasonDependencyMissing = "dependency_missing"
	// ReasonConfigurationDisallowed means configuration explicitly disabled the check.
	ReasonConfigurationDisallowed = "configuration_disallowed"
	// ReasonTimeout means the check audit exceeded its configured timeout.
	ReasonTimeout = "timeout"
	// ReasonExplicitSkip means the check or its group was explicitly skipped.
	ReasonExplicitSkip = "explicit_skip"
	// ReasonNotApplicable means the check is outside the target's applicability.
	ReasonNotApplicable = "not_applicable"
	// ReasonConfigurationUnavailable means a required configuration file was unavailable.
	ReasonConfigurationUnavailable = "configuration_unavailable"

	// ReasonDependencyFailed is an alias for prerequisite failure.
	ReasonDependencyFailed = ReasonPrerequisiteFailed
	// ReasonPreconditionFailed is an alias for prerequisite failure.
	ReasonPreconditionFailed = ReasonPrerequisiteFailed
	// ReasonConfigNotAllowed is an alias for configuration-disallowed execution.
	ReasonConfigNotAllowed = ReasonConfigurationDisallowed
)

var (
	// ErrAuditTimeout identifies an audit command that exceeded its timeout.
	ErrAuditTimeout = errors.New("audit command timed out")
	// ErrAuditConfigUnavailable identifies a missing audit configuration file.
	ErrAuditConfigUnavailable = errors.New("audit configuration unavailable")
)

// Check contains information about a recommendation in the
// CIS Kubernetes document.
type Check struct {
	ID                string   `yaml:"id" json:"test_number"`
	Text              string   `json:"test_desc"`
	Audit             string   `json:"audit"`
	AuditEnv          string   `yaml:"audit_env"`
	AuditConfig       string   `yaml:"audit_config"`
	Type              string   `json:"type"`
	Tests             *tests   `json:"-"`
	Set               bool     `json:"-"`
	Remediation       string   `json:"remediation"`
	TestInfo          []string `json:"test_info"`
	State             `json:"status"`
	ActualValue       string       `json:"actual_value"`
	Scored            bool         `json:"scored"`
	IsMultiple        bool         `yaml:"use_multiple_values"`
	ExpectedResult    string       `json:"expected_result"`
	Reason            string       `json:"reason,omitempty"`
	AuditOutput       string       `json:"-"`
	AuditEnvOutput    string       `json:"-"`
	AuditConfigOutput string       `json:"-"`
	DisableEnvTesting bool         `json:"-"`
	DependsOn         []string     `yaml:"depends_on,omitempty" json:"depends_on,omitempty"`
	Requires          []string     `yaml:"requires,omitempty" json:"requires,omitempty"`
	Version           string       `yaml:"version,omitempty" json:"test_version,omitempty"`
	BaselineVersion   string       `yaml:"-" json:"baseline_version,omitempty"`
	Timeout           string       `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	Applicable        *bool        `yaml:"applicable,omitempty" json:"applicable,omitempty"`
	Enabled           *bool        `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	ReasonCategory    string       `json:"reason_category,omitempty"`
	BlockedBy         []string     `json:"blocked_by,omitempty"`
	WasBlocked        bool         `json:"was_blocked,omitempty"`
	VersionMismatch   bool         `json:"version_mismatch,omitempty"`
	AuditTrail        []AuditEvent `json:"audit_trail,omitempty"`
	DistinguishStates bool         `json:"-" yaml:"-"`
	timeout           time.Duration
}

// Dependencies returns the unique dependency IDs declared by a check. Both
// depends_on and requires are accepted for backwards-compatible configuration.
func (c *Check) Dependencies() []string {
	seen := make(map[string]bool)
	var dependencies []string
	for _, id := range append(append([]string{}, c.DependsOn...), c.Requires...) {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		dependencies = append(dependencies, id)
	}
	return dependencies
}

// TimeoutDuration returns the configured timeout. A bare integer is treated
// as seconds for convenient YAML configuration.
func (c *Check) TimeoutDuration() (time.Duration, error) {
	value := strings.TrimSpace(c.Timeout)
	if value == "" {
		return c.timeout, nil
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		if seconds < 0 {
			return 0, fmt.Errorf("invalid timeout %q for check %s", c.Timeout, c.ID)
		}
		return time.Duration(seconds) * time.Second, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration < 0 {
		return 0, fmt.Errorf("invalid timeout %q for check %s", c.Timeout, c.ID)
	}
	return duration, nil
}

// Runner wraps the basic Run method.
type Runner interface {
	// Run runs a given check and returns the execution state.
	Run(c *Check) State
}

// NewRunner constructs a default Runner.
func NewRunner() Runner {
	return &defaultRunner{}
}

type defaultRunner struct{}

func (r *defaultRunner) Run(c *Check) State {
	return c.run()
}

// Run executes the audit commands specified in a check and outputs
// the results.
func (c *Check) run() State {
	glog.V(3).Infof("-----   Running check %v   -----", c.ID)

	if c.Enabled != nil && !*c.Enabled {
		c.Reason = "Check disabled by configuration"
		c.ReasonCategory = ReasonConfigurationDisallowed
		c.State = NOT_EXECUTED
		glog.V(3).Info(c.Reason)
		return c.State
	}

	if c.Applicable != nil && !*c.Applicable {
		c.Reason = "Check is not applicable to this target"
		c.ReasonCategory = ReasonNotApplicable
		c.State = NOT_APPLICABLE
		glog.V(3).Info(c.Reason)
		return c.State
	}

	if _, err := c.TimeoutDuration(); err != nil {
		c.Reason = err.Error()
		c.ReasonCategory = ReasonConfigurationDisallowed
		c.State = NOT_EXECUTED
		glog.V(3).Info(c.Reason)
		return c.State
	}

	// Since this is an Scored check
	// without tests return a 'WARN' to alert
	// the user that this check needs attention
	if c.Scored && strings.TrimSpace(c.Type) == "" && c.Tests == nil {
		c.Reason = "There are no tests"
		c.State = WARN
		glog.V(3).Info(c.Reason)
		return c.State
	}

	// If check type is skip, preserve the legacy INFO state by default and use
	// the explicit SKIPPED state when dependency-aware reporting is enabled.
	if c.Type == SKIP {
		c.Reason = "Test marked as skip"
		c.ReasonCategory = ReasonExplicitSkip
		if c.DistinguishStates {
			c.State = SKIPPED
		} else {
			c.State = INFO
		}
		glog.V(3).Info(c.Reason)
		return c.State
	}

	if strings.EqualFold(c.Type, NOT_APPLICABLE_TYPE) || strings.EqualFold(c.Type, "not-applicable") || strings.EqualFold(c.Type, "n/a") {
		c.Reason = "Test marked as not applicable"
		c.ReasonCategory = ReasonNotApplicable
		c.State = NOT_APPLICABLE
		glog.V(3).Info(c.Reason)
		return c.State
	}

	// If check type is manual force result to WARN
	if c.Type == MANUAL {
		c.Reason = "Test marked as a manual test"
		c.State = WARN
		glog.V(3).Info(c.Reason)
		return c.State
	}

	// If there aren't any tests defined this is a FAIL or WARN
	if c.Tests == nil || len(c.Tests.TestItems) == 0 {
		c.Reason = "No tests defined"
		if c.Scored {
			c.State = FAIL
		} else {
			c.State = WARN
		}
		glog.V(3).Info(c.Reason)
		return c.State
	}

	// Command line parameters override the setting in the config file, so if we get a good result from the Audit command that's all we need to run
	var finalOutput *testOutput
	var lastCommand string

	lastCommand, err := c.runAuditCommands()
	if err == nil {
		finalOutput, err = c.execute()
	}

	if finalOutput != nil {
		if finalOutput.testResult {
			c.State = PASS
		} else {
			if c.Scored {
				c.State = FAIL
			} else {
				c.State = WARN
			}
		}

		c.ActualValue = finalOutput.actualResult
		c.ExpectedResult = finalOutput.ExpectedResult
	}

	if err != nil {
		c.Reason = err.Error()
		if errors.Is(err, ErrAuditTimeout) {
			c.ReasonCategory = ReasonTimeout
			c.State = NOT_EXECUTED
		} else if errors.Is(err, ErrAuditConfigUnavailable) {
			c.ReasonCategory = ReasonConfigurationUnavailable
			c.State = SKIPPED
		} else if c.Scored {
			c.State = FAIL
		} else {
			c.State = WARN
		}
		glog.V(3).Info(c.Reason)
	}

	if finalOutput != nil {
		glog.V(3).Infof("Command: %q TestResult: %t State: %q \n", lastCommand, finalOutput.testResult, c.State)
	} else {
		glog.V(3).Infof("Command: %q TestResult: <<EMPTY>> \n", lastCommand)
	}

	if c.Reason != "" {
		glog.V(2).Info(c.Reason)
	}
	return c.State
}

func (c *Check) runAuditCommands() (lastCommand string, err error) {
	timeout, err := c.TimeoutDuration()
	if err != nil {
		return "", err
	}

	// Always run auditEnvOutput if needed
	if c.AuditEnv != "" {
		c.AuditEnvOutput, err = runAuditWithTimeout(c.AuditEnv, timeout)
		if err != nil {
			return c.AuditEnv, err
		}
	}

	// Run the audit command and auditConfig commands, if present
	c.AuditOutput, err = runAuditWithTimeout(c.Audit, timeout)
	if err != nil {
		return c.Audit, err
	}

	c.AuditConfigOutput, err = runAuditWithTimeout(c.AuditConfig, timeout)
	// when file not found then error comes as exit status 127
	// in some env same error comes as exit status 1
	if err != nil && (strings.Contains(err.Error(), "exit status 127") ||
		strings.Contains(err.Error(), "No such file or directory")) {
		if c.DistinguishStates {
			c.AuditConfigOutput = ""
			return c.AuditConfig, fmt.Errorf("%w: %v", ErrAuditConfigUnavailable, err)
		}
		if c.AuditEnvOutput != "" || c.AuditOutput != "" {
			// Legacy behavior: suppress file not found when there is Audit or
			// auditEnv output present.
			glog.V(3).Info(err)
			err = nil
			c.AuditConfigOutput = ""
		}
	}
	return c.AuditConfig, err
}

func (c *Check) execute() (finalOutput *testOutput, err error) {
	finalOutput = &testOutput{}

	ts := c.Tests
	res := make([]testOutput, len(ts.TestItems))
	expectedResultArr := make([]string, len(res))

	glog.V(3).Infof("Running %d test_items", len(ts.TestItems))
	for i, t := range ts.TestItems {

		t.isMultipleOutput = c.IsMultiple

		// Try with the auditOutput first, and if that's not found, try the auditConfigOutput
		t.auditUsed = AuditCommand
		result := *(t.execute(c.AuditOutput))

		// Check for AuditConfigOutput only if AuditConfig is set and auditConfigOutput is not empty
		if !result.flagFound && c.AuditConfig != "" && c.AuditConfigOutput != "" {
			// t.isConfigSetting = true
			t.auditUsed = AuditConfig
			result = *(t.execute(c.AuditConfigOutput))
			if !result.flagFound && t.Env != "" {
				t.auditUsed = AuditEnv
				result = *(t.execute(c.AuditEnvOutput))
			}
		}

		if !result.flagFound && t.Env != "" {
			t.auditUsed = AuditEnv
			result = *(t.execute(c.AuditEnvOutput))
		}
		glog.V(2).Infof("Used %s", t.auditUsed)
		res[i] = result
		expectedResultArr[i] = res[i].ExpectedResult
	}

	var result bool
	// If no binary operation is specified, default to AND
	switch ts.BinOp {
	default:
		glog.V(2).Info(fmt.Sprintf("unknown binary operator for tests %s\n", ts.BinOp))
		finalOutput.actualResult = fmt.Sprintf("unknown binary operator for tests %s\n", ts.BinOp)
		return finalOutput, fmt.Errorf("unknown binary operator for tests %s", ts.BinOp)
	case and, "":
		result = true
		for i := range res {
			result = result && res[i].testResult
		}
		// Generate an AND expected result
		finalOutput.ExpectedResult = strings.Join(expectedResultArr, " AND ")

	case or:
		result = false
		for i := range res {
			result = result || res[i].testResult
		}
		// Generate an OR expected result
		finalOutput.ExpectedResult = strings.Join(expectedResultArr, " OR ")
	}

	finalOutput.testResult = result
	finalOutput.actualResult = res[0].actualResult

	glog.V(3).Infof("Returning from execute on tests: finalOutput %#v", finalOutput)
	return finalOutput, nil
}

func runAudit(audit string) (output string, err error) {
	return runAuditWithTimeout(audit, 0)
}

func runAuditWithTimeout(audit string, timeout time.Duration) (output string, err error) {
	var out bytes.Buffer

	audit = strings.TrimSpace(audit)
	if len(audit) == 0 {
		return output, err
	}

	ctx := context.Background()
	cancel := func() {}
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()

	cmd := exec.CommandContext(ctx, "/bin/sh")
	cmd.Stdin = strings.NewReader(audit)
	cmd.Stdout = &out
	cmd.Stderr = &out
	configureCommandProcessGroup(cmd)
	if err = cmd.Start(); err != nil {
		return "", fmt.Errorf("failed to run: %q, error: %s", audit, err)
	}
	wait := make(chan error, 1)
	go func() {
		wait <- cmd.Wait()
	}()
	select {
	case err = <-wait:
	case <-ctx.Done():
		killCommandProcessGroup(cmd)
		err = <-wait
	}
	output = out.String()

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return output, fmt.Errorf("%w: failed to run: %q, output: %q, timeout: %s", ErrAuditTimeout, audit, output, timeout)
	}

	if err != nil {
		err = fmt.Errorf("failed to run: %q, output: %q, error: %s", audit, output, err)
	} else {
		glog.V(3).Infof("Command: %q", audit)
		glog.V(3).Infof("Output:\n %q", output)
	}
	return output, err
}
