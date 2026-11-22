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
	"fmt"
	"os/exec"
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
	// UNKNOWN the check could not be evaluated: the audit command could not
	// be executed, produced no usable output, or its output could not be
	// parsed. UNKNOWN is not a pass and not a fail; it is excluded from
	// compliance-rate numerator and denominator but always reported.
	UNKNOWN State = "UNKNOWN"

	// SKIP for when a check should be skipped.
	SKIP = "skip"

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

// Check contains information about a recommendation in the
// CIS Kubernetes document.
type Check struct {
	ID             string   `yaml:"id" json:"test_number"`
	Text           string   `json:"test_desc"`
	Audit          string   `json:"audit"`
	AuditEnv       string   `yaml:"audit_env"`
	AuditConfig    string   `yaml:"audit_config"`
	Type           string   `json:"type"`
	Tests          *tests   `json:"-"`
	Set            bool     `json:"-"`
	Remediation    string   `json:"remediation"`
	TestInfo       []string `json:"test_info"`
	State          `json:"status"`
	ActualValue    string `json:"actual_value"`
	Scored         bool   `json:"scored"`
	IsMultiple     bool   `yaml:"use_multiple_values"`
	ExpectedResult string `json:"expected_result"`
	Reason         string `json:"reason,omitempty"`
	// Evidence links the conclusion back to what was executed and observed.
	Evidence *Evidence `json:"evidence,omitempty"`
	// PreviousState/PreviousReason record the conclusion this check
	// replaced, when a re-run or a manual review changed the outcome.
	PreviousState     State  `json:"previous_state,omitempty"`
	PreviousReason    string `json:"previous_reason,omitempty"`
	AuditOutput       string `json:"-"`
	AuditEnvOutput    string `json:"-"`
	AuditConfigOutput string `json:"-"`
	DisableEnvTesting bool   `json:"-"`
}

// Override records a manual review decision, preserving the original
// conclusion and its reason so the change stays auditable.
func (c *Check) Override(state State, reason string) {
	if c.State != "" && c.State != state {
		c.PreviousState = c.State
		c.PreviousReason = c.Reason
	}
	c.State = state
	c.Reason = reason
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

	// If this check already carried a conclusion (re-run), keep the last
	// conclusion and note the previous one.
	prevState, prevReason := c.State, c.Reason
	ranAudit := false
	defer func() {
		if ranAudit {
			c.Evidence = c.buildEvidence()
		} else {
			// No audit command was executed on this path (manual, skip,
			// missing tests): the reason alone is the evidence.
			c.Evidence = &Evidence{Reason: sanitizeEvidence(c.Reason)}
		}
		if prevState != "" && prevState != c.State {
			c.PreviousState = prevState
			c.PreviousReason = prevReason
		}
	}()

	// Since this is an Scored check
	// without tests return a 'WARN' to alert
	// the user that this check needs attention
	if c.Scored && strings.TrimSpace(c.Type) == "" && c.Tests == nil {
		c.Reason = "There are no tests"
		c.State = WARN
		glog.V(3).Info(c.Reason)
		return c.State
	}

	// If check type is skip, force result to INFO
	if c.Type == SKIP {
		c.Reason = "Test marked as skip"
		c.State = INFO
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

	ranAudit = true
	lastCommand, err := c.runAuditCommands()
	if err == nil && c.noUsableEvidence() {
		// The commands ran but produced nothing to evaluate, and no test
		// item treats absence itself as the signal: this is "not evaluated",
		// neither a pass nor a fail.
		err = fmt.Errorf("audit commands produced no output to evaluate")
	}
	if err == nil {
		finalOutput, err = c.execute()
	}

	switch {
	case err != nil:
		// The audit command could not be executed (permission denied, path
		// missing, timeout, ...) or the tests could not be evaluated.
		c.Reason = sanitizeEvidence(err.Error())
		c.State = UNKNOWN
		glog.V(3).Info(c.Reason)
	case finalOutput != nil && finalOutput.unknown:
		// At least one sub-check could not be evaluated, so the check as a
		// whole cannot be called a pass.
		c.Reason = sanitizeEvidence(finalOutput.unknownReason)
		c.State = UNKNOWN
		glog.V(3).Info(c.Reason)
	case finalOutput != nil:
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

// noUsableEvidence reports whether every configured audit command produced
// no output at all while no test item treats "flag absent" as a meaningful
// signal (set: false). In that situation there is no evidence to judge the
// check by, so it cannot be called a pass or a fail.
func (c *Check) noUsableEvidence() bool {
	if c.Tests == nil {
		return false
	}
	for _, ti := range c.Tests.TestItems {
		if !ti.Set {
			return false
		}
	}
	return isBlank(c.AuditOutput) && isBlank(c.AuditConfigOutput) && isBlank(c.AuditEnvOutput)
}

func isBlank(s string) bool {
	return strings.TrimSpace(s) == ""
}

func (c *Check) runAuditCommands() (lastCommand string, err error) {
	// Always run auditEnvOutput if needed
	if c.AuditEnv != "" {
		c.AuditEnvOutput, err = runAudit(c.AuditEnv)
		if err != nil {
			return c.AuditEnv, err
		}
	}

	// Run the audit command and auditConfig commands, if present
	c.AuditOutput, err = runAudit(c.Audit)
	if err != nil {
		return c.Audit, err
	}

	c.AuditConfigOutput, err = runAudit(c.AuditConfig)
	// when file not found then error comes as exit status 127
	// in some env same error comes as exit status 1
	if err != nil && (strings.Contains(err.Error(), "exit status 127") ||
		strings.Contains(err.Error(), "No such file or directory")) &&
		(c.AuditEnvOutput != "" || c.AuditOutput != "") {
		// suppress file not found error when there is Audit OR auditEnv output present
		glog.V(3).Info(err)
		err = nil
		c.AuditConfigOutput = ""
	}
	return c.AuditConfig, err
}

func (c *Check) execute() (finalOutput *testOutput, err error) {
	finalOutput = &testOutput{}

	ts := c.Tests
	res := make([]testOutput, len(ts.TestItems))
	expectedResultArr := make([]string, len(res))

	glog.V(3).Infof("Running %d test_items", len(ts.TestItems))
	var unknownReasons []string
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
		if result.unknown {
			unknownReasons = append(unknownReasons, fmt.Sprintf("test_item %d (%s): %s", i, t.value(), result.unknownReason))
		}
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
	if len(unknownReasons) > 0 {
		finalOutput.unknown = true
		finalOutput.unknownReason = strings.Join(unknownReasons, "; ")
	}

	glog.V(3).Infof("Returning from execute on tests: finalOutput %#v", finalOutput)
	return finalOutput, nil
}

// auditTimeout bounds how long a single audit command may run before it is
// treated as unable to execute. It is a variable so tests can shorten it.
var auditTimeout = 30 * time.Second

func runAudit(audit string) (output string, err error) {
	var out bytes.Buffer

	audit = strings.TrimSpace(audit)
	if len(audit) == 0 {
		return output, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), auditTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "/bin/sh")
	// Bound how long Wait blocks after a timeout kill, in case the audit
	// spawned children that inherited the output pipes.
	cmd.WaitDelay = time.Second
	cmd.Stdin = strings.NewReader(audit)
	cmd.Stdout = &out
	cmd.Stderr = &out
	err = cmd.Run()
	output = out.String()

	if ctx.Err() == context.DeadlineExceeded {
		return output, fmt.Errorf("audit command timed out after %s: %q, output: %q", auditTimeout, audit, truncateReasonOutput(output))
	}
	if err != nil {
		err = fmt.Errorf("failed to run: %q, output: %q, error: %s", audit, truncateReasonOutput(output), err)
	} else {
		glog.V(3).Infof("Command: %q", audit)
		glog.V(3).Infof("Output:\n %q", output)
	}
	return output, err
}
