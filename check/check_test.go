// Copyright © 2017-2020 Aqua Security Software Ltd. <info@aquasec.com>
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
	"strings"
	"testing"
	"time"
)

func TestCheck_Run_Unknown(t *testing.T) {
	flagTest := func() *tests {
		return &tests{TestItems: []*testItem{{Flag: "hello", Set: true}}}
	}

	t.Run("audit command cannot be executed -> UNKNOWN", func(t *testing.T) {
		c := Check{Scored: true, Audit: "/nonexistent/audit-command --flag", Tests: flagTest()}
		if state := c.run(); state != UNKNOWN {
			t.Errorf("expected UNKNOWN, got %s", state)
		}
		if !strings.Contains(c.Reason, "failed to run") {
			t.Errorf("expected reason to mention the failure, got %q", c.Reason)
		}
		if c.Evidence == nil || !strings.Contains(c.Evidence.Command, "/nonexistent/audit-command") {
			t.Errorf("expected evidence to record the command, got %+v", c.Evidence)
		}
	})

	t.Run("audit command times out -> UNKNOWN", func(t *testing.T) {
		old := auditTimeout
		auditTimeout = 100 * time.Millisecond
		defer func() { auditTimeout = old }()

		c := Check{Scored: true, Audit: "sleep 5", Tests: flagTest()}
		if state := c.run(); state != UNKNOWN {
			t.Errorf("expected UNKNOWN, got %s", state)
		}
		if !strings.Contains(c.Reason, "timed out") {
			t.Errorf("expected reason to mention the timeout, got %q", c.Reason)
		}
	})

	t.Run("audit command runs but output is empty -> UNKNOWN", func(t *testing.T) {
		c := Check{Scored: true, Audit: "true", Tests: flagTest()}
		if state := c.run(); state != UNKNOWN {
			t.Errorf("expected UNKNOWN, got %s", state)
		}
		if !strings.Contains(c.Reason, "no output") {
			t.Errorf("expected reason to mention the empty output, got %q", c.Reason)
		}
	})

	t.Run("empty output with an absence test keeps existing semantics -> PASS", func(t *testing.T) {
		c := Check{
			Scored: true,
			Audit:  "true",
			Tests:  &tests{TestItems: []*testItem{{Flag: "hello", Set: false}}},
		}
		if state := c.run(); state != PASS {
			t.Errorf("expected PASS, got %s", state)
		}
	})

	t.Run("audit output cannot be parsed -> UNKNOWN", func(t *testing.T) {
		c := Check{
			Scored:      true,
			AuditConfig: "echo 'broken: [yaml'",
			Tests: &tests{TestItems: []*testItem{{
				Path:    "{.enabled}",
				Set:     true,
				Compare: compare{Op: "eq", Value: "false"},
			}}},
		}
		if state := c.run(); state != UNKNOWN {
			t.Errorf("expected UNKNOWN, got %s", state)
		}
		if !strings.Contains(c.Reason, "failed to load YAML or JSON") {
			t.Errorf("expected reason to mention the parse failure, got %q", c.Reason)
		}
	})

	t.Run("one unparseable sub-check makes the whole check UNKNOWN", func(t *testing.T) {
		c := Check{
			Scored:      true,
			Audit:       "echo hello",
			AuditConfig: "echo 'broken: [yaml'",
			Tests: &tests{
				BinOp: or,
				TestItems: []*testItem{
					{Flag: "hello", Set: true},
					{Path: "{.enabled}", Set: true, Compare: compare{Op: "eq", Value: "false"}},
				},
			},
		}
		if state := c.run(); state != UNKNOWN {
			t.Errorf("expected UNKNOWN, got %s", state)
		}
	})

	t.Run("normal check still evaluates -> PASS", func(t *testing.T) {
		c := Check{Scored: true, Audit: "echo hello", Tests: flagTest()}
		if state := c.run(); state != PASS {
			t.Errorf("expected PASS, got %s", state)
		}
		if c.Evidence == nil || c.Evidence.Command == "" || c.Evidence.Output == "" || c.Evidence.Reason == "" {
			t.Errorf("expected evidence linking command, output and reason, got %+v", c.Evidence)
		}
	})
}

func TestCheck_Run_Evidence(t *testing.T) {
	t.Run("long output is truncated and the truncation point marked", func(t *testing.T) {
		c := Check{
			Scored: true,
			Audit:  "head -c 3000 /dev/zero | tr '\\0' 'a'",
			Tests:  &tests{TestItems: []*testItem{{Flag: "aaa", Set: true}}},
		}
		if state := c.run(); state != PASS {
			t.Fatalf("expected PASS, got %s", state)
		}
		if c.Evidence == nil || !c.Evidence.Truncated {
			t.Fatalf("expected evidence to be marked truncated, got %+v", c.Evidence)
		}
		if !strings.Contains(c.Evidence.Output, "[truncated: showing first 1024 of") {
			t.Errorf("expected truncation marker in evidence output, got %q...", c.Evidence.Output[:80])
		}
		if len(c.Evidence.Output) > 1024+200 {
			t.Errorf("evidence output exceeds retention cap: %d chars", len(c.Evidence.Output))
		}
	})

	t.Run("secrets and internal paths are redacted from evidence", func(t *testing.T) {
		c := Check{
			Scored: true,
			Audit:  `echo "token=supersecret123"; echo "config at /home/someone/config.yaml"`,
			Tests:  &tests{TestItems: []*testItem{{Flag: "token", Set: true}}},
		}
		if state := c.run(); state != PASS {
			t.Fatalf("expected PASS, got %s", state)
		}
		if strings.Contains(c.Evidence.Output, "supersecret123") || strings.Contains(c.Evidence.Command, "supersecret123") {
			t.Errorf("secret leaked into evidence: %+v", c.Evidence)
		}
		if strings.Contains(c.Evidence.Output, "/home/someone") {
			t.Errorf("internal path leaked into evidence: %+v", c.Evidence)
		}
		if !strings.Contains(c.Evidence.Output, redactedValue) || !strings.Contains(c.Evidence.Output, redactedPath) {
			t.Errorf("expected redaction markers in evidence, got %q", c.Evidence.Output)
		}
	})

	t.Run("evidence collection failure still yields UNKNOWN, not FAIL", func(t *testing.T) {
		c := Check{Scored: true, Audit: "cat /definitely/not/here", Tests: &tests{TestItems: []*testItem{{Flag: "x", Set: true}}}}
		if state := c.run(); state != UNKNOWN {
			t.Errorf("expected UNKNOWN, got %s", state)
		}
		if c.Evidence == nil || c.Evidence.Reason == "" {
			t.Errorf("expected evidence explaining the failure, got %+v", c.Evidence)
		}
	})
}

func TestCheck_RerunKeepsPreviousConclusion(t *testing.T) {
	c := Check{
		Scored: true,
		Audit:  "echo hello",
		Tests:  &tests{TestItems: []*testItem{{Flag: "hello", Set: true}}},
	}
	if state := c.run(); state != PASS {
		t.Fatalf("expected PASS, got %s", state)
	}

	// Re-run with a command that now fails: the last conclusion wins and
	// the previous one is noted.
	c.Audit = "false"
	if state := c.run(); state != UNKNOWN {
		t.Fatalf("expected UNKNOWN, got %s", state)
	}
	if c.PreviousState != PASS {
		t.Errorf("expected previous state PASS to be noted, got %q", c.PreviousState)
	}
}

func TestCheck_Override(t *testing.T) {
	c := &Check{}
	c.State = UNKNOWN
	c.Reason = "audit command failed"

	c.Override(PASS, "manual review: accepted risk")
	if c.State != PASS {
		t.Errorf("expected overridden state PASS, got %s", c.State)
	}
	if c.PreviousState != UNKNOWN {
		t.Errorf("expected original conclusion UNKNOWN preserved, got %q", c.PreviousState)
	}
	if c.PreviousReason != "audit command failed" {
		t.Errorf("expected original reason preserved, got %q", c.PreviousReason)
	}
	if c.Reason != "manual review: accepted risk" {
		t.Errorf("expected override reason recorded, got %q", c.Reason)
	}
}

func TestCheck_Run(t *testing.T) {
	type TestCase struct {
		name     string
		check    Check
		Expected State
	}

	testCases := []TestCase{
		{name: "Manual check should WARN", check: Check{Type: MANUAL}, Expected: WARN},
		{name: "Skip check should INFO", check: Check{Type: "skip"}, Expected: INFO},
		{name: "Unscored check (with no type) should WARN on failure", check: Check{Scored: false}, Expected: WARN},
		{
			name: "Unscored check that pass should PASS",
			check: Check{
				Scored: false,
				Audit:  "echo hello",
				Tests: &tests{TestItems: []*testItem{{
					Flag: "hello",
					Set:  true,
				}}},
			},
			Expected: PASS,
		},

		{name: "Check with no tests should WARN", check: Check{Scored: true}, Expected: WARN},
		{name: "Scored check with empty tests should FAIL", check: Check{Scored: true, Tests: &tests{}}, Expected: FAIL},
		{
			name: "Scored check that doesn't pass should FAIL",
			check: Check{
				Scored: true,
				Audit:  "echo hello",
				Tests: &tests{TestItems: []*testItem{{
					Flag: "hello",
					Set:  false,
				}}},
			},
			Expected: FAIL,
		},
		{
			name: "Scored checks that pass should PASS",
			check: Check{
				Scored: true,
				Audit:  "echo hello",
				Tests: &tests{TestItems: []*testItem{{
					Flag: "hello",
					Set:  true,
				}}},
			},
			Expected: PASS,
		},
		{
			name: "Scored checks that pass should PASS when config file is not present",
			check: Check{
				Scored:      true,
				Audit:       "echo hello",
				AuditConfig: "/test/config.yaml",
				Tests: &tests{TestItems: []*testItem{{
					Flag: "hello",
					Set:  true,
				}}},
			},
			Expected: PASS,
		},
		{
			name: "Scored check whose audit command cannot run (config file not present) should be UNKNOWN",
			check: Check{
				Scored:      true,
				AuditConfig: "/test/config.yaml",
				Tests: &tests{TestItems: []*testItem{{
					Flag: "hello",
					Set:  true,
				}}},
			},
			Expected: UNKNOWN,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			testCase.check.run()
			if testCase.check.State != testCase.Expected {
				t.Errorf("expected %s, actual %s", testCase.Expected, testCase.check.State)
			}
		})
	}
}

func TestCheckAuditEnv(t *testing.T) {
	passingCases := []*Check{
		controls.Groups[2].Checks[0],
		controls.Groups[2].Checks[2],
		controls.Groups[2].Checks[3],
		controls.Groups[2].Checks[4],
	}

	failingCases := []*Check{
		controls.Groups[2].Checks[1],
		controls.Groups[2].Checks[5],
		controls.Groups[2].Checks[6],
	}

	for _, c := range passingCases {
		t.Run(c.Text, func(t *testing.T) {
			c.run()
			if c.State != "PASS" {
				t.Errorf("Should PASS, got: %v", c.State)
			}
		})
	}

	for _, c := range failingCases {
		t.Run(c.Text, func(t *testing.T) {
			c.run()
			if c.State != "FAIL" {
				t.Errorf("Should FAIL, got: %v", c.State)
			}
		})
	}
}

func TestCheckAuditConfig(t *testing.T) {
	passingCases := []*Check{
		controls.Groups[1].Checks[0],
		controls.Groups[1].Checks[3],
		controls.Groups[1].Checks[5],
		controls.Groups[1].Checks[7],
		controls.Groups[1].Checks[9],
		controls.Groups[1].Checks[15],
	}

	failingCases := []*Check{
		controls.Groups[1].Checks[1],
		controls.Groups[1].Checks[2],
		controls.Groups[1].Checks[4],
		controls.Groups[1].Checks[6],
		controls.Groups[1].Checks[8],
		controls.Groups[1].Checks[10],
		controls.Groups[1].Checks[11],
		controls.Groups[1].Checks[12],
		controls.Groups[1].Checks[13],
		controls.Groups[1].Checks[14],
		controls.Groups[1].Checks[16],
	}

	for _, c := range passingCases {
		t.Run(c.Text, func(t *testing.T) {
			c.run()
			if c.State != "PASS" {
				t.Errorf("Should PASS, got: %v", c.State)
			}
		})
	}

	for _, c := range failingCases {
		t.Run(c.Text, func(t *testing.T) {
			c.run()
			if c.State != "FAIL" {
				t.Errorf("Should FAIL, got: %v", c.State)
			}
		})
	}
}

func Test_runAudit(t *testing.T) {
	type args struct {
		audit  string
		output string
	}
	tests := []struct {
		name   string
		args   args
		errMsg string
		output string
	}{
		{
			name: "run success",
			args: args{
				audit: "echo 'hello world'",
			},
			errMsg: "",
			output: "hello world\n",
		},
		{
			name: "run multiple lines script",
			args: args{
				audit: `
hello() {
  echo "hello world"
}

hello
`,
			},
			errMsg: "",
			output: "hello world\n",
		},
		{
			name: "run failed",
			args: args{
				audit: "unknown_command",
			},
			errMsg: "failed to run: \"unknown_command\", output: \"/bin/sh: ",
			output: "not found\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var errMsg string
			output, err := runAudit(tt.args.audit)
			if err != nil {
				errMsg = err.Error()
			}
			if errMsg != "" && !strings.Contains(errMsg, tt.errMsg) {
				t.Errorf("name %s errMsg = %q, want %q", tt.name, errMsg, tt.errMsg)
			}
			if errMsg == "" && output != tt.output {
				t.Errorf("name %s output = %q, want %q", tt.name, output, tt.output)
			}
			if errMsg != "" && !strings.Contains(output, tt.output) {
				t.Errorf("name %s output = %q, want %q", tt.name, output, tt.output)
			}
		})
	}
}
