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
	"fmt"
	"regexp"
	"strings"
)

// maxEvidenceLength is the upper bound, in characters, for a single piece of
// retained evidence (command output). Anything longer is truncated and the
// truncation point is marked.
const maxEvidenceLength = 1024

// maxReasonOutputLength bounds how much command output is embedded in error
// reasons, so a runaway command cannot flood the report.
const maxReasonOutputLength = 200

const (
	redactedValue = "<redacted>"
	redactedPath  = "<internal-path>"
)

var (
	// secretPattern matches password/token style assignments such as
	// "token=abc", "password: foo", "Bearer xyz" or "--token abc".
	secretPattern = regexp.MustCompile(`(?i)\b(password|passwd|pwd|token|secret|api[-_]?key|authorization|credential|bearer)\b(\s*[=:]\s*|\s+)("[^"]*"|'[^']*'|\S+)`)
	// internalPathPattern matches machine-local paths that must not leak
	// into evidence.
	internalPathPattern = regexp.MustCompile(`/(?:home|root|Users)/[^\s"']+`)
)

// Evidence records how a check's conclusion was reached: what was executed,
// what output was observed, and why the conclusion follows. Contents are
// sanitized (no passwords, tokens or internal paths) and truncated to
// maxEvidenceLength.
type Evidence struct {
	Command   string `json:"command,omitempty"`
	Output    string `json:"output,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// sanitizeEvidence removes passwords, tokens and internal paths from s.
func sanitizeEvidence(s string) string {
	s = secretPattern.ReplaceAllString(s, "${1}${2}"+redactedValue)
	s = internalPathPattern.ReplaceAllString(s, redactedPath)
	return s
}

// truncateEvidence caps s at maxEvidenceLength characters. When truncation
// happens the cut point is marked and the second return value is true.
func truncateEvidence(s string) (string, bool) {
	runes := []rune(s)
	if len(runes) <= maxEvidenceLength {
		return s, false
	}
	marker := fmt.Sprintf("...[truncated: showing first %d of %d chars]", maxEvidenceLength, len(runes))
	return string(runes[:maxEvidenceLength]) + marker, true
}

// truncateReasonOutput caps command output embedded in error reasons.
func truncateReasonOutput(s string) string {
	runes := []rune(s)
	if len(runes) <= maxReasonOutputLength {
		return s
	}
	return string(runes[:maxReasonOutputLength]) + fmt.Sprintf("...[truncated: showing first %d of %d chars]", maxReasonOutputLength, len(runes))
}

// buildEvidence assembles the evidence trail for a concluded check from the
// commands it ran and the outputs they produced.
func (c *Check) buildEvidence() *Evidence {
	e := &Evidence{Reason: sanitizeEvidence(c.Reason)}

	var commands []string
	if c.Audit != "" {
		commands = append(commands, "audit: "+c.Audit)
	}
	if c.AuditConfig != "" {
		commands = append(commands, "audit_config: "+c.AuditConfig)
	}
	if c.AuditEnv != "" {
		commands = append(commands, "audit_env: "+c.AuditEnv)
	}
	e.Command = sanitizeEvidence(strings.Join(commands, "\n"))

	var outputs []string
	if c.AuditOutput != "" {
		outputs = append(outputs, "audit: "+c.AuditOutput)
	}
	if c.AuditConfigOutput != "" {
		outputs = append(outputs, "audit_config: "+c.AuditConfigOutput)
	}
	if c.AuditEnvOutput != "" {
		outputs = append(outputs, "audit_env: "+c.AuditEnvOutput)
	}
	e.Output, e.Truncated = truncateEvidence(sanitizeEvidence(strings.Join(outputs, "\n")))

	if e.Reason == "" {
		e.Reason = fmt.Sprintf("check evaluated as %s from audit command output", c.State)
	}
	return e
}
