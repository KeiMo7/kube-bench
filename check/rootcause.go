// Copyright © 2024 Aqua Security Software Ltd. <info@aquasec.com>
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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v2"
)

// RootCauseClass is the single, unique root cause attribution of a check that
// did not pass. Exactly one class is assigned per check.
type RootCauseClass string

const (
	// RootCauseFileUnreadable means the audit target (a config file, manifest
	// or other host file) could not be read from inside the environment.
	RootCauseFileUnreadable RootCauseClass = "file_unreadable"
	// RootCauseCommandMissing means a command the audit depends on does not
	// exist in the environment.
	RootCauseCommandMissing RootCauseClass = "command_missing"
	// RootCausePermissionDenied means the audit ran but lacked privileges.
	RootCausePermissionDenied RootCauseClass = "permission_denied"
	// RootCauseUpstreamBlocked means a check this one depends on did not pass,
	// so this check's result cannot be determined.
	RootCauseUpstreamBlocked RootCauseClass = "upstream_blocked"
	// RootCauseNotApplicable means the check does not apply to this
	// environment (for example, an explicitly skipped check).
	RootCauseNotApplicable RootCauseClass = "not_applicable"
	// RootCauseUnclassified is the fallback. The raw observed symptom is kept
	// alongside it; a class is never guessed.
	RootCauseUnclassified RootCauseClass = "unclassified"
)

// RootCauseClasses lists every class in report order. The order is fixed so
// that output is byte-for-byte reproducible across runs.
var RootCauseClasses = []RootCauseClass{
	RootCauseFileUnreadable,
	RootCauseCommandMissing,
	RootCausePermissionDenied,
	RootCauseUpstreamBlocked,
	RootCauseNotApplicable,
	RootCauseUnclassified,
}

// ClassRemediations holds the single remediation for each root cause class.
// It is emitted once per class in the grouped report, never once per check.
var ClassRemediations = map[RootCauseClass]string{
	RootCauseFileUnreadable: "Expose the unreachable host file(s) to the container (for example with a hostPath volume) " +
		"or run kube-bench directly on the host. Every check in this group reads from the same kind of source.",
	RootCauseCommandMissing: "Install the missing command or expose the host binary inside the container " +
		"(for example via the /usr/local/mount-from-host/bin mount). Every check in this group depends on it.",
	RootCausePermissionDenied: "Run kube-bench with sufficient privileges (privileged container or root) so the " +
		"audit command can access the protected path. Every check in this group hits the same permission boundary.",
	RootCauseUpstreamBlocked: "Resolve the upstream non-passing check(s) first; these checks can only be judged " +
		"once their dependency passes.",
	RootCauseNotApplicable: "No action needed: this check does not apply to the current environment.",
	RootCauseUnclassified:  "Review the reported symptom individually; the cause could not be determined automatically.",
}

// CheckRootCause is the additive per-check annotation. It deliberately carries
// no remediation: a fix is stated once per root cause, not per check.
type CheckRootCause struct {
	Class RootCauseClass `json:"class"`
	// Detail is the concrete point behind the attribution: the unreachable
	// path, the missing command, or the raw observed symptom for an
	// unclassified check. Checks sharing a Detail share one point of action.
	Detail string `json:"detail,omitempty"`
	// BlockedBy lists the upstream checks that must pass before this one can
	// be judged. It is only set for RootCauseUpstreamBlocked.
	BlockedBy []string `json:"blocked_by,omitempty"`
}

// RootCauseAction is one concrete point to act on within a shared root cause.
type RootCauseAction struct {
	Detail string   `json:"detail"`
	Checks []string `json:"checks"`
}

// RootCauseGroup aggregates every non-passing check that shares a class.
type RootCauseGroup struct {
	Class     RootCauseClass `json:"class"`
	Signature string         `json:"signature"`
	Count     int            `json:"count"`
	Checks    []string       `json:"checks"`
	// Sources lists the distinct points of action, sorted.
	Sources []string `json:"sources,omitempty"`
	// Actions groups the affected checks by the point they share.
	Actions []RootCauseAction `json:"actions,omitempty"`
	// BlockedBy lists the union of upstream checks for a blocked group.
	BlockedBy []string `json:"blocked_by,omitempty"`
	// Remediation is stated once for the whole class.
	Remediation string `json:"remediation"`
}

// RootCauseReport is the aggregation result attached when root cause analysis
// is enabled.
type RootCauseReport struct {
	Enabled bool `json:"enabled"`
	// Degraded is set when aggregation itself failed. Only the per-check raw
	// results are trustworthy in that case and no statistics are emitted.
	Degraded bool `json:"degraded,omitempty"`
	// Note explains a degraded report.
	Note string `json:"note,omitempty"`
	// Counts is the number of checks per class. It is omitted when degraded.
	Counts map[RootCauseClass]int `json:"counts,omitempty"`
	// TotalNonPassing is the number of checks that did not report PASS. The
	// counts always sum to this value, because each check gets exactly one
	// class.
	TotalNonPassing int `json:"total_non_passing,omitempty"`
	// Groups is ordered by the fixed RootCauseClasses order.
	Groups []RootCauseGroup `json:"groups,omitempty"`
	// Delta compares Counts with a previous run when a baseline was supplied.
	// A negative value means fewer checks were affected in this run.
	Delta map[RootCauseClass]int `json:"delta,omitempty"`
}

// RootCauseConfig holds the out-of-band dependency graph. It lives in its own
// file; the benchmark definitions are untouched.
type RootCauseConfig struct {
	// Dependencies maps a check ID to the check IDs that must pass first.
	Dependencies map[string][]string `yaml:"dependencies"`
}

// Normalize fills in nil maps and canonicalises dependency entries.
func (c *RootCauseConfig) Normalize() {
	if c == nil {
		return
	}
	if c.Dependencies == nil {
		c.Dependencies = map[string][]string{}
	}
	for from, to := range c.Dependencies {
		cleaned := make([]string, 0, len(to))
		for _, dep := range to {
			dep = strings.TrimSpace(dep)
			if dep != "" && dep != from {
				cleaned = append(cleaned, dep)
			}
		}
		sort.Strings(cleaned)
		c.Dependencies[from] = cleaned
	}
}

// ValidateDependencies checks the declared graph for cycles. It reports the
// check IDs on the cycle rather than silently ignoring it. Traversal is
// deterministic (sorted roots and edges), so the reported cycle is stable.
func ValidateDependencies(deps map[string][]string) error {
	nodes := map[string]bool{}
	for from, to := range deps {
		nodes[from] = true
		for _, d := range to {
			nodes[d] = true
		}
	}
	roots := sortedKeys(nodes)

	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := map[string]int{}
	var stack []string

	var visit func(string) []string
	visit = func(n string) []string {
		color[n] = gray
		stack = append(stack, n)
		edges := append([]string(nil), deps[n]...)
		sort.Strings(edges)
		for _, next := range edges {
			switch color[next] {
			case gray:
				for i, s := range stack {
					if s == next {
						cycle := append([]string(nil), stack[i:]...)
						return append(cycle, next)
					}
				}
				return []string{next, next}
			case white:
				if c := visit(next); c != nil {
					return c
				}
			}
		}
		stack = stack[:len(stack)-1]
		color[n] = black
		return nil
	}

	for _, n := range roots {
		if color[n] == white {
			if cycle := visit(n); cycle != nil {
				return fmt.Errorf("root cause dependency cycle detected: %s", strings.Join(cycle, " -> "))
			}
		}
	}
	return nil
}

// AnalyzeRootCauses classifies every non-PASS check, stores the annotation on
// the check itself, and returns the grouped report. It returns an error naming
// the checks on a dependency cycle and produces no statistics in that case.
func AnalyzeRootCauses(checks []*Check, cfg *RootCauseConfig, baseline map[RootCauseClass]int) (*RootCauseReport, error) {
	if cfg == nil {
		cfg = &RootCauseConfig{}
	}
	cfg.Normalize()
	if err := ValidateDependencies(cfg.Dependencies); err != nil {
		return nil, err
	}
	// A dependency that names an ambiguous check ID cannot be resolved to one
	// upstream. Some legacy benchmarks repeat IDs; refuse rather than pick one.
	if err := validateUniqueReferences(checks, cfg.Dependencies); err != nil {
		return nil, err
	}

	blocked := resolveBlocked(checks, cfg.Dependencies)
	for _, c := range checks {
		if c.State == PASS {
			c.RootCause = nil
			continue
		}
		rc := classifyCheck(c, blocked[c.ID])
		c.RootCause = &rc
	}

	return buildReport(checks, baseline)
}

// validateUniqueReferences rejects a dependency graph that points at a check ID
// which occurs more than once, because the upstream state would be ambiguous.
func validateUniqueReferences(checks []*Check, deps map[string][]string) error {
	counts := map[string]int{}
	for _, c := range checks {
		counts[c.ID]++
	}
	referenced := map[string]bool{}
	for from := range deps {
		referenced[from] = true
	}
	for _, to := range deps {
		for _, dep := range to {
			referenced[dep] = true
		}
	}
	var ambiguous []string
	for id := range referenced {
		if counts[id] > 1 {
			ambiguous = append(ambiguous, id)
		}
	}
	if len(ambiguous) > 0 {
		sort.Strings(ambiguous)
		return fmt.Errorf("root cause dependency references ambiguous check ID(s) that occur more than once: %s", strings.Join(ambiguous, ", "))
	}
	return nil
}

// SectionReport builds a report from checks that have already been annotated
// by AnalyzeRootCauses. It performs no classification, so a section report is
// consistent with the global one even when dependencies cross sections.
func SectionReport(checks []*Check) *RootCauseReport {
	report, err := buildReport(checks, nil)
	if err != nil {
		return &RootCauseReport{
			Enabled:  true,
			Degraded: true,
			Note:     fmt.Sprintf("root cause aggregation failed and was not applied: %v", err),
		}
	}
	return report
}

// buildReport groups already-classified checks. It never classifies, so the
// sum of counts always equals the number of non-PASS checks passed in.
func buildReport(checks []*Check, baseline map[RootCauseClass]int) (report *RootCauseReport, err error) {
	report = &RootCauseReport{Enabled: true, Counts: map[RootCauseClass]int{}}
	// Aggregation is best-effort: a bug here must not emit half a statistic.
	defer func() {
		if r := recover(); r != nil {
			report = &RootCauseReport{
				Enabled:  true,
				Degraded: true,
				Note:     fmt.Sprintf("root cause aggregation failed and was not applied: %v", r),
			}
			err = nil
		}
	}()

	sources := map[RootCauseClass]map[string][]string{}
	blockedUnion := map[RootCauseClass][]string{}

	for _, c := range checks {
		if c.State == PASS || c.RootCause == nil {
			continue
		}
		class := c.RootCause.Class
		report.Counts[class]++
		report.TotalNonPassing++
		if sources[class] == nil {
			sources[class] = map[string][]string{}
		}
		sources[class][c.RootCause.Detail] = append(sources[class][c.RootCause.Detail], c.ID)
		for _, b := range c.RootCause.BlockedBy {
			blockedUnion[class] = appendUnique(blockedUnion[class], b)
		}
	}

	for _, class := range RootCauseClasses {
		if report.Counts[class] == 0 {
			continue
		}
		g := RootCauseGroup{
			Class:       class,
			Signature:   signature(class),
			Count:       report.Counts[class],
			Remediation: ClassRemediations[class],
		}
		for detail, ids := range sources[class] {
			sortedIDs := append([]string(nil), ids...)
			sort.Strings(sortedIDs)
			g.Checks = append(g.Checks, sortedIDs...)
			g.Sources = append(g.Sources, detail)
			g.Actions = append(g.Actions, RootCauseAction{Detail: detail, Checks: sortedIDs})
		}
		sort.Strings(g.Checks)
		sort.Strings(g.Sources)
		sort.Slice(g.Actions, func(i, j int) bool { return g.Actions[i].Detail < g.Actions[j].Detail })
		if len(blockedUnion[class]) > 0 {
			g.BlockedBy = append([]string(nil), blockedUnion[class]...)
			sort.Strings(g.BlockedBy)
		}
		report.Groups = append(report.Groups, g)
	}

	// Self-check: grouping must account for every annotated non-passing check
	// exactly once. If not, refuse to publish a partial statistic.
	if err := verifyReport(checks, report); err != nil {
		return &RootCauseReport{
			Enabled:  true,
			Degraded: true,
			Note:     fmt.Sprintf("root cause aggregation failed and was not applied: %v", err),
		}, nil
	}

	if baseline != nil {
		delta := map[RootCauseClass]int{}
		for _, class := range RootCauseClasses {
			d := report.Counts[class] - baseline[class]
			if d != 0 || baseline[class] != 0 || report.Counts[class] != 0 {
				delta[class] = d
			}
		}
		report.Delta = delta
	}
	return report, nil
}

// verifyReport checks internal consistency: every annotated non-passing check
// appears in exactly one group, and the class counts sum to the total.
//
// Checks are counted by identity, not by ID: a few legacy benchmarks repeat
// check IDs, and that is not double counting.
func verifyReport(checks []*Check, report *RootCauseReport) error {
	expected := 0
	for _, c := range checks {
		// Every non-PASS check must be accounted for. An unannotated one would
		// be silently dropped, so it is a hard integrity failure.
		if c.State != PASS {
			expected++
		}
	}
	if report.TotalNonPassing != expected {
		return fmt.Errorf("total %d does not match %d non-passing checks", report.TotalNonPassing, expected)
	}

	sum := 0
	for _, n := range report.Counts {
		sum += n
	}
	if sum != report.TotalNonPassing {
		return fmt.Errorf("class counts sum to %d but total is %d", sum, report.TotalNonPassing)
	}

	groupTotal := 0
	for _, g := range report.Groups {
		if g.Count != len(g.Checks) {
			return fmt.Errorf("group %s count %d does not match %d listed checks", g.Class, g.Count, len(g.Checks))
		}
		groupTotal += g.Count
	}
	if groupTotal != report.TotalNonPassing {
		return fmt.Errorf("groups cover %d checks but total is %d", groupTotal, report.TotalNonPassing)
	}
	return nil
}

// classifyCheck decides the unique root cause of one check. The cascade is
// fixed, so a check can never be counted under more than one class.
func classifyCheck(c *Check, blockedBy []string) CheckRootCause {
	// 1. Explicitly out of scope for this environment: skipped, or manual
	// (which cannot be evaluated automatically).
	switch c.Type {
	case SKIP:
		return CheckRootCause{Class: RootCauseNotApplicable, Detail: "check marked as skip"}
	case MANUAL:
		return CheckRootCause{Class: RootCauseNotApplicable, Detail: "manual check"}
	}

	// 2. A failed prerequisite makes the check undeterminable. This takes
	// precedence so it is not mixed in with ordinary failures.
	if len(blockedBy) > 0 {
		sorted := append([]string(nil), blockedBy...)
		sort.Strings(sorted)
		return CheckRootCause{
			Class:     RootCauseUpstreamBlocked,
			Detail:    strings.Join(sorted, ", "),
			BlockedBy: sorted,
		}
	}

	// 3. A concrete environment symptom from the audit command.
	if class, detail := classifyEvidence(c); class != "" {
		return CheckRootCause{Class: class, Detail: detail}
	}

	// 4. Fallback: keep the raw symptom, never guess.
	return CheckRootCause{Class: RootCauseUnclassified, Detail: observedSymptom(c)}
}

// evidenceClassPatterns are ordered: command problems are checked before file
// problems so `sh: kubectl: not found` is not attributed to a missing file.
var evidenceClassPatterns = []struct {
	class    RootCauseClass
	patterns []*regexp.Regexp
}{
	{RootCauseCommandMissing, []*regexp.Regexp{
		regexp.MustCompile(`exit status 127`),
		regexp.MustCompile(`(?i)command not found`),
		regexp.MustCompile(`(?i)executable file not found`),
		// POSIX shell form: `sh: 1: kubectl: not found` or `sh: kubectl: not found`.
		// A single token is required so that deliberate benchmark strings such as
		// `File not found` are not mistaken for a missing command.
		regexp.MustCompile(`(?:^|:\s)([^\s:'"]+): not found`),
	}},
	{RootCausePermissionDenied, []*regexp.Regexp{
		regexp.MustCompile(`(?i)permission denied`),
		regexp.MustCompile(`(?i)operation not permitted`),
		regexp.MustCompile(`exit status 126`),
		regexp.MustCompile(`(?i)must be run as (root|superuser)`),
	}},
	{RootCauseFileUnreadable, []*regexp.Regexp{
		regexp.MustCompile(`(?i)no such file or directory`),
		regexp.MustCompile(`(?i)does not exist`),
	}},
}

func matchEvidenceClass(s string) RootCauseClass {
	for _, entry := range evidenceClassPatterns {
		for _, re := range entry.patterns {
			if re.MatchString(s) {
				return entry.class
			}
		}
	}
	return ""
}

// classifyEvidence returns the class and the concrete point behind it.
func classifyEvidence(c *Check) (RootCauseClass, string) {
	for _, e := range c.auditEvidence {
		if e.Err == "" || e.Suppressed {
			continue
		}
		blob := e.Err + "\n" + e.Output
		class := matchEvidenceClass(blob)
		if class == "" {
			continue
		}
		return class, pointOfAction(class, blob, e.Command)
	}
	if path := guardedPathMissing(c); path != "" {
		return RootCauseFileUnreadable, path
	}
	return "", ""
}

// pointOfAction extracts the concrete thing to fix: the unreachable path, the
// missing command name, or the failing line. Normalising here is what lets
// several checks share one action instead of repeating per check.
func pointOfAction(class RootCauseClass, blob, command string) string {
	switch class {
	case RootCauseFileUnreadable, RootCausePermissionDenied:
		for _, line := range strings.Split(blob, "\n") {
			if matchEvidenceClass(line) != class {
				continue
			}
			if p := pathToken(line); p != "" {
				return p
			}
		}
	case RootCauseCommandMissing:
		for _, line := range strings.Split(blob, "\n") {
			if matchEvidenceClass(line) != class {
				continue
			}
			if name := commandToken(line); name != "" {
				return name
			}
		}
	}
	// Fall back to the first recorded command, then to the raw symptom.
	if cmd := firstWord(command); cmd != "" {
		return cmd
	}
	return firstSymptomLine(blob)
}

var commandTokenRe = regexp.MustCompile(`([^\s:'"]+): (?:command )?not found`)
var execTokenRe = regexp.MustCompile(`"([^"]+)"`)

func pathToken(line string) string {
	// Prefer a quoted or bare absolute path; a stray slash inside an audit
	// command body (for example a sed expression) is not a file operand.
	if m := quotedPathRe.FindStringSubmatch(line); len(m) > 1 {
		return normalizePath(m[1])
	}
	if m := barePathRe.FindStringSubmatch(line); len(m) > 1 {
		return normalizePath(m[1])
	}
	return ""
}

var quotedPathRe = regexp.MustCompile(`(?:'|")(/[^'"]+)(?:'|")`)
var barePathRe = regexp.MustCompile(`(?:^|[\s:=])(/[^\s:'"]+)`)

// normalizePath strips the trailing separators and quotes that different
// tools add, so the same file always yields the same action point.
func normalizePath(p string) string {
	p = strings.TrimSpace(p)
	p = strings.Trim(p, `'"`)
	p = strings.TrimRight(p, "/")
	p = strings.Trim(p, `'"`)
	if p == "" {
		return "/"
	}
	return p
}

func commandToken(line string) string {
	if m := commandTokenRe.FindStringSubmatch(line); len(m) > 1 {
		return m[1]
	}
	if m := execTokenRe.FindStringSubmatch(line); len(m) > 1 {
		return m[1]
	}
	return ""
}

func firstWord(command string) string {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

// firstSymptomLine extracts the most relevant line of an audit failure.
func firstSymptomLine(blob string) string {
	for _, line := range strings.Split(blob, "\n") {
		if matchEvidenceClass(line) != "" {
			return strings.TrimSpace(line)
		}
	}
	return strings.TrimSpace(blob)
}

// oneLine collapses a multi-line symptom to a single deterministic line, used
// for the per-check detail so it stays readable and groups identically.
func oneLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			return line
		}
	}
	return ""
}

// guardedAuditRe matches audit commands that only run their payload when a
// target file exists, e.g. `if test -e FILE; then ...; fi`.
var guardedAuditRe = regexp.MustCompile(`test\s+-[ef]\s+("[^"]+"|'[^']+'|[^\s;]+)`)

// guardedPathMissing detects the "guard swallowed a missing file" case: the
// audit was guarded by `test -e`, produced no usable output, and the check did
// not pass. In that situation the file was not readable in this environment.
//
// This is the strongest deterministic signal available without inventing
// semantics: a guarded audit exits 0 either way, so the empty result is what
// distinguishes a missing file from a present file whose value failed.
func guardedPathMissing(c *Check) string {
	if c.State == PASS {
		return ""
	}
	if strings.TrimSpace(c.ActualValue) != "" {
		return ""
	}
	for _, e := range c.auditEvidence {
		if e.Suppressed || e.Err != "" || e.Command == "" {
			continue
		}
		if path := extractGuardedPath(e.Command); path != "" {
			return path
		}
	}
	return ""
}

func extractGuardedPath(command string) string {
	m := guardedAuditRe.FindStringSubmatch(command)
	if len(m) < 2 {
		return ""
	}
	return strings.Trim(strings.TrimSpace(m[1]), `"'`)
}

// observedSymptom renders the raw symptom for an unclassified check without
// guessing a cause. It is always one line so identical symptoms group together
// and the output stays readable.
func observedSymptom(c *Check) string {
	if c.Reason != "" {
		if line := oneLine(c.Reason); line != "" {
			return line
		}
	}
	if strings.TrimSpace(c.ActualValue) != "" {
		if line := oneLine(c.ActualValue); line != "" {
			return "actual value: " + line
		}
	}
	return "no audit evidence captured"
}

// signature is a stable identity for a class, used to compare the same root
// cause across runs.
func signature(class RootCauseClass) string {
	h := sha256.Sum256([]byte(class))
	return string(class) + ":" + hex.EncodeToString(h[:])[:12]
}

// resolveBlocked computes, for every check, the direct dependencies that did
// not pass. Because a blocked check is itself non-PASS, transitive blocking
// follows naturally from the original states.
func resolveBlocked(checks []*Check, deps map[string][]string) map[string][]string {
	stateByID := map[string]State{}
	for _, c := range checks {
		stateByID[c.ID] = c.State
	}

	blocked := map[string][]string{}
	for _, c := range checks {
		var by []string
		for _, dep := range deps[c.ID] {
			state, ok := stateByID[dep]
			if !ok {
				// The dependency is not part of this run; it cannot be judged.
				continue
			}
			if state != PASS {
				by = append(by, dep)
			}
		}
		if len(by) > 0 {
			sort.Strings(by)
			blocked[c.ID] = by
		}
	}
	return blocked
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

// sortedKeys returns map keys in a fixed, sorted order.
func sortedKeys[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ReadRootCauseConfig loads the optional out-of-band root cause config.
func ReadRootCauseConfig(path string) (*RootCauseConfig, error) {
	cfg := &RootCauseConfig{Dependencies: map[string][]string{}}
	if strings.TrimSpace(path) == "" {
		return cfg, nil
	}
	in, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read root cause config %s: %v", path, err)
	}
	if err := yaml.Unmarshal(in, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse root cause config %s: %v", path, err)
	}
	cfg.Normalize()
	return cfg, nil
}
