package check

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

// AuditEvent records a check state transition together with the condition that
// caused it. Events can be retrieved by check ID from Controls.
type AuditEvent struct {
	At             time.Time `json:"time"`
	CheckID        string    `json:"check_id"`
	From           State     `json:"from,omitempty"`
	To             State     `json:"to"`
	Condition      string    `json:"condition,omitempty"`
	ReasonCategory string    `json:"reason_category,omitempty"`
	BlockedBy      []string  `json:"blocked_by,omitempty"`
}

// CheckDistribution describes the results for one check ID across all scanned
// nodes. It deliberately retains every outcome instead of collapsing them to a
// majority result.
type CheckDistribution struct {
	CheckID string                   `json:"check_id"`
	Total   int                      `json:"total"`
	States  map[State]int            `json:"states"`
	Nodes   map[string]map[State]int `json:"nodes,omitempty"`
}

// ComparisonReport compares two scans. Comparisons across different benchmark
// or check versions are rejected instead of producing a misleading summary.
type ComparisonReport struct {
	BeforeBaselineVersion string           `json:"before_baseline_version,omitempty"`
	AfterBaselineVersion  string           `json:"after_baseline_version,omitempty"`
	BeforeCheckVersion    string           `json:"before_check_version,omitempty"`
	AfterCheckVersion     string           `json:"after_check_version,omitempty"`
	Comparable            bool             `json:"comparable"`
	Status                string           `json:"status"`
	Message               string           `json:"message,omitempty"`
	Items                 []ComparisonItem `json:"items,omitempty"`
}

// ComparisonItem explains one changed check result.
type ComparisonItem struct {
	CheckID     string `json:"check_id"`
	Before      string `json:"before"`
	After       string `json:"after"`
	Explanation string `json:"explanation"`
}

// UnmarshalYAML accepts dependency declarations either as a scalar, a list of
// IDs, or a list of objects containing id/check_id. This keeps existing check
// definitions compatible while allowing concise dependency syntax.
func (c *Check) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var raw map[interface{}]interface{}
	if err := unmarshal(&raw); err != nil {
		return err
	}
	raw["depends_on"] = normalizeDependencyValue(raw["depends_on"])
	raw["requires"] = normalizeDependencyValue(raw["requires"])
	raw["dependencies"] = normalizeDependencyValue(raw["dependencies"])
	if dependencies, ok := raw["dependencies"].([]string); ok && len(dependencies) > 0 {
		existing, _ := raw["depends_on"].([]string)
		raw["depends_on"] = append(existing, dependencies...)
	}
	delete(raw, "dependencies")

	normalized, err := yaml.Marshal(raw)
	if err != nil {
		return err
	}
	type plainCheck Check
	return yaml.Unmarshal(normalized, (*plainCheck)(c))
}

func normalizeDependencyValue(value interface{}) []string {
	switch typed := value.(type) {
	case nil:
		return nil
	case string:
		if id := strings.TrimSpace(typed); id != "" {
			return []string{id}
		}
	case []interface{}:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			switch entry := item.(type) {
			case string:
				if id := strings.TrimSpace(entry); id != "" {
					result = append(result, id)
				}
			case map[interface{}]interface{}:
				if id := dependencyIDFromMap(entry); id != "" {
					result = append(result, id)
				}
			}
		}
		return result
	case map[interface{}]interface{}:
		if id := dependencyIDFromMap(typed); id != "" {
			return []string{id}
		}
	}
	return nil
}

func dependencyIDFromMap(entry map[interface{}]interface{}) string {
	for _, key := range []string{"id", "check_id", "check", "test_number"} {
		value, ok := entry[key]
		if !ok {
			continue
		}
		if id, ok := value.(string); ok {
			if id = strings.TrimSpace(id); id != "" {
				return id
			}
		}
	}
	return ""
}

// ValidateDependencies builds the configured dependency graph and rejects
// missing references and cycles before any check is executed.
func ValidateDependencies(groups []*Group) error {
	checks := make(map[string]*Check)
	var ordered []*Check

	for _, group := range groups {
		for _, check := range group.Checks {
			id := strings.TrimSpace(check.ID)
			if id == "" {
				continue
			}
			if _, exists := checks[id]; !exists {
				checks[id] = check
				ordered = append(ordered, check)
			}
		}
	}

	for _, check := range ordered {
		for _, dependency := range check.Dependencies() {
			if _, ok := checks[dependency]; !ok {
				return fmt.Errorf("check %q depends on missing check %q", check.ID, dependency)
			}
		}
	}

	const (
		unvisited = iota
		visiting
		visited
	)
	colors := make(map[string]int, len(checks))
	stack := make([]string, 0, len(checks))
	stackIndex := make(map[string]int, len(checks))

	var walk func(string) []string
	walk = func(id string) []string {
		colors[id] = visiting
		stackIndex[id] = len(stack)
		stack = append(stack, id)

		for _, dependency := range checks[id].Dependencies() {
			switch colors[dependency] {
			case unvisited:
				if cycle := walk(dependency); cycle != nil {
					return cycle
				}
			case visiting:
				start := stackIndex[dependency]
				cycle := append([]string{}, stack[start:]...)
				cycle = append(cycle, dependency)
				return cycle
			}
		}

		stack = stack[:len(stack)-1]
		delete(stackIndex, id)
		colors[id] = visited
		return nil
	}

	for _, check := range ordered {
		if colors[check.ID] != unvisited {
			continue
		}
		if cycle := walk(check.ID); cycle != nil {
			return fmt.Errorf("dependency cycle detected: %s", strings.Join(cycle, " -> "))
		}
	}

	return nil
}

// AuditByCheckID returns all recorded transitions for a check ID.
func (controls *Controls) AuditByCheckID(checkID string) []AuditEvent {
	events := make([]AuditEvent, 0)
	for _, event := range controls.AuditTrail {
		if event.CheckID == checkID {
			events = append(events, event)
		}
	}
	return events
}

func (controls *Controls) recordAudit(check *Check, from, to State, condition, reasonCategory string, blockedBy []string) {
	if from == to && !check.WasBlocked {
		return
	}
	event := AuditEvent{
		At:             time.Now().UTC(),
		CheckID:        check.ID,
		From:           from,
		To:             to,
		Condition:      condition,
		ReasonCategory: reasonCategory,
		BlockedBy:      append([]string{}, blockedBy...),
	}
	controls.AuditTrail = append(controls.AuditTrail, event)
	check.AuditTrail = append(check.AuditTrail, event)
}

// BuildDistributions returns non-uniform check results across controls. The
// caller can include these in reports without choosing a majority outcome.
func BuildDistributions(controlsCollection []*Controls) []CheckDistribution {
	type aggregate struct {
		total  int
		states map[State]int
		nodes  map[string]map[State]int
	}

	byID := make(map[string]*aggregate)
	var order []string

	for _, controls := range controlsCollection {
		node := controls.NodeName
		if node == "" {
			node = string(controls.Type)
		}
		for _, group := range controls.Groups {
			for _, check := range group.Checks {
				if check.ID == "" {
					continue
				}
				aggregated, exists := byID[check.ID]
				if !exists {
					aggregated = &aggregate{
						states: make(map[State]int),
						nodes:  make(map[string]map[State]int),
					}
					byID[check.ID] = aggregated
					order = append(order, check.ID)
				}
				aggregated.total++
				aggregated.states[check.State]++
				if aggregated.nodes[node] == nil {
					aggregated.nodes[node] = make(map[State]int)
				}
				aggregated.nodes[node][check.State]++
			}
		}
	}

	sort.Strings(order)
	distributions := make([]CheckDistribution, 0)
	for _, id := range order {
		aggregated := byID[id]
		if len(aggregated.states) < 2 {
			continue
		}
		distributions = append(distributions, CheckDistribution{
			CheckID: id,
			Total:   aggregated.total,
			States:  aggregated.states,
			Nodes:   aggregated.nodes,
		})
	}
	return distributions
}

// CompareScans compares two scans and explains every changed result. If the
// benchmark or check versions differ, the report is explicitly marked as not
// comparable.
func CompareScans(before, after []*Controls) ComparisonReport {
	report := ComparisonReport{
		BeforeBaselineVersion: scanBaselineVersion(before),
		AfterBaselineVersion:  scanBaselineVersion(after),
		BeforeCheckVersion:    scanCheckVersion(before),
		AfterCheckVersion:     scanCheckVersion(after),
		Status:                "COMPARABLE",
		Comparable:            true,
	}

	if report.BeforeBaselineVersion != report.AfterBaselineVersion ||
		report.BeforeCheckVersion != report.AfterCheckVersion ||
		scanVersionsMismatched(before) ||
		scanVersionsMismatched(after) {
		report.Comparable = false
		report.Status = "NOT_COMPARABLE"
		report.Message = fmt.Sprintf(
			"不可跨版本比对: before baseline=%s check=%s, after baseline=%s check=%s",
			report.BeforeBaselineVersion,
			report.BeforeCheckVersion,
			report.AfterBaselineVersion,
			report.AfterCheckVersion,
		)
		return report
	}

	beforeStates := scanStates(before)
	afterStates := scanStates(after)
	ids := make(map[string]bool)
	for id := range beforeStates {
		ids[id] = true
	}
	for id := range afterStates {
		ids[id] = true
	}

	ordered := make([]string, 0, len(ids))
	for id := range ids {
		ordered = append(ordered, id)
	}
	sort.Strings(ordered)

	for _, id := range ordered {
		beforeState := beforeStates[id]
		afterState := afterStates[id]
		if beforeState == afterState {
			continue
		}
		report.Items = append(report.Items, ComparisonItem{
			CheckID:     id,
			Before:      beforeState,
			After:       afterState,
			Explanation: explainDifference(before, after, id, beforeState, afterState),
		})
	}
	return report
}

func scanBaselineVersion(collection []*Controls) string {
	versions := make(map[string]bool)
	for _, controls := range collection {
		if controls.BaselineVersion != "" {
			versions[controls.BaselineVersion] = true
		}
		if controls.BaselineVersion == "" && controls.Version != "" {
			versions[controls.Version] = true
		}
	}
	return versionSetLabel(versions)
}

func scanCheckVersion(collection []*Controls) string {
	versions := make(map[string]bool)
	for _, controls := range collection {
		if controls.CheckVersion != "" {
			versions[controls.CheckVersion] = true
		}
		if controls.CheckVersion == "" && controls.Version != "" {
			versions[controls.Version] = true
		}
		for _, group := range controls.Groups {
			for _, check := range group.Checks {
				if check.Version != "" {
					versions[check.Version] = true
				}
			}
		}
	}
	return versionSetLabel(versions)
}

func scanVersionsMismatched(collection []*Controls) bool {
	baseline := scanBaselineVersion(collection)
	checkVersion := scanCheckVersion(collection)
	if strings.HasPrefix(baseline, "mixed:") || strings.HasPrefix(checkVersion, "mixed:") {
		return true
	}
	if baseline != "" || checkVersion != "" {
		if baseline != checkVersion {
			return true
		}
	}

	for _, controls := range collection {
		if controls.VersionMismatch {
			return true
		}
		expected := controls.BaselineVersion
		if expected == "" {
			expected = controls.Version
		}
		for _, group := range controls.Groups {
			for _, check := range group.Checks {
				if check.Version != "" && check.Version != expected {
					return true
				}
			}
		}
	}
	return false
}

func versionSetLabel(versions map[string]bool) string {
	if len(versions) == 0 {
		return ""
	}
	ordered := make([]string, 0, len(versions))
	for version := range versions {
		ordered = append(ordered, version)
	}
	sort.Strings(ordered)
	if len(ordered) == 1 {
		return ordered[0]
	}
	return "mixed:" + strings.Join(ordered, ",")
}

func scanStates(collection []*Controls) map[string]string {
	states := make(map[string]map[State]int)
	for _, controls := range collection {
		for _, group := range controls.Groups {
			for _, check := range group.Checks {
				if states[check.ID] == nil {
					states[check.ID] = make(map[State]int)
				}
				states[check.ID][check.State]++
			}
		}
	}

	result := make(map[string]string, len(states))
	for id, counts := range states {
		parts := make([]string, 0, len(counts))
		for state, count := range counts {
			parts = append(parts, fmt.Sprintf("%s:%d", state, count))
		}
		sort.Strings(parts)
		result[id] = strings.Join(parts, ",")
	}
	return result
}

func explainDifference(before, after []*Controls, checkID, beforeState, afterState string) string {
	for _, controls := range after {
		for _, group := range controls.Groups {
			for _, check := range group.Checks {
				if check.ID != checkID {
					continue
				}
				if check.ReasonCategory != "" {
					return fmt.Sprintf("%s: %s", check.ReasonCategory, check.Reason)
				}
			}
		}
	}

	if strings.Contains(afterState, string(NOT_EXECUTED)) {
		return "dependency prerequisites were not satisfied"
	}
	if strings.Contains(beforeState, string(NOT_EXECUTED)) && strings.Contains(afterState, string(PASS)) {
		return "dependencies were satisfied on the later run"
	}
	return "check result changed"
}
