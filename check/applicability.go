package check

import (
	"fmt"
	"sort"
	"strings"
)

// State values added for role-aware coverage. They are deliberately
// self-describing strings so that downstream consumers can recognize them
// instead of treating them as an opaque/unknown enum value. Consumers that
// only know PASS/FAIL/WARN/INFO will still see that they are not FAIL.
const (
	// NOT_APPLICABLE is used when a check belongs to a role that is not
	// present on the scanned machine. It is counted separately and never
	// contributes to the FAIL total or to the exit code.
	NOT_APPLICABLE State = "NOT_APPLICABLE"
)

// ApplicabilityState describes the conclusion for a whole target (controls
// file) after role-based trimming.
type ApplicabilityState string

const (
	// ApplicabilityCovered means the target's checks were in scope and were
	// executed (or would have been, under the active filters).
	ApplicabilityCovered ApplicabilityState = "covered"
	// ApplicabilityNotApplicable means every in-scope check of the target was
	// trimmed because the target's role is not running on this machine.
	ApplicabilityNotApplicable ApplicabilityState = "not_applicable"
	// ApplicabilityUncovered means applicability could not be established
	// (for example the role detection command is unavailable). The checks are
	// still executed so that their real results are preserved, but the report
	// states explicitly that coverage is not established and why.
	ApplicabilityUncovered ApplicabilityState = "uncovered"
	// ApplicabilityUndetermined is an alias for ApplicabilityUncovered.
	ApplicabilityUndetermined = ApplicabilityUncovered
)

// Reason codes explaining why a target or check was trimmed or left
// uncovered. They are stable machine-readable values.
const (
	ReasonRoleNotObserved          = "role_not_observed"
	ReasonRoleDetectionUnavailable = "role_detection_unavailable"
	ReasonNoComponentsObserved     = "no_components_observed"
)

// RoleReport records the machine-level role determination together with the
// observable evidence it was based on. It never uses hostnames, environment
// variables or directory conventions.
type RoleReport struct {
	// Roles is the set of roles observed on the machine. Possible values are
	// "controlplane", "worker" and "etcd". It is sorted deterministically.
	Roles []string `json:"roles"`
	// Determined is true when role detection produced a definitive answer.
	Determined bool `json:"determined"`
	// Source is "observed" when the answer comes from running processes and
	// "unavailable" when the detection command could not be used.
	Source string `json:"source"`
	// Fallback is true when the machine-level result could not be used to
	// trim targets (no components observed, or detection unavailable). In
	// that case the explicit default is to cover every candidate target.
	Fallback bool `json:"fallback,omitempty"`
	// ReasonCode is a stable code for a fallback or a failed determination.
	ReasonCode string `json:"reason_code,omitempty"`
	// Reason is the human-readable explanation of the determination.
	Reason string `json:"reason,omitempty"`
	// Unresolved lists roles whose components could not be probed at all, so
	// their absence cannot be asserted. Targets for these roles are executed
	// but reported as uncovered rather than silently marked not applicable.
	Unresolved []string `json:"unresolved,omitempty"`
	// Evidence lists the observed facts the decision was based on.
	Evidence []string `json:"evidence,omitempty"`
}

// Applicability is attached to a Controls object and explains, for one
// target, how many checks were covered, trimmed and deduplicated, and why.
type Applicability struct {
	State ApplicabilityState `json:"state"`
	// ReasonCode is one of the Reason* constants.
	ReasonCode string `json:"reason_code,omitempty"`
	// Reason is the human-readable explanation.
	Reason string `json:"reason,omitempty"`
	// Source is "observed", "manual", "default" or "cluster-scoped".
	Source string `json:"source,omitempty"`
	// Evidence records the observable facts for this decision.
	Evidence []string `json:"evidence,omitempty"`
	// Covered is the number of checks that were executed.
	Covered int `json:"covered"`
	// NotApplicable is the number of checks trimmed because of the role.
	NotApplicable int `json:"not_applicable"`
	// Deduplicated is the number of checks folded into another target because
	// the same check identifier was produced by another role's controls.
	Deduplicated int `json:"deduplicated,omitempty"`
}

// MarkNotApplicable sets a check to the not-applicable state without running
// its audit command. It never changes the check's own audit logic or
// thresholds; it only decides that the check is out of scope for this machine.
func (c *Check) MarkNotApplicable(reasonCode, reason string) {
	c.State = NOT_APPLICABLE
	c.ReasonCode = reasonCode
	c.Reason = reason
	c.ActualValue = ""
	c.ExpectedResult = ""
	c.TestInfo = append(c.TestInfo, c.Remediation)
}

// MarkNotApplicable marks every check accepted by filter as NOT_APPLICABLE and
// rebuilds the group/summary accounting. Checks are still listed in the report
// so that "not applicable" is visible instead of the section silently
// disappearing.
func (controls *Controls) MarkNotApplicable(filter Predicate, reasonCode, reason string) Summary {
	var g []*Group
	m := make(map[string]*Group)
	controls.Summary = Summary{}

	for _, group := range controls.Groups {
		for _, check := range group.Checks {
			if !filter(group, check) {
				continue
			}

			check.MarkNotApplicable(reasonCode, reason)

			v, ok := m[group.ID]
			if !ok {
				v = &Group{ID: group.ID, Text: group.Text, Checks: []*Check{}}
				m[v.ID] = v
				g = append(g, v)
			}
			v.Checks = append(v.Checks, check)
			summarizeGroup(v, check.State)
			summarize(controls, check.State)
		}
	}

	controls.Groups = g
	return controls.Summary
}

// RecalculateSummary rebuilds group and control summaries from the current
// check states. It is used after de-duplication removes checks.
func (controls *Controls) RecalculateSummary() Summary {
	return controls.recalculate()
}

// recalculate derives group counts and the control summary from the checks.
func (controls *Controls) recalculate() Summary {
	var total Summary
	for _, group := range controls.Groups {
		group.Pass, group.Fail, group.Warn, group.Info, group.NotApplicable = 0, 0, 0, 0, 0
		for _, check := range group.Checks {
			summarizeGroup(group, check.State)
		}
		total.Pass += group.Pass
		total.Fail += group.Fail
		total.Warn += group.Warn
		total.Info += group.Info
		total.NotApplicable += group.NotApplicable
	}
	controls.Summary = total
	return total
}

// severityRank orders states for de-duplication. A real result always wins
// over "not applicable"; among real results the more severe one is kept.
func severityRank(state State) int {
	switch state {
	case FAIL:
		return 5
	case WARN:
		return 4
	case PASS:
		return 3
	case INFO:
		return 2
	case NOT_APPLICABLE:
		return 1
	default:
		return 0
	}
}

func targetPriority(t NodeType) int {
	switch t {
	case MASTER:
		return 0
	case CONTROLPLANE:
		return 1
	case ETCD:
		return 2
	case NODE:
		return 3
	case POLICIES:
		return 4
	case MANAGEDSERVICES:
		return 5
	default:
		return 6
	}
}

// Deduplicate folds checks sharing the same identifier across the selected
// controls into one result and records every contributing source on the kept
// check. The kept result is the most severe one; ties are broken by a stable
// target priority then by file order. Only controls accepted by include are
// considered, which lets callers restrict de-duplication to role-bearing
// targets on mixed-role machines.
//
// Deduplicate returns the number of check occurrences that were folded into
// another result.
func Deduplicate(collection []*Controls, include func(*Controls) bool) int {
	type location struct {
		controls *Controls
		index    int // position in the collection, for stable tie-breaking
		group    *Group
		check    *Check
	}

	var order []string
	seen := make(map[string]bool)
	occurrences := make(map[string][]*location)

	for i, c := range collection {
		if include != nil && !include(c) {
			continue
		}
		for _, g := range c.Groups {
			for _, ch := range g.Checks {
				if !seen[ch.ID] {
					seen[ch.ID] = true
					order = append(order, ch.ID)
				}
				occurrences[ch.ID] = append(occurrences[ch.ID], &location{
					controls: c,
					index:    i,
					group:    g,
					check:    ch,
				})
			}
		}
	}

	removed := make(map[*Check]bool)
	deduplicated := 0

	for _, id := range order {
		locs := occurrences[id]
		if len(locs) < 2 {
			continue
		}

		sort.SliceStable(locs, func(i, j int) bool {
			ri, rj := severityRank(locs[i].check.State), severityRank(locs[j].check.State)
			if ri != rj {
				return ri > rj
			}
			pi, pj := targetPriority(locs[i].controls.Type), targetPriority(locs[j].controls.Type)
			if pi != pj {
				return pi < pj
			}
			return locs[i].index < locs[j].index
		})

		primary := locs[0]
		sources := make([]string, 0, len(locs))
		states := make(map[string]State, len(locs))
		seenSource := make(map[string]bool, len(locs))

		for _, loc := range locs {
			src := sourceName(loc.controls)
			if !seenSource[src] {
				seenSource[src] = true
				sources = append(sources, src)
			}
			// If the same source produced the identifier twice, keep the most
			// severe occurrence for that source.
			if prev, ok := states[src]; !ok || severityRank(loc.check.State) > severityRank(prev) {
				states[src] = loc.check.State
			}
		}
		sort.Strings(sources)

		if len(sources) > 1 {
			primary.check.Sources = sources
			primary.check.SourceStates = make(map[string]string, len(states))
			for src, state := range states {
				primary.check.SourceStates[src] = string(state)
			}
		}

		for _, loc := range locs[1:] {
			removed[loc.check] = true
			deduplicated++
			if loc.controls.Applicability != nil {
				loc.controls.Applicability.Deduplicated++
			}
		}
	}

	if deduplicated == 0 {
		return 0
	}

	for _, c := range collection {
		if include != nil && !include(c) {
			continue
		}
		var groups []*Group
		for _, g := range c.Groups {
			var kept []*Check
			for _, ch := range g.Checks {
				if !removed[ch] {
					kept = append(kept, ch)
				}
			}
			g.Checks = kept
			if len(g.Checks) > 0 {
				groups = append(groups, g)
			}
		}
		c.Groups = groups
		c.recalculate()
		if c.Applicability != nil {
			c.Applicability.Covered = c.Summary.Pass + c.Summary.Fail + c.Summary.Warn + c.Summary.Info
			c.Applicability.NotApplicable = c.Summary.NotApplicable
		}
	}

	return deduplicated
}

func sourceName(c *Controls) string {
	if c.Type != "" {
		return string(c.Type)
	}
	return c.ID
}

// String renders a short human-readable summary of the applicability.
func (a *Applicability) String() string {
	if a == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString(string(a.State))
	if a.ReasonCode != "" {
		b.WriteString(" (" + a.ReasonCode + ")")
	}
	if a.Reason != "" {
		b.WriteString(": " + a.Reason)
	}
	b.WriteString(fmt.Sprintf(" [covered=%d not_applicable=%d", a.Covered, a.NotApplicable))
	if a.Deduplicated > 0 {
		b.WriteString(fmt.Sprintf(" deduplicated=%d", a.Deduplicated))
	}
	b.WriteString("]")
	return b.String()
}
