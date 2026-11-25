// Copyright © 2025 Aqua Security Software Ltd. <info@aquasec.com>
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

package baseline

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aquasecurity/kube-bench/check"
)

// Selection is a fully resolved baseline selection. The SourceKey is
// produced here exactly once and only passed through every later stage.
type Selection struct {
	Family      string
	Version     string
	Target      string
	SourceKey   SourceKey
	Definitions string
	Config      string
	// Degraded is true when selection fell back to the family default.
	Degraded bool
	// DegradeReason explains a default fallback, when Degraded is true.
	DegradeReason string
	// ManifestPath and EntryVersion identify the manifest/entry for errors.
	ManifestPath string
}

// Resolve turns a family plus a requested cluster version and a target
// into a Selection, applying the deterministic overlap rule and the
// explicit-default degradation path.
func (r *Registry) Resolve(family, requestedVersion, target string) (*Selection, error) {
	m, ok := r.Family(family)
	if !ok {
		return nil, fmt.Errorf("family %q is not registered", family)
	}

	// An explicit definition-version pin ("family/version") bypasses range
	// matching but still has to be a declared entry.
	if b, ok := m.Baseline(requestedVersion); ok {
		if err := validateTarget(b, target); err != nil {
			return nil, err
		}
		return r.newSelection(m, b, target, false, ""), nil
	}

	res, err := selectVersion(m, requestedVersion)
	if err != nil {
		return nil, err
	}
	b, ok := m.Baseline(res.version)
	if !ok {
		return nil, fmt.Errorf("%s: resolved version %q is not registered", m.origin, res.version)
	}
	if err := validateTarget(b, target); err != nil {
		return nil, err
	}
	return r.newSelection(m, b, target, res.degraded, res.reason), nil
}

func validateTarget(b *Baseline, target string) error {
	if !b.HasTarget(target) {
		return fmt.Errorf("target %q is not available for %s; available targets: %s",
			target, b.Version, strings.Join(b.Targets, ","))
	}
	return nil
}

func (r *Registry) newSelection(m *Manifest, b *Baseline, target string, degraded bool, reason string) *Selection {
	key := SourceKey{Family: m.Family, Version: b.Version, Target: target}
	return &Selection{
		Family:        m.Family,
		Version:       b.Version,
		Target:        target,
		SourceKey:     key,
		Definitions:   b.Definitions,
		Config:        b.Config,
		Degraded:      degraded,
		DegradeReason: reason,
		ManifestPath:  m.origin,
	}
}

// DuplicateEntry records a check number that appeared more than once under
// the same source key. Only the first occurrence is kept as an independent
// item; duplicates are excluded from every pass/fail/warn/info counter.
type DuplicateEntry struct {
	SourceKey  SourceKey `json:"source_key"`
	CheckID    string    `json:"check_id"`
	Occurrence int       `json:"occurrence"`
}

// ConflictPair records the same check number appearing under two different
// family/version sources with a different judgment type or expected value.
// Both original values are retained; nothing is silently overwritten.
type ConflictPair struct {
	CheckID       string `json:"check_id"`
	SourceA       string `json:"source_a"`
	SourceB       string `json:"source_b"`
	TypeA         string `json:"type_a"`
	TypeB         string `json:"type_b"`
	ExpectedA     string `json:"expected_a"`
	ExpectedB     string `json:"expected_b"`
	ConflictField string `json:"conflict_field"`
}

// DefinitionError records a single check definition that could not be
// parsed. The check is skipped and counted, while all other checks run.
type DefinitionError struct {
	SourceKey SourceKey `json:"source_key"`
	EntryID   string    `json:"entry_id"`
	Reason    string    `json:"reason"`
}

// NormalizedReport is the merged view of one run across any number of
// families and definition versions.
type NormalizedReport struct {
	// Items are the independent check items. The same check number under
	// different families is represented by separate items, never merged.
	Items []*NormalizedItem `json:"items"`
	// Duplicates are repeated occurrences under one source key.
	Duplicates []DuplicateEntry `json:"duplicates,omitempty"`
	// Conflicts are same-numbered, semantically different checks across
	// family/version sources.
	Conflicts []ConflictPair `json:"conflicts,omitempty"`
	// DefinitionErrors are unparseable individual check definitions.
	DefinitionErrors []DefinitionError `json:"definition_errors,omitempty"`
	// Summary counts normalized independent items; duplicates are excluded.
	Summary NormalizedSummary `json:"summary"`
}

// NormalizedItem is one independent check after normalization.
type NormalizedItem struct {
	SourceKey     SourceKey           `json:"source_key"`
	Normalization string              `json:"normalization_key"`
	GroupID       string              `json:"group_id"`
	Check         *check.Check        `json:"check"`
	Semantic      SemanticFingerprint `json:"semantic"`
}

// SemanticFingerprint captures the parts of a check that define its
// judgment semantics. Two same-numbered checks with different fingerprints
// are explicit conflicts.
type SemanticFingerprint struct {
	Type           string `json:"type"`
	ExpectedResult string `json:"expected_result"`
}

// NormalizedSummary counts in normalized-item units. Duplicate and conflict
// counts are reported separately from pass/fail/warn/info.
type NormalizedSummary struct {
	Total            int `json:"total"`
	Pass             int `json:"total_pass"`
	Fail             int `json:"total_fail"`
	Warn             int `json:"total_warn"`
	Info             int `json:"total_info"`
	DuplicateCount   int `json:"duplicate_count"`
	ConflictCount    int `json:"conflict_count"`
	DefinitionErrors int `json:"definition_error_count"`
}

// Normalizer accumulates executed controls across selections. It owns the
// single place where source keys are attached.
type Normalizer struct {
	items       []*NormalizedItem
	duplicates  []DuplicateEntry
	conflicts   []ConflictPair
	defErrors   []DefinitionError
	seen        map[string]int // source+group+check -> first item index
	occurrences map[string]int // source+check -> occurrence count
	byNumber    map[string][]*NormalizedItem
}

// NewNormalizer creates an empty Normalizer.
func NewNormalizer() *Normalizer {
	return &Normalizer{
		seen:        make(map[string]int),
		occurrences: make(map[string]int),
		byNumber:    make(map[string][]*NormalizedItem),
	}
}

// AddControls attaches the selection's source key to every executed check
// and applies the stable same-source dedup rule: the first occurrence of a
// check number under one source key is kept, later occurrences are marked
// duplicates and excluded from all counters.
func (n *Normalizer) AddControls(sel *Selection, controls *check.Controls) {
	if sel == nil || !sel.SourceKey.Valid() {
		// A result without all three source layers is illegal and cannot
		// enter the normalized report.
		return
	}
	for _, group := range controls.Groups {
		for _, c := range group.Checks {
			occKey := sel.SourceKey.String() + "#" + c.ID
			n.occurrences[occKey]++
			if n.occurrences[occKey] > 1 {
				n.duplicates = append(n.duplicates, DuplicateEntry{
					SourceKey:  sel.SourceKey,
					CheckID:    c.ID,
					Occurrence: n.occurrences[occKey],
				})
				continue
			}

			item := &NormalizedItem{
				SourceKey:     sel.SourceKey,
				Normalization: sel.SourceKey.NormalizedKey(),
				GroupID:       group.ID,
				Check:         c,
				Semantic: SemanticFingerprint{
					Type:           c.Type,
					ExpectedResult: c.ExpectedResult,
				},
			}
			n.seen[occKey] = len(n.items)
			n.items = append(n.items, item)
			n.byNumber[c.ID] = append(n.byNumber[c.ID], item)
		}
	}
}

// AddDefinitionError records an unparseable individual check definition.
func (n *Normalizer) AddDefinitionError(key SourceKey, entryID, reason string) {
	n.defErrors = append(n.defErrors, DefinitionError{
		SourceKey: key,
		EntryID:   entryID,
		Reason:    reason,
	})
}

// Report finalizes the merged report: cross-source semantic conflicts are
// detected, counters are computed from normalized independent items only,
// and items are ordered deterministically.
func (n *Normalizer) Report() *NormalizedReport {
	n.detectConflicts()

	report := &NormalizedReport{
		Items:            n.items,
		Duplicates:       n.duplicates,
		Conflicts:        n.conflicts,
		DefinitionErrors: n.defErrors,
	}

	for _, item := range n.items {
		report.Summary.Total++
		switch item.Check.State {
		case check.PASS:
			report.Summary.Pass++
		case check.FAIL:
			report.Summary.Fail++
		case check.WARN:
			report.Summary.Warn++
		case check.INFO:
			report.Summary.Info++
		}
	}
	report.Summary.DuplicateCount = len(n.duplicates)
	report.Summary.ConflictCount = len(n.conflicts)
	report.Summary.DefinitionErrors = len(n.defErrors)

	n.sortReport(report)
	return report
}

// detectConflicts compares every pair of same-numbered items from different
// family/version sources. Both original values are always retained.
func (n *Normalizer) detectConflicts() {
	seenPairs := make(map[string]bool)
	for number, sameNumber := range n.byNumber {
		for i := 0; i < len(sameNumber); i++ {
			for j := i + 1; j < len(sameNumber); j++ {
				a, b := sameNumber[i], sameNumber[j]
				if a.Normalization == b.Normalization {
					continue // same source: dedup, not conflict
				}
				field, conflicted := semanticDifference(a.Semantic, b.Semantic)
				if !conflicted {
					continue
				}
				pairKey := number + "|" + pairOrderKey(a, b)
				if seenPairs[pairKey] {
					continue
				}
				seenPairs[pairKey] = true
				n.conflicts = append(n.conflicts, ConflictPair{
					CheckID:       number,
					SourceA:       a.Normalization,
					SourceB:       b.Normalization,
					TypeA:         a.Semantic.Type,
					TypeB:         b.Semantic.Type,
					ExpectedA:     a.Semantic.ExpectedResult,
					ExpectedB:     b.Semantic.ExpectedResult,
					ConflictField: field,
				})
			}
		}
	}
}

func semanticDifference(a, b SemanticFingerprint) (field string, conflicted bool) {
	if a.Type != b.Type {
		return "type", true
	}
	if a.ExpectedResult != b.ExpectedResult {
		return "expected_result", true
	}
	return "", false
}

func pairOrderKey(a, b *NormalizedItem) string {
	if a.Normalization < b.Normalization {
		return a.Normalization + "|" + b.Normalization
	}
	return b.Normalization + "|" + a.Normalization
}

// sortReport gives deterministic output independent of map iteration.
func (n *Normalizer) sortReport(report *NormalizedReport) {
	sort.SliceStable(report.Items, func(i, j int) bool {
		a, b := report.Items[i], report.Items[j]
		if a.SourceKey.Family != b.SourceKey.Family {
			return a.SourceKey.Family < b.SourceKey.Family
		}
		if a.SourceKey.Version != b.SourceKey.Version {
			return a.SourceKey.Version < b.SourceKey.Version
		}
		if a.SourceKey.Target != b.SourceKey.Target {
			return a.SourceKey.Target < b.SourceKey.Target
		}
		return checkNumberLess(a.Check.ID, b.Check.ID)
	})
	sort.SliceStable(report.Conflicts, func(i, j int) bool {
		if report.Conflicts[i].CheckID != report.Conflicts[j].CheckID {
			return checkNumberLess(report.Conflicts[i].CheckID, report.Conflicts[j].CheckID)
		}
		return report.Conflicts[i].SourceA < report.Conflicts[j].SourceA
	})
	sort.SliceStable(report.Duplicates, func(i, j int) bool {
		if report.Duplicates[i].CheckID != report.Duplicates[j].CheckID {
			return checkNumberLess(report.Duplicates[i].CheckID, report.Duplicates[j].CheckID)
		}
		return report.Duplicates[i].SourceKey.String() < report.Duplicates[j].SourceKey.String()
	})
}

// checkNumberLess compares dotted numeric check ids ("1.2.10" after
// "1.2.9"), falling back to lexical comparison for non-numeric segments.
func checkNumberLess(a, b string) bool {
	sa, sb := strings.Split(a, "."), strings.Split(b, ".")
	n := len(sa)
	if len(sb) < n {
		n = len(sb)
	}
	for i := 0; i < n; i++ {
		na, errA := parseLeadingInt(sa[i])
		nb, errB := parseLeadingInt(sb[i])
		if errA != nil || errB != nil {
			if sa[i] != sb[i] {
				return sa[i] < sb[i]
			}
			continue
		}
		if na != nb {
			return na < nb
		}
	}
	return len(sa) < len(sb)
}

func parseLeadingInt(s string) (int, error) {
	var n int
	var parsed bool
	for _, r := range s {
		if r < '0' || r > '9' {
			break
		}
		n = n*10 + int(r-'0')
		parsed = true
	}
	if !parsed {
		return 0, fmt.Errorf("no leading integer in %q", s)
	}
	return n, nil
}
