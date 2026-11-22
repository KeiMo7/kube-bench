// Package aggregate builds a cluster-level summary from individual
// single-node kube-bench JSON reports.
//
// It never executes checks itself: every conclusion is derived solely from
// the report files handed to it. The original report bytes are preserved
// verbatim in the output so that no field produced by a single-node run is
// rewritten or discarded.
package aggregate

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Status values used for cluster-level control conclusions.
const (
	// StatusPass means every node covering the control reported PASS.
	StatusPass = "PASS"
	// StatusFail means the covering nodes agreed on FAIL: the control is non-compliant.
	StatusFail = "FAIL"
	// StatusWarn means the covering nodes agreed on a non-conclusive state
	// (WARN or INFO): the check did not produce a pass/fail conclusion.
	StatusWarn = "WARN"
	// StatusInfo means the covering nodes agreed on INFO.
	StatusInfo = "INFO"
	// StatusMixed means the covering nodes disagree; deviating nodes are named.
	StatusMixed = "MIXED"
	// StatusConflict means the same control number maps to different titles
	// across benchmark versions; the variants cannot be merged.
	StatusConflict = "CONFLICT"
)

// ReportRef identifies a single-node report file and the node (source) it
// belongs to. The source label is supplied explicitly: a report file carries
// no source identifier of its own, and the aggregator must never invent one.
type ReportRef struct {
	Source string
	Path   string
}

// ParseError records a report that could not be included in the aggregation.
type ParseError struct {
	Source string `json:"source"`
	Path   string `json:"path"`
	Error  string `json:"error"`
}

// Summary mirrors check.Summary using the exact JSON field names used by
// single-node reports so the counting vocabulary stays identical.
type Summary struct {
	Pass int `json:"total_pass"`
	Fail int `json:"total_fail"`
	Warn int `json:"total_warn"`
	Info int `json:"total_info"`
}

// RawCheck is the subset of a single-node check that is needed for alignment.
// The remaining fields stay untouched inside RawReport.
type RawCheck struct {
	Number string `json:"test_number"`
	Text   string `json:"test_desc"`
	Status string `json:"status"`
}

// RawGroup is the subset of a report section (group) that is needed.
type RawGroup struct {
	Section string     `json:"section"`
	Text    string     `json:"desc"`
	Checks  []RawCheck `json:"results"`
}

// RawControls is the subset of a Controls block that is needed.
type RawControls struct {
	ID       string     `json:"id"`
	Version  string     `json:"version"`
	Text     string     `json:"text"`
	NodeType string     `json:"node_type"`
	Groups   []RawGroup `json:"tests"`
	Summary
}

// ParsedReport is one successfully decoded report.
type ParsedReport struct {
	Source      string          `json:"source"`
	Path        string          `json:"path"`
	CollectedAt time.Time       `json:"-"`
	NodeTypes   []string        `json:"node_types"`
	Versions    []string        `json:"benchmark_versions"`
	Sections    []RawControls   `json:"-"`
	Totals      Summary         `json:"report_totals"`
	TotalChecks int             `json:"total_checks"`
	RawReport   json.RawMessage `json:"raw_report"`
}

// CheckObservation is one node's result for a given control number.
type CheckObservation struct {
	Source           string `json:"source"`
	Status           string `json:"status"`
	BenchmarkVersion string `json:"benchmark_version"`
	NodeType         string `json:"node_type"`
	Section          string `json:"section"`
}

// TitleConflictVariant describes one appearance of a control number whose
// title does not agree across reports.
type TitleConflictVariant struct {
	Title            string `json:"title"`
	BenchmarkVersion string `json:"benchmark_version"`
	NodeType         string `json:"node_type"`
	Source           string `json:"source"`
	Status           string `json:"status"`
}

// ControlResult is the cluster-level conclusion for one control number.
type ControlResult struct {
	ID                string             `json:"id"`
	Title             string             `json:"title"`
	ClusterStatus     string             `json:"cluster_status"`
	NodesEvaluated    int                `json:"nodes_evaluated"`
	StatusCounts      map[string]int     `json:"status_counts"`
	ConsistentNodes   []string           `json:"consistent_nodes"`
	DeviatingNodes    []NodeDeviation    `json:"deviating_nodes"`
	UncoveredNodes    []string           `json:"uncovered_nodes"`
	Observations      []CheckObservation `json:"observations"`
	BenchmarkVersions []string           `json:"benchmark_versions"`
	NodeTypes         []string           `json:"node_types"`
}

// NodeDeviation names a node whose status differs from the majority view.
type NodeDeviation struct {
	Source string `json:"source"`
	Status string `json:"status"`
}

// VersionConflict is a control number whose title differs between benchmark
// versions (same number, different meaning). It is never silently merged.
type VersionConflict struct {
	ID       string                 `json:"id"`
	Variants []TitleConflictVariant `json:"variants"`
}

// DuplicateSource records every report seen for a source, marking the one
// actually used for aggregation.
type DuplicateSource struct {
	Source       string         `json:"source"`
	SelectedPath string         `json:"selected_path"`
	SelectedAt   time.Time      `json:"selected_collected_at"`
	AllReports   []SourceReport `json:"all_reports"`
}

// SourceReport describes one report file supplied for a source.
type SourceReport struct {
	Path        string    `json:"path"`
	CollectedAt time.Time `json:"collected_at"`
	Used        bool      `json:"used"`
	ParseError  string    `json:"parse_error,omitempty"`
}

// SourceReconciliation makes mismatches between the expected machine count
// and the reports actually provided explicit.
type SourceReconciliation struct {
	ExpectedSources []string `json:"expected_sources"`
	MissingSources  []string `json:"missing_sources"`
	ExtraSources    []string `json:"extra_sources"`
}

// ClusterSummary is the machine-readable aggregation result.
type ClusterSummary struct {
	SchemaVersion      string               `json:"schema_version"`
	AllReportsFailed   bool                 `json:"all_reports_failed"`
	Totals             Summary              `json:"cluster_totals"`
	TotalChecks        int                  `json:"total_checks"`
	NodesParticipating int                  `json:"nodes_participating"`
	ReportsProvided    int                  `json:"reports_provided"`
	ReportsParsed      int                  `json:"reports_parsed"`
	Controls           []ControlResult      `json:"controls"`
	VersionConflicts   []VersionConflict    `json:"version_conflicts"`
	Sources            []*ParsedReport      `json:"sources"`
	Duplicates         []DuplicateSource    `json:"duplicate_sources"`
	SourceReconcile    SourceReconciliation `json:"source_reconciliation"`
	ParseErrors        []ParseError         `json:"parse_errors"`
}

const schemaVersion = "aggregate/v1"

// envelope supports both the default {"Controls":...,"Totals":...} shape
// and the --nototals bare-array shape.
type envelope struct {
	Controls []RawControls `json:"Controls"`
	Totals   *Summary      `json:"Totals"`
}

// decodeReport reads and parses one report file. Read/parse failures are
// returned as errors rather than aborting the whole aggregation.
func decodeReport(ref ReportRef) (*ParsedReport, error) {
	raw, err := os.ReadFile(ref.Path)
	if err != nil {
		return nil, fmt.Errorf("cannot read report: %v", err)
	}

	info, err := os.Stat(ref.Path)
	if err != nil {
		return nil, fmt.Errorf("cannot stat report: %v", err)
	}

	// Re-encode through json.RawMessage validation so RawReport always holds
	// canonical, re-emittable JSON without dropping any original fields.
	if !json.Valid(raw) {
		return nil, fmt.Errorf("invalid JSON: %s", ref.Path)
	}

	var sections []RawControls
	var reportTotals *Summary
	trimmed := strings.TrimSpace(string(raw))
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal(raw, &sections); err != nil {
			return nil, fmt.Errorf("failed to decode report array: %v", err)
		}
	} else {
		var env envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			return nil, fmt.Errorf("failed to decode report object: %v", err)
		}
		sections = env.Controls
		reportTotals = env.Totals
	}

	if len(sections) == 0 {
		return nil, fmt.Errorf("report contains no Controls sections")
	}

	canonical, err := json.Marshal(json.RawMessage(raw))
	if err != nil {
		return nil, fmt.Errorf("failed to re-encode report: %v", err)
	}

	p := &ParsedReport{
		Source:      ref.Source,
		Path:        ref.Path,
		CollectedAt: info.ModTime().UTC(),
		Sections:    sections,
		RawReport:   canonical,
	}

	nodeTypes := map[string]bool{}
	versions := map[string]bool{}
	checkCount := 0
	var summed Summary
	for _, sec := range sections {
		if sec.NodeType != "" {
			nodeTypes[sec.NodeType] = true
		}
		if sec.Version != "" {
			versions[sec.Version] = true
		}
		summed.Pass += sec.Pass
		summed.Fail += sec.Fail
		summed.Warn += sec.Warn
		summed.Info += sec.Info
		for _, g := range sec.Groups {
			checkCount += len(g.Checks)
		}
	}
	p.NodeTypes = sortedKeys(nodeTypes)
	p.Versions = sortedKeys(versions)
	p.TotalChecks = checkCount

	// Counting stays consistent with the single-node report: prefer the
	// report's own Totals block, fall back to summing the sections only when
	// the report was produced with --nototals.
	if reportTotals != nil {
		p.Totals = *reportTotals
	} else {
		p.Totals = summed
	}
	return p, nil
}

type checkOccurrence struct {
	source   string
	status   string
	title    string
	version  string
	nodeType string
	section  string
}

// Aggregate builds the cluster-level summary from the supplied report
// references. expectedSources, when non-empty, enables explicit missing/extra
// source reconciliation.
func Aggregate(refs []ReportRef, expectedSources []string) (*ClusterSummary, error) {
	if len(refs) == 0 {
		return nil, fmt.Errorf("no reports supplied")
	}

	// Deterministic input order: repeated runs over the same arguments must
	// produce byte-identical output.
	sortedRefs := make([]ReportRef, len(refs))
	copy(sortedRefs, refs)
	sort.SliceStable(sortedRefs, func(i, j int) bool {
		if sortedRefs[i].Source != sortedRefs[j].Source {
			return sortedRefs[i].Source < sortedRefs[j].Source
		}
		return sortedRefs[i].Path < sortedRefs[j].Path
	})

	summary := &ClusterSummary{
		SchemaVersion:    schemaVersion,
		Controls:         []ControlResult{},
		VersionConflicts: []VersionConflict{},
		Sources:          []*ParsedReport{},
		Duplicates:       []DuplicateSource{},
		ParseErrors:      []ParseError{},
	}
	summary.ReportsProvided = len(sortedRefs)

	// Track every file seen per source, including unparseable ones.
	allBySource := map[string][]SourceReport{}
	parsedBySource := map[string][]*ParsedReport{}
	for _, ref := range sortedRefs {
		if strings.TrimSpace(ref.Source) == "" {
			return nil, fmt.Errorf("report %q has no source identifier; pass --report <source>=<path>", ref.Path)
		}
		p, err := decodeReport(ref)
		if err != nil {
			summary.ParseErrors = append(summary.ParseErrors, ParseError{
				Source: ref.Source,
				Path:   ref.Path,
				Error:  err.Error(),
			})
			allBySource[ref.Source] = append(allBySource[ref.Source], SourceReport{
				Path:       ref.Path,
				ParseError: err.Error(),
			})
			continue
		}
		summary.ReportsParsed++
		parsedBySource[ref.Source] = append(parsedBySource[ref.Source], p)
		allBySource[ref.Source] = append(allBySource[ref.Source], SourceReport{
			Path:        p.Path,
			CollectedAt: p.CollectedAt,
		})
	}

	if summary.ReportsParsed == 0 {
		// Still return the structured errors so the caller can emit them.
		summary.AllReportsFailed = true
		summary.reconcile(expectedSources, map[string]bool{})
		return summary, fmt.Errorf("none of the %d supplied reports could be parsed", len(sortedRefs))
	}

	// Deduplicate: newest report per source wins, ties broken by path so the
	// outcome never depends on filesystem iteration order.
	selected := map[string]*ParsedReport{}
	sourceNames := make([]string, 0, len(parsedBySource))
	for source, reports := range parsedBySource {
		sourceNames = append(sourceNames, source)
		winner := reports[0]
		for _, r := range reports[1:] {
			if r.CollectedAt.After(winner.CollectedAt) ||
				(r.CollectedAt.Equal(winner.CollectedAt) && r.Path < winner.Path) {
				winner = r
			}
		}
		selected[source] = winner
	}
	sort.Strings(sourceNames)

	for _, source := range sourceNames {
		winner := selected[source]
		entries := allBySource[source]
		used := false
		hasDuplicate := len(entries) > 1
		for i := range entries {
			if entries[i].Path == winner.Path {
				entries[i].Used = true
				used = true
			}
		}
		if hasDuplicate || !used {
			summary.Duplicates = append(summary.Duplicates, DuplicateSource{
				Source:       source,
				SelectedPath: winner.Path,
				SelectedAt:   winner.CollectedAt,
				AllReports:   entries,
			})
		}
	}

	// Collect every check occurrence keyed by control number.
	occurrences := map[string][]checkOccurrence{}
	for _, source := range sourceNames {
		report := selected[source]
		summary.Sources = append(summary.Sources, report)
		summary.Totals.Pass += report.Totals.Pass
		summary.Totals.Fail += report.Totals.Fail
		summary.Totals.Warn += report.Totals.Warn
		summary.Totals.Info += report.Totals.Info
		summary.TotalChecks += report.TotalChecks

		for _, sec := range report.Sections {
			for _, g := range sec.Groups {
				for _, c := range g.Checks {
					occurrences[c.Number] = append(occurrences[c.Number], checkOccurrence{
						source:   source,
						status:   c.Status,
						title:    c.Text,
						version:  sec.Version,
						nodeType: sec.NodeType,
						section:  g.Section,
					})
				}
			}
		}
	}
	summary.NodesParticipating = len(sourceNames)

	allSourcesSet := map[string]bool{}
	for _, s := range sourceNames {
		allSourcesSet[s] = true
	}
	summary.reconcile(expectedSources, allSourcesSet)
	summary.buildControls(sourceNames, occurrences)

	sort.SliceStable(summary.ParseErrors, func(i, j int) bool {
		if summary.ParseErrors[i].Source != summary.ParseErrors[j].Source {
			return summary.ParseErrors[i].Source < summary.ParseErrors[j].Source
		}
		return summary.ParseErrors[i].Path < summary.ParseErrors[j].Path
	})
	return summary, nil
}

func (s *ClusterSummary) reconcile(expectedSources []string, have map[string]bool) {
	s.SourceReconcile.ExpectedSources = append([]string{}, expectedSources...)
	s.SourceReconcile.MissingSources = []string{}
	s.SourceReconcile.ExtraSources = []string{}
	sort.Strings(s.SourceReconcile.ExpectedSources)
	for _, name := range expectedSources {
		if !have[name] {
			s.SourceReconcile.MissingSources = append(s.SourceReconcile.MissingSources, name)
		}
	}
	if len(expectedSources) > 0 {
		for name := range have {
			if !contains(expectedSources, name) {
				s.SourceReconcile.ExtraSources = append(s.SourceReconcile.ExtraSources, name)
			}
		}
		sort.Strings(s.SourceReconcile.ExtraSources)
	}
	sort.Strings(s.SourceReconcile.MissingSources)
}

func (s *ClusterSummary) buildControls(allSources []string, occurrences map[string][]checkOccurrence) {
	ids := make([]string, 0, len(occurrences))
	for id := range occurrences {
		ids = append(ids, id)
	}
	naturalSort(ids)

	for _, id := range ids {
		occs := occurrences[id]
		sort.SliceStable(occs, func(i, j int) bool {
			if occs[i].source != occs[j].source {
				return occs[i].source < occs[j].source
			}
			return occs[i].version < occs[j].version
		})

		// Requirement: same number but different title is a version conflict;
		// never merge.
		titles := map[string]bool{}
		for _, o := range occs {
			titles[o.title] = true
		}
		if len(titles) > 1 {
			s.VersionConflicts = append(s.VersionConflicts, buildVersionConflict(id, occs))
			continue
		}

		covering := map[string]bool{}
		statusCounts := map[string]int{}
		obs := make([]CheckObservation, 0, len(occs))
		versions, nodeTypes := map[string]bool{}, map[string]bool{}
		for _, o := range occs {
			covering[o.source] = true
			statusCounts[o.status]++
			versions[o.version] = true
			nodeTypes[o.nodeType] = true
			obs = append(obs, CheckObservation{
				Source:           o.source,
				Status:           o.status,
				BenchmarkVersion: o.version,
				NodeType:         o.nodeType,
				Section:          o.section,
			})
		}

		uncovered := []string{}
		for _, src := range allSources {
			if !covering[src] {
				uncovered = append(uncovered, src)
			}
		}

		// Majority = the largest status group; ties broken by the fixed
		// severity ordering FAIL > WARN > INFO > PASS so the result does not
		// depend on map iteration order.
		majorityStatus, _ := majority(statusCounts)
		consistent, deviations := []string{}, []NodeDeviation{}
		for _, o := range occs {
			if o.status == majorityStatus {
				consistent = append(consistent, o.source)
			} else {
				deviations = append(deviations, NodeDeviation{Source: o.source, Status: o.status})
			}
		}
		sort.Strings(consistent)

		clusterStatus := majorityStatus
		if len(statusCounts) > 1 {
			clusterStatus = StatusMixed
		}

		s.Controls = append(s.Controls, ControlResult{
			ID:                id,
			Title:             occs[0].title,
			ClusterStatus:     clusterStatus,
			NodesEvaluated:    len(covering),
			StatusCounts:      statusCounts,
			ConsistentNodes:   consistent,
			DeviatingNodes:    deviations,
			UncoveredNodes:    uncovered,
			Observations:      obs,
			BenchmarkVersions: sortedKeys(versions),
			NodeTypes:         sortedKeys(nodeTypes),
		})
	}
}

func buildVersionConflict(id string, occs []checkOccurrence) VersionConflict {
	vc := VersionConflict{ID: id, Variants: []TitleConflictVariant{}}
	seen := map[string]bool{}
	for _, o := range occs {
		key := o.title + "|" + o.version + "|" + o.nodeType + "|" + o.source
		if seen[key] {
			continue
		}
		seen[key] = true
		vc.Variants = append(vc.Variants, TitleConflictVariant{
			Title:            o.title,
			BenchmarkVersion: o.version,
			NodeType:         o.nodeType,
			Source:           o.source,
			Status:           o.status,
		})
	}
	sort.SliceStable(vc.Variants, func(i, j int) bool {
		if vc.Variants[i].Title != vc.Variants[j].Title {
			return vc.Variants[i].Title < vc.Variants[j].Title
		}
		return vc.Variants[i].Source < vc.Variants[j].Source
	})
	return vc
}

// severityRank gives a deterministic precedence when status groups tie.
func severityRank(status string) int {
	switch status {
	case StatusFail:
		return 0
	case StatusWarn:
		return 1
	case StatusInfo:
		return 2
	case StatusPass:
		return 3
	default:
		return 4
	}
}

func majority(counts map[string]int) (string, int) {
	var bestStatus string
	bestCount := -1
	for status, n := range counts {
		if n > bestCount || (n == bestCount && severityRank(status) < severityRank(bestStatus)) {
			bestStatus = status
			bestCount = n
		}
	}
	return bestStatus, bestCount
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func contains(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}

// naturalSort sorts dotted numeric identifiers (e.g. 1.1.2 before 1.1.10)
// and falls back to lexicographic order for non-numeric segments.
func naturalSort(items []string) {
	sort.SliceStable(items, func(i, j int) bool {
		return naturalLess(items[i], items[j])
	})
}

func naturalLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for k := 0; k < len(pa) && k < len(pb); k++ {
		na, errA := strconv.Atoi(pa[k])
		nb, errB := strconv.Atoi(pb[k])
		if errA == nil && errB == nil && na != nb {
			return na < nb
		}
		if pa[k] != pb[k] {
			return pa[k] < pb[k]
		}
	}
	return len(pa) < len(pb)
}
