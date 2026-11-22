package aggregate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// reportBuilder is a compact helper for constructing single-node reports that
// keep the exact JSON shape emitted by kube-bench --json.
type reportBuilder struct {
	sections []RawControls
}

func (b *reportBuilder) section(id, version, text, nodeType string, checks ...RawCheck) *reportBuilder {
	b.sections = append(b.sections, RawControls{
		ID:       id,
		Version:  version,
		Text:     text,
		NodeType: nodeType,
		Groups: []RawGroup{{
			Section: id,
			Text:    text,
			Checks:  checks,
		}},
	})
	return b
}

func check(num, title, status string) RawCheck {
	return RawCheck{Number: num, Text: title, Status: status}
}

// writeReport writes an enveloped {"Controls":...,"Totals":...} report and
// pins its modification time so duplicate selection is testable.
func writeReport(t *testing.T, dir, name string, b *reportBuilder, mtime time.Time) string {
	t.Helper()
	path := filepath.Join(dir, name)
	env := envelope{Controls: b.sections}
	var totals Summary
	for _, s := range env.Controls {
		for _, g := range s.Groups {
			for _, c := range g.Checks {
				switch c.Status {
				case StatusPass:
					totals.Pass++
				case StatusFail:
					totals.Fail++
				case StatusWarn:
					totals.Warn++
				case StatusInfo:
					totals.Info++
				}
			}
		}
	}
	env.Totals = &totals
	data, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal report %s: %v", name, err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write report %s: %v", name, err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatalf("chtimes report %s: %v", name, err)
	}
	return path
}

func writeBareArrayReport(t *testing.T, dir, name string, b *reportBuilder) string {
	t.Helper()
	path := filepath.Join(dir, name)
	data, err := json.Marshal(b.sections) // --nototals shape
	if err != nil {
		t.Fatalf("marshal array report %s: %v", name, err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write report %s: %v", name, err)
	}
	return path
}

// buildScenario assembles reports exercising every required case:
// consistent (1.1.1), deviation (1.1.2 split PASS/FAIL), uncovered (1.1.4
// exists only on node-b), duplicate (two reports for node-a), version
// conflict (1.1.5 same number, different title across benchmark versions),
// and a conclusive-vs-inconclusive distinction (WARN control 1.1.3).
func buildScenario(t *testing.T) (dir string, refs []ReportRef) {
	t.Helper()
	dir = t.TempDir()
	base := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)

	// Older duplicate for node-a: its 1.1.1 is PASS. The newer report wins
	// and flips 1.1.1 to FAIL, which the assertions can detect.
	oldA := (&reportBuilder{}).
		section("1", "cis-1.10", "Master Node Security Configuration", "master",
			check("1.1.1", "API server pod spec permissions", StatusPass),
			check("1.1.2", "API server anonymous auth", StatusFail),
			check("1.1.3", "Manual check", StatusWarn))
	writeReport(t, dir, "node-a-old.json", oldA, base.Add(-2*time.Hour))

	newA := (&reportBuilder{}).
		section("1", "cis-1.10", "Master Node Security Configuration", "master",
			check("1.1.1", "API server pod spec permissions", StatusFail),
			check("1.1.2", "API server anonymous auth", StatusFail),
			check("1.1.3", "Manual check", StatusWarn))
	pathA := writeReport(t, dir, "node-a-new.json", newA, base)

	nodeB := (&reportBuilder{}).
		section("1", "cis-1.10", "Master Node Security Configuration", "master",
			check("1.1.1", "API server pod spec permissions", StatusPass),
			check("1.1.2", "API server anonymous auth", StatusPass),
			check("1.1.3", "Manual check", StatusWarn),
			check("1.1.4", "Admission control plugin", StatusPass))
	pathB := writeReport(t, dir, "node-b.json", nodeB, base.Add(time.Hour))

	// node-c runs a different benchmark version: 1.1.5 carries a different
	// title for the same number -> conflict; 1.1.1 aligns cleanly by number.
	nodeC := (&reportBuilder{}).
		section("1", "cis-1.11", "Master Node Security Configuration", "master",
			check("1.1.1", "API server pod spec permissions", StatusPass),
			check("1.1.5", "Renamed control in the newer benchmark", StatusFail))
	pathC := writeReport(t, dir, "node-c.json", nodeC, base.Add(2*time.Hour))

	nodeD := (&reportBuilder{}).
		section("1", "cis-1.10", "Master Node Security Configuration", "master",
			check("1.1.5", "Original title of the control", StatusPass))
	pathD := writeBareArrayReport(t, dir, "node-d.json", nodeD)

	refs = []ReportRef{
		{Source: "node-a", Path: filepath.Join(dir, "node-a-old.json")},
		{Source: "node-a", Path: pathA},
		{Source: "node-b", Path: pathB},
		{Source: "node-c", Path: pathC},
		{Source: "node-d", Path: pathD},
	}
	return dir, refs
}

func findControl(t *testing.T, s *ClusterSummary, id string) ControlResult {
	t.Helper()
	for _, c := range s.Controls {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("control %s not found in aggregation", id)
	return ControlResult{}
}

func TestAggregateScenario(t *testing.T) {
	_, refs := buildScenario(t)
	summary, err := Aggregate(refs, []string{"node-a", "node-b", "node-c", "node-d", "node-missing"})
	if err != nil {
		t.Fatalf("aggregate failed: %v", err)
	}
	if len(summary.ParseErrors) != 0 {
		t.Fatalf("unexpected parse errors: %+v", summary.ParseErrors)
	}

	if got, want := summary.NodesParticipating, 4; got != want {
		t.Errorf("nodes participating: got %d want %d", got, want)
	}
	if got, want := summary.ReportsProvided, 5; got != want {
		t.Errorf("reports provided: got %d want %d", got, want)
	}
	if got, want := summary.ReportsParsed, 5; got != want {
		t.Errorf("reports parsed: got %d want %d", got, want)
	}

	// Duplicate handling: newest node-a report selected, both files listed.
	if len(summary.Duplicates) != 1 || summary.Duplicates[0].Source != "node-a" {
		t.Fatalf("expected one duplicate entry for node-a, got %+v", summary.Duplicates)
	}
	dup := summary.Duplicates[0]
	if !stringsHasSuffix(dup.SelectedPath, "node-a-new.json") {
		t.Errorf("wrong selected duplicate: %s", dup.SelectedPath)
	}
	if len(dup.AllReports) != 2 {
		t.Errorf("expected both node-a reports listed, got %d", len(dup.AllReports))
	}
	usedCount := 0
	for _, r := range dup.AllReports {
		if r.Used {
			usedCount++
		}
	}
	if usedCount != 1 {
		t.Errorf("expected exactly one used report, got %d", usedCount)
	}

	// 1.1.1 comes from the NEWER node-a report (FAIL), so the cluster sees a
	// split: node-a FAIL vs node-b/node-c PASS.
	c111 := findControl(t, summary, "1.1.1")
	if c111.ClusterStatus != StatusMixed {
		t.Errorf("1.1.1 expected MIXED, got %s", c111.ClusterStatus)
	}
	if c111.StatusCounts[StatusPass] != 2 || c111.StatusCounts[StatusFail] != 1 {
		t.Errorf("1.1.1 status counts wrong: %+v", c111.StatusCounts)
	}
	if len(c111.DeviatingNodes) != 1 || c111.DeviatingNodes[0].Source != "node-a" ||
		c111.DeviatingNodes[0].Status != StatusFail {
		t.Errorf("1.1.1 deviating nodes wrong: %+v", c111.DeviatingNodes)
	}
	if c111.NodesEvaluated != 3 {
		t.Errorf("1.1.1 nodes evaluated: got %d want 3", c111.NodesEvaluated)
	}
	// node-d does not run 1.1.1: uncovered, never counted as pass.
	if len(c111.UncoveredNodes) != 1 || c111.UncoveredNodes[0] != "node-d" {
		t.Errorf("1.1.1 uncovered nodes wrong: %+v", c111.UncoveredNodes)
	}

	// 1.1.2 splits evenly across node-a (FAIL) and node-b (PASS). With no
	// numeric majority the deterministic severity tie-break (FAIL > WARN >
	// INFO > PASS) names the FAIL group as the headline view and flags node-b
	// as the deviation; node-c/node-d are uncovered.
	c112 := findControl(t, summary, "1.1.2")
	if c112.ClusterStatus != StatusMixed {
		t.Errorf("1.1.2 expected MIXED, got %s", c112.ClusterStatus)
	}
	if len(c112.ConsistentNodes) != 1 || c112.ConsistentNodes[0] != "node-a" {
		t.Errorf("1.1.2 consistent nodes wrong: %+v", c112.ConsistentNodes)
	}
	if len(c112.DeviatingNodes) != 1 || c112.DeviatingNodes[0].Source != "node-b" {
		t.Errorf("1.1.2 deviating nodes wrong: %+v", c112.DeviatingNodes)
	}
	if len(c112.UncoveredNodes) != 2 {
		t.Errorf("1.1.2 uncovered nodes wrong: %+v", c112.UncoveredNodes)
	}

	// 1.1.3 is WARN everywhere: inconclusive, must not be reported as FAIL.
	c113 := findControl(t, summary, "1.1.3")
	if c113.ClusterStatus != StatusWarn {
		t.Errorf("1.1.3 expected WARN (inconclusive), got %s", c113.ClusterStatus)
	}
	if c113.NodesEvaluated != 2 {
		t.Errorf("1.1.3 nodes evaluated: got %d want 2", c113.NodesEvaluated)
	}

	// 1.1.4 exists only on node-b: everyone else is explicitly uncovered.
	c114 := findControl(t, summary, "1.1.4")
	if c114.ClusterStatus != StatusPass {
		t.Errorf("1.1.4 expected PASS, got %s", c114.ClusterStatus)
	}
	if c114.NodesEvaluated != 1 {
		t.Errorf("1.1.4 nodes evaluated: got %d want 1", c114.NodesEvaluated)
	}
	if len(c114.UncoveredNodes) != 3 {
		t.Errorf("1.1.4 uncovered nodes wrong: %+v", c114.UncoveredNodes)
	}

	// 1.1.5 has two titles: conflict, listed separately and never merged.
	var conflict *VersionConflict
	for i := range summary.VersionConflicts {
		if summary.VersionConflicts[i].ID == "1.1.5" {
			conflict = &summary.VersionConflicts[i]
		}
	}
	if conflict == nil {
		t.Fatal("1.1.5 version conflict not reported")
	}
	titles := map[string]bool{}
	for _, v := range conflict.Variants {
		titles[v.Title] = true
	}
	if len(titles) != 2 {
		t.Errorf("expected two conflict variants, got %+v", conflict.Variants)
	}
	for _, c := range summary.Controls {
		if c.ID == "1.1.5" {
			t.Fatal("conflicted control 1.1.5 must not be merged into controls")
		}
	}

	// Reconciliation: node-missing was expected but never supplied.
	if len(summary.SourceReconcile.MissingSources) != 1 ||
		summary.SourceReconcile.MissingSources[0] != "node-missing" {
		t.Errorf("missing source reconciliation wrong: %+v", summary.SourceReconcile)
	}

	// Every count must trace back to the selected input reports.
	var recomputed Summary
	var recomputedChecks int
	for _, src := range summary.Sources {
		recomputed.Pass += src.Totals.Pass
		recomputed.Fail += src.Totals.Fail
		recomputed.Warn += src.Totals.Warn
		recomputed.Info += src.Totals.Info
		recomputedChecks += src.TotalChecks
	}
	if recomputed != summary.Totals {
		t.Errorf("cluster totals %+v not equal to sum of report totals %+v", summary.Totals, recomputed)
	}
	if recomputedChecks != summary.TotalChecks {
		t.Errorf("total checks %d not equal to sum %d", summary.TotalChecks, recomputedChecks)
	}
	for _, c := range summary.Controls {
		sum := 0
		for _, n := range c.StatusCounts {
			sum += n
		}
		if sum != c.NodesEvaluated {
			t.Errorf("control %s: status counts sum %d != nodes evaluated %d", c.ID, sum, c.NodesEvaluated)
		}
		if c.NodesEvaluated+len(c.UncoveredNodes) != summary.NodesParticipating {
			t.Errorf("control %s: evaluated + uncovered != participating nodes", c.ID)
		}
	}
}

func TestAggregateDeterministic(t *testing.T) {
	_, refs := buildScenario(t)
	first, err := Aggregate(refs, nil)
	if err != nil {
		t.Fatalf("first aggregate failed: %v", err)
	}
	second, err := Aggregate(refs, nil)
	if err != nil {
		t.Fatalf("second aggregate failed: %v", err)
	}
	b1, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if string(b1) != string(b2) {
		t.Fatal("aggregation output is not byte-identical across runs")
	}

	// Shuffling the input order must not change the output.
	shuffled := []ReportRef{refs[3], refs[0], refs[4], refs[2], refs[1]}
	third, err := Aggregate(shuffled, nil)
	if err != nil {
		t.Fatalf("shuffled aggregate failed: %v", err)
	}
	b3, err := json.Marshal(third)
	if err != nil {
		t.Fatal(err)
	}
	if string(b1) != string(b3) {
		t.Fatal("aggregation output depends on input ordering")
	}
}

func TestAggregateCorruptReport(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)

	good := (&reportBuilder{}).
		section("1", "cis-1.10", "Master", "master",
			check("1.1.1", "Good control", StatusPass))
	goodPath := writeReport(t, dir, "good.json", good, base)

	badPath := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badPath, []byte("{this is not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	refs := []ReportRef{
		{Source: "good-node", Path: goodPath},
		{Source: "bad-node", Path: badPath},
	}
	summary, err := Aggregate(refs, nil)
	if err != nil {
		t.Fatalf("partial failure must still return a summary, got: %v", err)
	}
	if len(summary.ParseErrors) != 1 {
		t.Fatalf("expected one parse error, got %+v", summary.ParseErrors)
	}
	if summary.ParseErrors[0].Source != "bad-node" || summary.ParseErrors[0].Path != badPath {
		t.Errorf("parse error does not name the offending report: %+v", summary.ParseErrors[0])
	}
	if summary.NodesParticipating != 1 {
		t.Errorf("good report should still be aggregated, got %d nodes", summary.NodesParticipating)
	}
}

func TestAggregateAllReportsUnavailable(t *testing.T) {
	dir := t.TempDir()
	bad1 := filepath.Join(dir, "bad1.json")
	bad2 := filepath.Join(dir, "bad2.json")
	if err := os.WriteFile(bad1, []byte("not json at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bad2, []byte(`{"Controls": []}`), 0o600); err != nil {
		t.Fatal(err)
	}

	summary, err := Aggregate([]ReportRef{
		{Source: "n1", Path: bad1},
		{Source: "n2", Path: bad2},
	}, nil)
	if err == nil {
		t.Fatal("expected an error when no report can be parsed")
	}
	if summary == nil || summary.ReportsParsed != 0 || len(summary.ParseErrors) != 2 {
		t.Fatalf("expected structured errors for both reports, got %+v", summary)
	}
}

func TestAggregateMissingFile(t *testing.T) {
	summary, err := Aggregate([]ReportRef{
		{Source: "ghost", Path: filepath.Join(t.TempDir(), "does-not-exist.json")},
	}, nil)
	if err == nil || summary == nil {
		t.Fatal("missing file must surface as a parse failure")
	}
	if summary.ReportsParsed != 0 || len(summary.ParseErrors) != 1 {
		t.Fatalf("expected one parse error, got %+v", summary)
	}
}

func TestAggregateRejectsEmptySource(t *testing.T) {
	dir := t.TempDir()
	path := writeReport(t, dir, "r.json",
		(&reportBuilder{}).section("1", "v", "t", "master", check("1.1.1", "t", StatusPass)),
		time.Now())

	if _, err := Aggregate([]ReportRef{{Source: "", Path: path}}, nil); err == nil {
		t.Fatal("report without a source identifier must be rejected")
	}
}

func TestAggregateNoRefs(t *testing.T) {
	if _, err := Aggregate(nil, nil); err == nil {
		t.Fatal("empty input must be an error, not an empty summary")
	}
}

func TestAggregatePreservesRawReport(t *testing.T) {
	dir := t.TempDir()
	path := writeReport(t, dir, "r.json",
		(&reportBuilder{}).section("1", "cis-1.10", "Master", "master",
			check("1.1.1", "t", StatusPass)),
		time.Now())
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	summary, err := Aggregate([]ReportRef{{Source: "node-a", Path: path}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(summary.Sources) != 1 {
		t.Fatalf("expected one source, got %d", len(summary.Sources))
	}
	if string(summary.Sources[0].RawReport) != string(original) {
		t.Fatal("raw report bytes were rewritten instead of preserved")
	}
}

func stringsHasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}
