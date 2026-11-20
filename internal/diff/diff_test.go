package diff

import (
	"encoding/json"
	"strings"
	"testing"
)

// Acceptance 5.1: the decision condition for one check ID is tightened between
// adjacent rule set versions while the machine output is unchanged. The result
// flip must be attributed to the rule, not the configuration.
func TestRuleChange_TightenedCondition(t *testing.T) {
	older := newFixture("k3s-cis-1.10").
		check("master", "1.1.20", "PASS", "hash-600", "bitmask '600'", "permissions=644\n", "PKI certificate permissions").
		json()
	newer := newFixture("k3s-cis-1.11").
		check("master", "1.1.20", "FAIL", "hash-644", "bitmask '644'", "permissions=644\n", "PKI certificate permissions").
		json()

	r, err := Compare(older, newer, Options{})
	if err != nil {
		t.Fatalf("Compare returned error: %v", err)
	}
	if !r.Comparable {
		t.Fatalf("expected comparable, got reason %q", r.IncomparableReason)
	}
	e, ok := findEntry(r, "1.1.20")
	if !ok {
		t.Fatalf("no entry for 1.1.20")
	}
	if e.Attribution != RuleChange {
		t.Fatalf("expected rule_change, got %s (%s)", e.Attribution, e.Reason)
	}
	if e.Movement != "" {
		t.Fatalf("rule change must not be counted as improvement/regression, got %q", e.Movement)
	}
	if e.Older.ExpectedResult != "bitmask '600'" || e.Newer.ExpectedResult != "bitmask '644'" {
		t.Fatalf("expected/actual evidence missing: %+v", e)
	}
	if e.Older.ActualValue != "permissions=644\n" || e.Newer.ActualValue != "permissions=644\n" {
		t.Fatalf("actual values should be carried through unchanged: %+v", e)
	}
	if r.Summary.Regressions != 0 || r.Summary.Improvements != 0 {
		t.Fatalf("rule flips must not move improvement/regression counters: %+v", r.Summary)
	}
}

// Same rule fingerprint on both sides but flipped status => configuration.
func TestConfigChange_IdenticalFingerprint(t *testing.T) {
	older := newFixture("cis-1.10").
		check("master", "1.2.3", "FAIL", "h1", "expected-x", "actual-a", "desc").
		json()
	newer := newFixture("cis-1.10").
		check("master", "1.2.3", "PASS", "h1", "expected-x", "actual-b", "desc").
		json()

	r, err := Compare(older, newer, Options{})
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	e, ok := findEntry(r, "1.2.3")
	if !ok {
		t.Fatalf("missing entry")
	}
	if e.Attribution != ConfigChange {
		t.Fatalf("expected config_change, got %s", e.Attribution)
	}
	if e.Movement != MovementImprovement {
		t.Fatalf("FAIL->PASS must be an improvement, got %q", e.Movement)
	}
	if r.Summary.Improvements != 1 || r.Summary.Regressions != 0 {
		t.Fatalf("summary wrong: %+v", r.Summary)
	}
}

// Regression direction: PASS -> FAIL under the same rule.
func TestConfigChange_RegressionDirection(t *testing.T) {
	older := newFixture("cis-1.10").check("node", "4.1.1", "PASS", "h", "e", "a", "d").json()
	newer := newFixture("cis-1.10").check("node", "4.1.1", "FAIL", "h", "e", "a2", "d").json()

	r, _ := Compare(older, newer, Options{})
	e, _ := findEntry(r, "4.1.1")
	if e.Attribution != ConfigChange || e.Movement != MovementRegression {
		t.Fatalf("expected config_change/regression, got %s/%s", e.Attribution, e.Movement)
	}
}

// Acceptance 5.2: checks existing on only one side are added/removed and never
// count as improvement or regression.
func TestAddedAndRemoved(t *testing.T) {
	older := newFixture("k3s-cis-1.10").
		check("master", "1.1.1", "PASS", "h1", "e", "a", "d").
		check("master", "1.1.2", "FAIL", "h2", "e", "a", "d").
		json()
	newer := newFixture("k3s-cis-1.11").
		check("master", "1.1.1", "PASS", "h1", "e", "a", "d").
		check("master", "1.1.3", "PASS", "h3", "e", "a", "d"). // new rule
		json()

	r, _ := Compare(older, newer, Options{})
	removed, ok := findEntry(r, "1.1.2")
	if !ok || removed.Attribution != Removed {
		t.Fatalf("expected removed entry, got %+v (ok=%v)", removed, ok)
	}
	if removed.Movement != "" {
		t.Fatalf("removed entry must not carry movement")
	}
	added, ok := findEntry(r, "1.1.3")
	if !ok || added.Attribution != Added {
		t.Fatalf("expected added entry, got %+v", added)
	}
	if added.Movement != "" {
		t.Fatalf("added entry must not carry movement")
	}
	if r.Summary.Improvements != 0 || r.Summary.Regressions != 0 {
		t.Fatalf("added/removed must not affect movement counters: %+v", r.Summary)
	}
	if r.Summary.ByAttribution[string(Added)] != 1 || r.Summary.ByAttribution[string(Removed)] != 1 {
		t.Fatalf("attribution counts wrong: %+v", r.Summary.ByAttribution)
	}
}

// Acceptance 5.3: different covered roles => the count difference is coverage,
// not configuration.
func TestCoverageChange_DifferentRoles(t *testing.T) {
	older := newFixture("k3s-cis-1.10").
		check("master", "1.1.1", "PASS", "h1", "e", "a", "d").
		check("etcd", "2.1", "WARN", "h2", "e", "a", "d"). // etcd only in older
		json()
	newer := newFixture("k3s-cis-1.10").
		check("master", "1.1.1", "PASS", "h1", "e", "a", "d").
		json()

	r, _ := Compare(older, newer, Options{})
	e, ok := findEntry(r, "2.1")
	if !ok {
		t.Fatalf("missing etcd entry")
	}
	if e.Attribution != CoverageChange {
		t.Fatalf("expected coverage_change, got %s", e.Attribution)
	}
	if r.Summary.OlderCheckCount != 2 || r.Summary.NewerCheckCount != 1 {
		t.Fatalf("check counts wrong: %+v", r.Summary)
	}
	if r.Summary.Regressions != 0 && r.Summary.Improvements != 0 {
		t.Fatalf("coverage must not move counters")
	}
}

// A check appearing under a role that only exists on the newer side is also
// coverage, not "added".
func TestCoverageChange_NewRoleOnly(t *testing.T) {
	older := newFixture("k3s-cis-1.10").check("master", "1.1.1", "PASS", "h", "e", "a", "d").json()
	newer := newFixture("k3s-cis-1.10").
		check("master", "1.1.1", "PASS", "h", "e", "a", "d").
		check("policies", "5.1.1", "FAIL", "h2", "e", "a", "d").
		json()

	r, _ := Compare(older, newer, Options{})
	e, _ := findEntry(r, "5.1.1")
	if e.Attribution != CoverageChange {
		t.Fatalf("expected coverage_change for new role, got %s", e.Attribution)
	}
}

// Acceptance 5.4 / degradation 3.2: a side missing rule set version info is
// unattributable and nothing is assumed identical.
func TestMissingRuleSetVersion(t *testing.T) {
	older := newFixture("k3s-cis-1.10").check("master", "1.1.1", "PASS", "h", "e", "a", "d").json()
	newer := newFixture("k3s-cis-1.11").withoutVersion().
		check("master", "1.1.1", "FAIL", "h2", "e", "a", "d").json()

	r, err := Compare(older, newer, Options{})
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if r.Comparable {
		t.Fatalf("report must be marked not comparable when version info is missing")
	}
	if !strings.Contains(r.IncomparableReason, "missing rule set version") {
		t.Fatalf("unexpected reason: %q", r.IncomparableReason)
	}
	e, _ := findEntry(r, "1.1.1")
	if e.Attribution != Unattributable {
		t.Fatalf("expected unattributable, got %s", e.Attribution)
	}
	if r.Summary.Improvements != 0 || r.Summary.Regressions != 0 {
		t.Fatalf("unattributable must not move counters: %+v", r.Summary)
	}
}

// Degradation 3.1: different product lines are incomparable.
func TestDifferentProductLines(t *testing.T) {
	older := newFixture("eks-1.8.0").check("master", "1.1.1", "PASS", "h", "e", "a", "d").json()
	newer := newFixture("k3s-cis-1.11").check("master", "1.1.1", "PASS", "h", "e", "a", "d").json()

	r, err := Compare(older, newer, Options{})
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if r.Comparable {
		t.Fatalf("different product lines must be incomparable")
	}
	if !strings.Contains(r.IncomparableReason, "product lines") {
		t.Fatalf("unexpected reason: %q", r.IncomparableReason)
	}
	if len(r.Entries) != 0 {
		t.Fatalf("incomparable product-line reports must not produce entries")
	}
}

// Requirement 4: same ID, same decision condition but different content => the
// ID appears repurposed; incomparable, never counted as movement.
func TestSameIDDifferentContent(t *testing.T) {
	older := newFixture("cis-1.10").check("master", "3.2.1", "PASS", "same-hash", "e", "a", "old description").json()
	newer := newFixture("cis-1.11").check("master", "3.2.1", "FAIL", "same-hash", "e", "a", "completely different check").json()

	r, _ := Compare(older, newer, Options{})
	e, _ := findEntry(r, "3.2.1")
	if e.Attribution != Incomparable {
		t.Fatalf("expected incomparable for repurposed ID, got %s", e.Attribution)
	}
	if e.Movement != "" {
		t.Fatalf("incomparable must not carry movement")
	}
}

// A revised rule often changes both its wording and its decision condition;
// the condition change is the dominant signal and the flip is a rule change,
// not an incomparable ID reuse.
func TestRuleChangeWithWordingChange(t *testing.T) {
	older := newFixture("cis-1.10").check("master", "1.1.20", "PASS", "hash-600", "e", "a", "permissions set to 600 (Manual)").json()
	newer := newFixture("cis-1.11").check("master", "1.1.20", "FAIL", "hash-644", "e", "a", "permissions set to 644 (Automated)").json()

	r, _ := Compare(older, newer, Options{})
	e, _ := findEntry(r, "1.1.20")
	if e.Attribution != RuleChange {
		t.Fatalf("expected rule_change for revised rule, got %s", e.Attribution)
	}
	if e.Movement != "" {
		t.Fatalf("rule change must not carry movement")
	}
}

// Legacy reports without fingerprints: overlapping checks are unattributable
// rather than guessed.
func TestLegacyReportWithoutFingerprint(t *testing.T) {
	older := newFixture("cis-1.10").legacyCheck("master", "1.1.1", "FAIL", "e", "a", "d").json()
	newer := newFixture("cis-1.10").legacyCheck("master", "1.1.1", "PASS", "e", "a", "d").json()

	r, _ := Compare(older, newer, Options{})
	e, _ := findEntry(r, "1.1.1")
	if e.Attribution != Unattributable {
		t.Fatalf("expected unattributable for missing fingerprint, got %s", e.Attribution)
	}
}

// Degradation 3.3: unrecognised structures are refused, not guessed.
func TestUnrecognisedStructureRejected(t *testing.T) {
	cases := [][]byte{
		[]byte(`{"foo":"bar"}`),
		[]byte(`{"Controls":[]}`),
		[]byte(`{"Controls":[{"id":"1"}]}`),
		[]byte(`not json at all`),
	}
	for i, raw := range cases {
		if _, err := Compare(raw, newFixture("cis-1.10").check("master", "1.1.1", "PASS", "h", "e", "a", "d").json(), Options{}); err == nil {
			t.Fatalf("case %d: expected error for unrecognised input", i)
		}
	}
}

// Hard constraint 4: entry cap truncates and marks the output.
func TestEntryCapTruncation(t *testing.T) {
	o := newFixture("cis-1.10")
	n := newFixture("cis-1.10")
	for i := 0; i < 10; i++ {
		id := "1.1." + string(rune('1'+i))
		o.check("master", id, "FAIL", "h-old", "e", "a", "d")
		n.check("master", id, "PASS", "h-new", "e", "a", "d")
	}
	r, err := Compare(o.json(), n.json(), Options{MaxEntries: 4})
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if !r.Summary.Truncated || r.Summary.TruncationLimit != 4 {
		t.Fatalf("expected truncation marker, got %+v", r.Summary)
	}
	if len(r.Entries) != 4 {
		t.Fatalf("expected 4 entries after truncation, got %d", len(r.Entries))
	}
	if r.Summary.EntriesBeforeCut != 10 {
		t.Fatalf("EntriesBeforeCut should retain the full count, got %d", r.Summary.EntriesBeforeCut)
	}
}

// Requirement 9: identical inputs produce byte-stable, identical output, and
// input order does not change the result.
func TestDeterministicStableOutput(t *testing.T) {
	older := newFixture("k3s-cis-1.10").
		check("etcd", "2.2", "WARN", "he", "e", "a", "d").
		check("master", "1.1.2", "FAIL", "h2", "e", "a", "d").
		check("master", "1.1.1", "PASS", "h1", "e", "a", "d").
		json()
	newer := newFixture("k3s-cis-1.11").
		check("master", "1.1.1", "PASS", "h1", "e", "a", "d").
		check("master", "1.1.2", "FAIL", "h2c", "e", "a", "d").
		json()

	first, err := Compare(older, newer, Options{})
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	second, err := Compare(older, newer, Options{})
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	b1, _ := json.Marshal(first)
	b2, _ := json.Marshal(second)
	if string(b1) != string(b2) {
		t.Fatalf("repeated comparison is not stable")
	}
	// entries must be ordered by node type then check ID
	ids := []string{}
	for _, e := range first.Entries {
		ids = append(ids, e.Older.NodeType+"/"+e.CheckID)
	}
	wantIDs := []string{"etcd/2.2", "master/1.1.2"}
	if len(ids) != len(wantIDs) {
		t.Fatalf("expected %d entries, got %v", len(wantIDs), ids)
	}
	for i := range wantIDs {
		if ids[i] != wantIDs[i] {
			t.Fatalf("entries not deterministically ordered: got %v want %v", ids, wantIDs)
		}
	}
}

// Requirement 8: every emitted entry carries both sides' expected and actual
// evidence when the side is present.
func TestEntriesCarryExpectedAndActual(t *testing.T) {
	older := newFixture("cis-1.10").check("master", "1.1.1", "FAIL", "h", "expected-old", "actual-old", "d").json()
	newer := newFixture("cis-1.10").check("master", "1.1.1", "PASS", "h", "expected-old", "actual-new", "d").json()

	r, _ := Compare(older, newer, Options{})
	e, _ := findEntry(r, "1.1.1")
	if e.Older.ExpectedResult == "" || e.Older.ActualValue == "" ||
		e.Newer.ExpectedResult == "" || e.Newer.ActualValue == "" {
		t.Fatalf("entry missing expected/actual evidence: %+v", e)
	}
}

// Hard constraint 5: no PEM blocks or secret values survive in the output.
func TestSensitiveMaterialRedacted(t *testing.T) {
	secretActual := "cert: -----BEGIN PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----\nclient-key-file=/etc/kubernetes/pki/apiserver.key token=abcdef0123456789"
	older := newFixture("cis-1.10").check("master", "1.1.1", "FAIL", "h", "e", secretActual, "d").json()
	newer := newFixture("cis-1.10").check("master", "1.1.1", "PASS", "h", "e", "clean", "d").json()

	r, _ := Compare(older, newer, Options{})
	blob, _ := json.Marshal(r)
	s := string(blob)
	if strings.Contains(s, "BEGIN PRIVATE KEY") || strings.Contains(s, "abcdef0123456789") {
		t.Fatalf("sensitive material leaked into comparison output: %s", s)
	}
	if !strings.Contains(s, "REDACTED") {
		t.Fatalf("expected redaction markers in output")
	}
}

// Rule set metadata (selection mode, fallback trail) is surfaced at the side
// level so the report records which rule set each scan used.
func TestRuleSetMetadataSurfaced(t *testing.T) {
	older := newFixture("k3s-cis-1.10").withFallback("1.27", "k3s-cis-1.10").
		check("master", "1.1.1", "PASS", "h", "e", "a", "d").json()
	newer := newFixture("k3s-cis-1.11").
		check("master", "1.1.1", "PASS", "h", "e", "a", "d").json()

	r, _ := Compare(older, newer, Options{})
	if r.Older.RuleSet == nil || !r.Older.RuleSet.FallbackUsed {
		t.Fatalf("fallback trail missing from older side: %+v", r.Older)
	}
	if r.Older.RuleSet.FallbackFromVersion != "1.27" || r.Older.RuleSet.FallbackToVersion != "k3s-cis-1.10" {
		t.Fatalf("fallback trail wrong: %+v", r.Older.RuleSet)
	}
}

// Unchanged checks are omitted from the entry list but totals still reconcile.
func TestUnchangedChecksOmitted(t *testing.T) {
	older := newFixture("cis-1.10").
		check("master", "1.1.1", "PASS", "h1", "e", "a", "d").
		check("master", "1.1.2", "FAIL", "h2", "e", "a", "d").
		json()
	newer := newFixture("cis-1.10").
		check("master", "1.1.1", "PASS", "h1", "e", "a", "d").  // unchanged
		check("master", "1.1.2", "PASS", "h2", "e", "a2", "d"). // config change
		json()

	r, _ := Compare(older, newer, Options{})
	if _, ok := findEntry(r, "1.1.1"); ok {
		t.Fatalf("unchanged check must not produce an entry")
	}
	if len(r.Entries) != 1 {
		t.Fatalf("expected exactly one entry (the changed check), got %d", len(r.Entries))
	}
	if r.Summary.OlderCheckCount != 2 || r.Summary.NewerCheckCount != 2 {
		t.Fatalf("check counts wrong: %+v", r.Summary)
	}
}

// The no-totals array form of the report is accepted as well.
func TestNoTotalsArrayForm(t *testing.T) {
	b := newFixture("cis-1.10").check("master", "1.1.1", "PASS", "h", "e", "a", "d").json()
	var overall rawOverall
	if err := json.Unmarshal(b, &overall); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	raw, _ := json.Marshal(overall.Controls)
	r, err := Compare(raw, b, Options{})
	if err != nil {
		t.Fatalf("array form should parse: %v", err)
	}
	if r.Older.CheckCount != 1 {
		t.Fatalf("expected 1 check parsed, got %d", r.Older.CheckCount)
	}
}

// Sanitizer unit checks including truncation.
func TestSanitizeActualValue(t *testing.T) {
	if got := sanitizeActualValue(""); got != "" {
		t.Fatalf("empty should stay empty")
	}
	long := strings.Repeat("x", maxActualValueLen+50)
	got := sanitizeActualValue(long)
	if !strings.HasSuffix(got, "...[truncated]") {
		t.Fatalf("expected truncation marker, got len %d", len(got))
	}
	redacted := sanitizeActualValue("password=hunter2 and TOKEN: abc123 rest")
	if strings.Contains(redacted, "hunter2") || strings.Contains(redacted, "abc123") {
		t.Fatalf("secrets not redacted: %q", redacted)
	}
}

func TestProductLineOf(t *testing.T) {
	cases := map[string]string{
		"k3s-cis-1.10":      "k3s",
		"cis-1.10":          "cis",
		"eks-1.8.0":         "eks",
		"cis-1.24-microk8s": "cis",
		"gke-1.8.0":         "gke",
	}
	for in, want := range cases {
		if got := productLineOf(in); got != want {
			t.Errorf("productLineOf(%q) = %q, want %q", in, got, want)
		}
	}
}
