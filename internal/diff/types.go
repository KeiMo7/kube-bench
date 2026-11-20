// Package diff compares two kube-bench JSON scan reports and attributes every
// difference between them using only the rule fingerprints recorded in the
// reports themselves.
//
// Attribution categories:
//   - config_change:    the same rule produced a different result; the machine
//     configuration must have changed.
//   - rule_change:      the same check ID was evaluated under a different
//     decision condition (or rule set version), so a result flip cannot be
//     attributed to configuration.
//   - added:            the check exists only in the newer report (new rule).
//   - removed:          the check exists only in the older report (deleted
//     rule). Neither added nor removed entries count as improvement or
//     regression.
//   - coverage_change:  the two scans covered different roles/node types, so
//     the entry only appears because of the coverage difference.
//   - incomparable:     the same ID points at different content, or the
//     reports are from different product lines / unrecognised structures.
//   - unattributable:   one side lacks the rule set version or fingerprint
//     information required to decide.
package diff

// Attribution is the category assigned to a comparison entry.
type Attribution string

const (
	// ConfigChange means identical rule identity (check ID, decision
	// condition, rule set version) but different result status.
	ConfigChange Attribution = "config_change"
	// RuleChange means the same check ID was evaluated under a different
	// decision condition or rule set version; any result flip is caused by
	// the rule, not the machine configuration.
	RuleChange Attribution = "rule_change"
	// Added means the check exists only in the newer report.
	Added Attribution = "added"
	// Removed means the check exists only in the older report.
	Removed Attribution = "removed"
	// CoverageChange means the entry appears/disappears because the two scans
	// covered different roles (node types), e.g. one included etcd.
	CoverageChange Attribution = "coverage_change"
	// Incomparable means the two sides cannot be put on the same scale
	// (different content behind one ID, different product lines, ...).
	Incomparable Attribution = "incomparable"
	// Unattributable means information required for attribution (rule set
	// version or rule fingerprint) is missing on one side.
	Unattributable Attribution = "unattributable"
)

// Side identifies one of the two compared reports.
type Side string

const (
	// Older is the pre-upgrade ("before") report.
	Older Side = "older"
	// Newer is the post-upgrade ("after") report.
	Newer Side = "newer"
)

// Severity movement of a comparable check whose status changed.
const (
	MovementImprovement = "improvement"
	MovementRegression  = "regression"
)

// SideView carries the evidence recorded for one side of a comparison entry.
// Only report fields needed for human review are included; audit commands,
// remediation text and raw file contents are deliberately omitted.
type SideView struct {
	Present         bool   `json:"present"`
	RuleSetVersion  string `json:"rule_set_version,omitempty"`
	NodeType        string `json:"node_type,omitempty"`
	Status          string `json:"status,omitempty"`
	ExpectedResult  string `json:"expected_result,omitempty"`
	ActualValue     string `json:"actual_value,omitempty"`
	ConditionHash   string `json:"condition_hash,omitempty"`
	Condition       string `json:"condition,omitempty"`
	TestDescription string `json:"test_desc,omitempty"`
}

// Entry is one attributed difference between the two reports. Entries are
// sorted deterministically (see Compare) so the same pair of inputs always
// produces byte-stable output.
type Entry struct {
	// CheckID is the check identifier, e.g. "1.1.20".
	CheckID string `json:"check_id"`
	// Attribution is the category this difference was assigned to.
	Attribution Attribution `json:"attribution"`
	// Reason explains the attribution in report-derived terms only.
	Reason string `json:"reason"`
	// Movement is "improvement" or "regression" for comparable config changes,
	// otherwise empty. Added/removed/incomparable/coverage/unattributable
	// entries never count as improvement or regression.
	Movement string `json:"movement,omitempty"`
	// Older and Newer hold the two sides' expected/actual evidence.
	Older SideView `json:"older"`
	Newer SideView `json:"newer"`
}

// Summary holds the aggregate counts. Incomparable, added, removed, coverage
// and unattributable entries are excluded from Improvements/Regressions.
type Summary struct {
	TotalEntries     int            `json:"total_entries"`
	ByAttribution    map[string]int `json:"by_attribution"`
	Improvements     int            `json:"improvements"`
	Regressions      int            `json:"regressions"`
	OlderCheckCount  int            `json:"older_check_count"`
	NewerCheckCount  int            `json:"newer_check_count"`
	Truncated        bool           `json:"truncated"`
	TruncationLimit  int            `json:"truncation_limit,omitempty"`
	EntriesBeforeCut int            `json:"entries_before_cut,omitempty"`
}

// Report is the machine-consumable comparison result.
type Report struct {
	// SchemaVersion identifies the comparison output structure.
	SchemaVersion string `json:"schema_version"`
	Comparable    bool   `json:"comparable"`
	// IncomparableReason is set when Comparable is false.
	IncomparableReason string   `json:"incomparable_reason,omitempty"`
	Older              SideMeta `json:"older"`
	Newer              SideMeta `json:"newer"`
	Summary            Summary  `json:"summary"`
	Entries            []Entry  `json:"entries"`
}

// SideMeta describes one input report at the report level.
type SideMeta struct {
	RuleSetVersion  string       `json:"rule_set_version,omitempty"`
	RuleSetVersions []string     `json:"rule_set_versions,omitempty"`
	ProductLine     string       `json:"product_line,omitempty"`
	NodeTypes       []string     `json:"node_types,omitempty"`
	MissingVersion  bool         `json:"missing_rule_set_version,omitempty"`
	CheckCount      int          `json:"check_count"`
	RuleSet         *RuleSetMeta `json:"rule_set,omitempty"`
}

// RuleSetMeta mirrors the additive rule set metadata embedded in a scan
// report, including any version-mapping fallback trail.
type RuleSetMeta struct {
	Version             string `json:"version,omitempty"`
	ProductLine         string `json:"product_line,omitempty"`
	SelectionMode       string `json:"selection_mode,omitempty"`
	RequestedVersion    string `json:"requested_version,omitempty"`
	DetectedVersion     string `json:"detected_version,omitempty"`
	FallbackUsed        bool   `json:"fallback_used,omitempty"`
	FallbackFromVersion string `json:"fallback_from_version,omitempty"`
	FallbackToVersion   string `json:"fallback_to_version,omitempty"`
}

// Comparison output schema identifier.
const SchemaVersion = "kube-bench-diff-v1"

// DefaultMaxEntries bounds the number of diff entries so a pathological
// comparison cannot produce unbounded output.
const DefaultMaxEntries = 1000
