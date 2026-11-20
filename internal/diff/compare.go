package diff

import (
	"fmt"
	"sort"
)

// Options controls comparison behaviour.
type Options struct {
	// MaxEntries caps the number of emitted entries. Zero means
	// DefaultMaxEntries. When the cap is hit the remaining entries are cut
	// and the summary is marked truncated.
	MaxEntries int
}

// Compare reads two kube-bench JSON reports (older = pre-upgrade, newer =
// post-upgrade) and produces a deterministic, machine-consumable attribution
// of every difference. The same pair of inputs always yields the same result.
func Compare(olderRaw, newerRaw []byte, opts Options) (*Report, error) {
	if opts.MaxEntries <= 0 {
		opts.MaxEntries = DefaultMaxEntries
	}

	older, err := parseReport(olderRaw)
	if err != nil {
		return nil, err
	}
	newer, err := parseReport(newerRaw)
	if err != nil {
		return nil, err
	}

	report := &Report{
		SchemaVersion: SchemaVersion,
		Comparable:    true,
		Older:         older.meta,
		Newer:         newer.meta,
	}
	report.Summary.ByAttribution = map[string]int{}

	// Hard failure/degradation: different benchmark product lines can never
	// be compared; rule identities are not shared across products.
	if older.meta.ProductLine != "" && newer.meta.ProductLine != "" &&
		older.meta.ProductLine != newer.meta.ProductLine {
		report.Comparable = false
		report.IncomparableReason = fmt.Sprintf(
			"reports come from different benchmark product lines: %q vs %q",
			older.meta.ProductLine, newer.meta.ProductLine)
		return report, nil
	}

	// Degradation: either side lacks rule set version information. Nothing
	// may be assumed identical, so every overlapping check is unattributable
	// and no improvement/regression counts are produced.
	if older.meta.MissingVersion || newer.meta.MissingVersion {
		report.Comparable = false
		report.IncomparableReason = "one or both reports are missing rule set version information; defaulting to unattributable"
		entries := buildMissingVersionEntries(older, newer)
		finalize(report, entries, opts)
		return report, nil
	}

	entries := buildEntries(older, newer)
	finalize(report, entries, opts)
	return report, nil
}

// buildEntries performs the full attribution when both reports carry rule set
// versions from the same product line.
func buildEntries(older, newer *parsedReport) []Entry {
	var entries []Entry

	olderNodes := nodeTypeSet(older)
	newerNodes := nodeTypeSet(newer)

	// Deterministic union of keys.
	allKeys := unionKeys(older, newer)
	for _, k := range allKeys {
		o, inOlder := older.checks[k]
		n, inNewer := newer.checks[k]

		switch {
		case inOlder && !inNewer:
			// A check can be absent on the newer side either because the rule
			// was deleted (same role still scanned) or because the role itself
			// was not covered this time.
			if !newerNodes[k.nodeType] {
				entries = append(entries, coverageEntry(k, o, nil, Older,
					fmt.Sprintf("node type %q was not covered by the newer scan", k.nodeType)))
			} else {
				entries = append(entries, oneSidedEntry(k, o, nil, Older, Removed,
					"check present in the older rule set but absent from the newer rule set; not counted as fixed"))
			}
		case !inOlder && inNewer:
			if !olderNodes[k.nodeType] {
				entries = append(entries, coverageEntry(k, nil, n, Newer,
					fmt.Sprintf("node type %q was not covered by the older scan", k.nodeType)))
			} else {
				entries = append(entries, oneSidedEntry(k, nil, n, Newer, Added,
					"check present only in the newer rule set; not counted as a new failure"))
			}
		default:
			if e, changed := pairedEntry(k, o, n); changed {
				entries = append(entries, e)
			}
		}
	}
	return entries
}

// pairedEntry attributes a check present in both reports. The second return
// value is false when the two sides are effectively identical, in which case
// no diff entry is emitted.
func pairedEntry(k key, o, n *rawCheck) (Entry, bool) {
	entry := Entry{
		CheckID: k.checkID,
		Older:   sideViewOf(o, k.nodeType),
		Newer:   sideViewOf(n, k.nodeType),
	}

	// Without fingerprints (e.g. reports produced before fingerprints
	// existed) the decision condition cannot be reconstructed from the
	// report, so attribution must not be guessed.
	if o.Fingerprint == nil || n.Fingerprint == nil {
		entry.Attribution = Unattributable
		entry.Reason = "rule fingerprint missing on one or both sides; decision condition cannot be compared"
		return entry, true
	}

	entry.Older.ConditionHash = o.Fingerprint.ConditionHash
	entry.Older.Condition = o.Fingerprint.Condition
	entry.Newer.ConditionHash = n.Fingerprint.ConditionHash
	entry.Newer.Condition = n.Fingerprint.Condition

	// Same identifier reused for genuinely different content: the decision
	// condition is byte-identical yet the check description changed, which is
	// the signature of an ID being repurposed rather than a rule revision.
	// Such entries cannot be put on the same scale.
	if o.TestDesc != "" && n.TestDesc != "" && o.TestDesc != n.TestDesc &&
		o.Fingerprint.ConditionHash == n.Fingerprint.ConditionHash {
		entry.Attribution = Incomparable
		entry.Reason = "check identifier maps to different check content despite an identical decision condition; ID appears repurposed"
		return entry, true
	}

	// The decision condition is byte-identical across the two reports: the
	// rule evaluated the same way, so only machine output can drive a result
	// change. A different rule set version label alone does not change a
	// judgment, so it is noted as context but does not turn a flip into a
	// rule change. Identical status means nothing effectively changed.
	if o.Fingerprint.ConditionHash == n.Fingerprint.ConditionHash {
		if o.Status == n.Status {
			return entry, false
		}
		entry.Attribution = ConfigChange
		if o.Fingerprint.RuleSetVersion == n.Fingerprint.RuleSetVersion {
			entry.Reason = "identical rule fingerprint on both sides; result changed under the same rule"
		} else {
			entry.Reason = fmt.Sprintf(
				"identical decision condition across rule set versions (%s -> %s); result changed under the same decision rule",
				o.Fingerprint.RuleSetVersion, n.Fingerprint.RuleSetVersion)
		}
		entry.Movement = movement(o.Status, n.Status)
		return entry, true
	}

	// Same ID, different decision condition. This is the case of a revised
	// rule (e.g. a permission requirement tightened from 644 to 600); a result
	// flip here is the rule's doing, not the configuration's. A simultaneous
	// wording change is expected for a revision and does not make the entry
	// incomparable.
	entry.Attribution = RuleChange
	switch {
	case o.Fingerprint.RuleSetVersion != n.Fingerprint.RuleSetVersion:
		entry.Reason = fmt.Sprintf(
			"decision condition changed between rule set versions (%s -> %s); any result flip is caused by the rule",
			o.Fingerprint.RuleSetVersion, n.Fingerprint.RuleSetVersion)
	default:
		entry.Reason = "decision condition changed within the same rule set version; any result flip is caused by the rule"
	}
	return entry, true
}

// oneSidedEntry builds an added/removed entry.
func oneSidedEntry(k key, o, n *rawCheck, presentOn Side, attr Attribution, reason string) Entry {
	e := Entry{CheckID: k.checkID, Attribution: attr, Reason: reason}
	if presentOn == Older {
		e.Older = sideViewOf(o, k.nodeType)
		e.Newer = SideView{Present: false, NodeType: k.nodeType}
	} else {
		e.Older = SideView{Present: false, NodeType: k.nodeType}
		e.Newer = sideViewOf(n, k.nodeType)
	}
	return e
}

// coverageEntry builds a coverage_change entry (role present on only one side).
func coverageEntry(k key, o, n *rawCheck, presentOn Side, reason string) Entry {
	e := oneSidedEntry(k, o, n, presentOn, CoverageChange, reason)
	return e
}

// buildMissingVersionEntries is used when at least one side lacks rule set
// version information. Overlapping checks are unattributable; one-sided checks
// are still classified as added/removed/coverage where the structural evidence
// supports it, and none of it counts toward improvement or regression.
func buildMissingVersionEntries(older, newer *parsedReport) []Entry {
	var entries []Entry
	olderNodes := nodeTypeSet(older)
	newerNodes := nodeTypeSet(newer)
	for _, k := range unionKeys(older, newer) {
		o, inOlder := older.checks[k]
		n, inNewer := newer.checks[k]
		switch {
		case inOlder && !inNewer:
			if !newerNodes[k.nodeType] {
				entries = append(entries, coverageEntry(k, o, nil, Older,
					fmt.Sprintf("node type %q was not covered by the newer scan", k.nodeType)))
			} else {
				entries = append(entries, oneSidedEntry(k, o, nil, Older, Removed,
					"check present only in the older report; rule set version unknown"))
			}
		case !inOlder && inNewer:
			if !olderNodes[k.nodeType] {
				entries = append(entries, coverageEntry(k, nil, n, Newer,
					fmt.Sprintf("node type %q was not covered by the older scan", k.nodeType)))
			} else {
				entries = append(entries, oneSidedEntry(k, nil, n, Newer, Added,
					"check present only in the newer report; rule set version unknown"))
			}
		default:
			e := Entry{
				CheckID:     k.checkID,
				Attribution: Unattributable,
				Reason:      "rule set version information missing on one or both sides; cannot attribute result differences",
				Older:       sideViewOf(o, k.nodeType),
				Newer:       sideViewOf(n, k.nodeType),
			}
			entries = append(entries, e)
		}
	}
	return entries
}

// sideViewOf projects a raw check onto the evidence view emitted in a report.
func sideViewOf(c *rawCheck, nodeType string) SideView {
	if c == nil {
		return SideView{Present: false, NodeType: nodeType}
	}
	v := SideView{
		Present:         true,
		NodeType:        nodeType,
		Status:          c.Status,
		ExpectedResult:  c.ExpectedResult,
		ActualValue:     sanitizeActualValue(c.ActualValue),
		TestDescription: c.TestDesc,
	}
	if c.Fingerprint != nil {
		v.RuleSetVersion = c.Fingerprint.RuleSetVersion
		v.ConditionHash = c.Fingerprint.ConditionHash
		v.Condition = c.Fingerprint.Condition
	}
	return v
}

// movement classifies a status change between two comparable results.
func movement(olderStatus, newerStatus string) string {
	if rankStatus(newerStatus) < rankStatus(olderStatus) {
		return MovementImprovement
	}
	return MovementRegression
}

// finalize sorts, truncates and aggregates entries into the summary.
func finalize(report *Report, entries []Entry, opts Options) {
	sortEntries(entries)
	report.Summary.EntriesBeforeCut = len(entries)
	report.Summary.OlderCheckCount = report.Older.CheckCount
	report.Summary.NewerCheckCount = report.Newer.CheckCount

	if len(entries) > opts.MaxEntries {
		entries = entries[:opts.MaxEntries]
		report.Summary.Truncated = true
		report.Summary.TruncationLimit = opts.MaxEntries
	}

	for _, e := range entries {
		report.Summary.ByAttribution[string(e.Attribution)]++
		switch e.Movement {
		case MovementImprovement:
			report.Summary.Improvements++
		case MovementRegression:
			report.Summary.Regressions++
		}
	}
	report.Summary.TotalEntries = len(entries)
	report.Entries = entries
}

// nodeTypeSet returns the node types covered by one parsed report.
func nodeTypeSet(p *parsedReport) map[string]bool {
	out := map[string]bool{}
	for _, c := range p.controls {
		out[c.NodeType] = true
	}
	return out
}

func unionKeys(a, b *parsedReport) []key {
	seen := map[key]bool{}
	var out []key
	for k := range a.checks {
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	for k := range b.checks {
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].nodeType != out[j].nodeType {
			return out[i].nodeType < out[j].nodeType
		}
		return out[i].checkID < out[j].checkID
	})
	return out
}
