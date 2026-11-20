package diff

import (
	"fmt"
	"strings"
)

// RenderText renders a comparison Report as a deterministic, human-readable
// text summary suitable for terminal review. The JSON form remains the
// machine-consumable output.
func RenderText(r *Report) string {
	var b strings.Builder

	b.WriteString("kube-bench report comparison\n")
	b.WriteString("============================\n\n")

	writeSideMeta(&b, "Older (pre-upgrade)", r.Older)
	writeSideMeta(&b, "Newer (post-upgrade)", r.Newer)
	b.WriteString("\n")

	if !r.Comparable {
		b.WriteString(fmt.Sprintf("RESULT: NOT COMPARABLE - %s\n\n", r.IncomparableReason))
	} else {
		b.WriteString("RESULT: comparable\n\n")
	}

	s := r.Summary
	b.WriteString("Summary\n")
	b.WriteString("-------\n")
	b.WriteString(fmt.Sprintf("Checks on each side: older=%d newer=%d\n", s.OlderCheckCount, s.NewerCheckCount))
	order := []Attribution{ConfigChange, RuleChange, Added, Removed, CoverageChange, Incomparable, Unattributable}
	for _, a := range order {
		if n := s.ByAttribution[string(a)]; n > 0 {
			b.WriteString(fmt.Sprintf("  %-17s %d\n", string(a)+":", n))
		}
	}
	b.WriteString(fmt.Sprintf("Improvements (config only): %d\n", s.Improvements))
	b.WriteString(fmt.Sprintf("Regressions  (config only): %d\n", s.Regressions))
	if s.Truncated {
		b.WriteString(fmt.Sprintf("NOTE: output truncated at %d entries (%d differences exist); re-run with a higher --max-entries to see all\n",
			s.TruncationLimit, s.EntriesBeforeCut))
	}
	b.WriteString("\n")

	if len(r.Entries) == 0 {
		b.WriteString("No differences.\n")
		return b.String()
	}

	b.WriteString("Differences\n")
	b.WriteString("-----------\n")
	for _, e := range r.Entries {
		writeEntry(&b, e)
	}
	return b.String()
}

func writeSideMeta(b *strings.Builder, label string, m SideMeta) {
	b.WriteString(fmt.Sprintf("%s:\n", label))
	b.WriteString(fmt.Sprintf("  rule set versions: %s\n", strings.Join(m.RuleSetVersions, ", ")))
	b.WriteString(fmt.Sprintf("  product line:      %s\n", m.ProductLine))
	b.WriteString(fmt.Sprintf("  node types:        %s\n", strings.Join(m.NodeTypes, ", ")))
	if m.MissingVersion {
		b.WriteString("  WARNING: rule set version information missing\n")
	}
	if m.RuleSet != nil {
		rs := m.RuleSet
		if rs.SelectionMode != "" {
			b.WriteString(fmt.Sprintf("  selection:         mode=%s requested=%q detected=%q\n",
				rs.SelectionMode, rs.RequestedVersion, rs.DetectedVersion))
		}
		if rs.FallbackUsed {
			b.WriteString(fmt.Sprintf("  version fallback:  %s -> %s\n",
				rs.FallbackFromVersion, rs.FallbackToVersion))
		}
	}
}

func writeEntry(b *strings.Builder, e Entry) {
	header := fmt.Sprintf("[%s] %s", e.Attribution, e.CheckID)
	if e.Movement != "" {
		header += " (" + e.Movement + ")"
	}
	b.WriteString(header + "\n")
	b.WriteString("  reason: " + e.Reason + "\n")
	writeSideView(b, "older", e.Older)
	writeSideView(b, "newer", e.Newer)
	b.WriteString("\n")
}

func writeSideView(b *strings.Builder, label string, v SideView) {
	if !v.Present {
		b.WriteString(fmt.Sprintf("  %s: <not present>\n", label))
		return
	}
	b.WriteString(fmt.Sprintf("  %s:\n", label))
	if v.RuleSetVersion != "" {
		b.WriteString(fmt.Sprintf("    rule set:   %s\n", v.RuleSetVersion))
	}
	b.WriteString(fmt.Sprintf("    status:     %s\n", v.Status))
	if v.ExpectedResult != "" {
		b.WriteString(fmt.Sprintf("    expected:   %s\n", v.ExpectedResult))
	}
	if v.ActualValue != "" {
		b.WriteString(fmt.Sprintf("    actual:     %s\n", strings.ReplaceAll(v.ActualValue, "\n", " | ")))
	}
}
