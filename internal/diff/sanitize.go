package diff

import (
	"regexp"
	"sort"
	"strings"
)

// maxActualValueLen bounds any single actual value carried into a comparison
// report. Actual values come from audit command output and can be long; the
// comparison output must stay compact and must never embed bulk file
// contents or key material.
const maxActualValueLen = 512

var (
	// pemBlock matches PEM-encoded material (certificates, private keys, ...).
	pemBlock = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]+-----[\s\S]*?-----END [A-Z0-9 ]+-----`)
	// secretAssignment matches assignments whose left-hand side names secret
	// material. The value (everything up to the next whitespace or line end)
	// is redacted; the key name is retained so reviewers know what was there.
	secretAssignment = regexp.MustCompile(`(?i)([a-z0-9_.-]*(?:password|passwd|secret|token|private[-_]?key|client[-_]?key|key[-_]?file)[a-z0-9_.-]*)\s*[:=]\s*[^\s]+`)
)

// sanitizeActualValue removes secret material and truncates audit output so
// the comparison report never contains file contents or key material.
func sanitizeActualValue(s string) string {
	if s == "" {
		return ""
	}
	out := pemBlock.ReplaceAllString(s, "[REDACTED-PEM]")
	out = secretAssignment.ReplaceAllString(out, "$1=[REDACTED]")
	if len(out) > maxActualValueLen {
		out = out[:maxActualValueLen] + "...[truncated]"
	}
	return out
}

// rankStatus orders results so that movement between states can be called an
// improvement or regression. A higher rank means a worse result.
func rankStatus(status string) int {
	switch strings.ToUpper(status) {
	case "PASS":
		return 0
	case "INFO":
		return 1
	case "WARN":
		return 2
	case "FAIL":
		return 3
	default:
		return 4
	}
}

func sortStrings(s []string) {
	sort.Strings(s)
}

// sortEntries imposes the deterministic output order: node type, then check
// ID lexicographically. kube-bench check IDs are dot-separated numeric
// identifiers; lexical ordering is stable and independent of input order.
func sortEntries(entries []Entry) {
	sort.SliceStable(entries, func(i, j int) bool {
		ni := firstNonEmpty(entries[i].Older.NodeType, entries[i].Newer.NodeType)
		nj := firstNonEmpty(entries[j].Older.NodeType, entries[j].Newer.NodeType)
		if ni != nj {
			return ni < nj
		}
		return entries[i].CheckID < entries[j].CheckID
	})
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
