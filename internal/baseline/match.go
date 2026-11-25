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
	"strconv"
	"strings"
)

// semanticVersion is a dotted numeric version. Non-numeric trailing segments
// (for example pre-release tags) are retained for equality but numeric
// comparison only uses the numeric prefix, mirroring how kube-bench handles
// "1.27+" style versions.
type semanticVersion struct {
	parts []int
	raw   string
}

func parseSemanticVersion(v string) (semanticVersion, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return semanticVersion{}, fmt.Errorf("empty version")
	}
	// Strip a leading "v" and common build/metadata suffixes.
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(v, "+-"); i >= 0 {
		v = v[:i]
	}
	segments := strings.Split(v, ".")
	parts := make([]int, 0, len(segments))
	for _, s := range segments {
		n, err := strconv.Atoi(s)
		if err != nil {
			// Non-numeric segments (for example an "eks" or "cis" prefix)
			// are tolerated for exact/identifier matching; they carry no
			// numeric ordering weight. Ranges still reject them via
			// isRangeExpression.
			n = 0
		}
		parts = append(parts, n)
	}
	return semanticVersion{parts: parts, raw: v}, nil
}

// compare returns -1, 0 or 1. Missing segments are treated as zero, so
// "1.2" equals "1.2.0".
func (s semanticVersion) compare(o semanticVersion) int {
	n := len(s.parts)
	if len(o.parts) > n {
		n = len(o.parts)
	}
	for i := 0; i < n; i++ {
		a, b := 0, 0
		if i < len(s.parts) {
			a = s.parts[i]
		}
		if i < len(o.parts) {
			b = o.parts[i]
		}
		if a != b {
			if a < b {
				return -1
			}
			return 1
		}
	}
	return 0
}

func (s semanticVersion) equals(o semanticVersion) bool { return s.compare(o) == 0 }

// matcherKind ranks matcher specificity: exact matches are narrowest,
// bounded ranges next, wildcard prefixes broadest.
type matcherKind int

const (
	kindExact matcherKind = iota
	kindRange
	kindWildcard
)

// matcher is one parsed entry of Baseline.Versions.
type matcher struct {
	kind       matcherKind
	exact      semanticVersion
	lower      semanticVersion
	upper      semanticVersion
	wildcard   semanticVersion
	wildSegs   int
	raw        string
	entryOrder int // index of the owning Baseline inside the manifest
}

// contains reports whether v is matched by this matcher.
func (m matcher) contains(v semanticVersion) bool {
	switch m.kind {
	case kindExact:
		return v.equals(m.exact)
	case kindWildcard:
		return matchWildcard(m.wildcard, v)
	case kindRange:
		return v.compare(m.lower) >= 0 && v.compare(m.upper) <= 0
	default:
		return false
	}
}

func matchWildcard(pattern, v semanticVersion) bool {
	if len(v.parts) < len(pattern.parts) {
		return false
	}
	for i, p := range pattern.parts {
		if v.parts[i] != p {
			return false
		}
	}
	return true
}

// specificity gives a narrower matcher a higher score. Exact > range >
// wildcard: a bounded interval is always narrower than a wildcard prefix.
type specificity struct {
	kind     matcherKind
	wildSegs int // lower is better
	span     int // range width in minor units; lower is better
	order    int // declaration order; lower is better
}

func (m matcher) specificity() specificity {
	s := specificity{kind: m.kind, wildSegs: m.wildSegs, order: m.entryOrder}
	if m.kind == kindRange {
		s.span = rangeSpan(m.lower, m.upper)
	}
	return s
}

// rangeSpan measures interval width in units of the most significant
// version segment that differs, so ranges expressed over different
// granularities stay comparable.
func rangeSpan(lower, upper semanticVersion) int {
	n := len(lower.parts)
	if len(upper.parts) > n {
		n = len(upper.parts)
	}
	// Use a simple segment-wise weighted width: each segment is 1000x the
	// next, which keeps ordering deterministic for realistic version depths.
	span := 0
	multiplier := 1
	for i := n - 1; i >= 0; i-- {
		a, b := 0, 0
		if i < len(lower.parts) {
			a = lower.parts[i]
		}
		if i < len(upper.parts) {
			b = upper.parts[i]
		}
		span += (b - a) * multiplier
		multiplier *= 1000
	}
	return span
}

// lessSpecific reports whether a should lose against b: b is chosen when
// more specific; ties resolve by declaration order (earlier wins).
func lessSpecific(a, b specificity) bool {
	if a.kind != b.kind {
		// exact(0) beats range(1) beats wildcard(2).
		return a.kind > b.kind
	}
	switch a.kind {
	case kindWildcard:
		if a.wildSegs != b.wildSegs {
			return a.wildSegs > b.wildSegs
		}
	case kindRange:
		if a.span != b.span {
			return a.span > b.span
		}
	}
	return a.order > b.order
}

// parseMatcher parses one Versions entry. Supported syntaxes:
//
//	"1.24"            exact version
//	"1.*" / "1.2.*"   wildcard (one or more trailing wild segments)
//	"1.22-1.24"       inclusive range
//	"[1.22,1.24]"     inclusive bracket range
func parseMatcher(raw string, entryOrder int) (matcher, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return matcher{}, fmt.Errorf("empty version expression")
	}

	switch {
	case strings.Contains(raw, "*"):
		return parseWildcard(raw, entryOrder)
	case strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]"):
		inner := strings.TrimSuffix(strings.TrimPrefix(raw, "["), "]")
		parts := strings.Split(inner, ",")
		if len(parts) != 2 {
			return matcher{}, fmt.Errorf("invalid bracket range %q", raw)
		}
		return parseRange(parts[0], parts[1], raw, entryOrder)
	case isRangeExpression(raw):
		parts := strings.SplitN(raw, "-", 2)
		return parseRange(parts[0], parts[1], raw, entryOrder)
	default:
		v, err := parseSemanticVersion(raw)
		if err != nil {
			return matcher{}, fmt.Errorf("invalid exact version %q: %v", raw, err)
		}
		return matcher{kind: kindExact, exact: v, raw: raw, entryOrder: entryOrder}, nil
	}
}

// isRangeExpression reports whether a hyphenated expression is a numeric
// version range ("1.22-1.24"). A range contains exactly one hyphen and
// both sides must be purely dotted-numeric versions; identifiers such as
// "cis-1.6-k3s" are exact versions, not ranges.
func isRangeExpression(raw string) bool {
	if strings.Count(raw, "-") != 1 {
		return false
	}
	idx := strings.Index(raw, "-")
	if idx <= 0 || idx == len(raw)-1 {
		return false
	}
	return isDottedNumeric(raw[:idx]) && isDottedNumeric(raw[idx+1:])
}

// isDottedNumeric reports whether s is a non-empty dotted sequence of
// non-negative integers ("1", "1.22").
func isDottedNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, seg := range strings.Split(s, ".") {
		if _, err := strconv.Atoi(seg); err != nil {
			return false
		}
	}
	return true
}

func parseWildcard(raw string, entryOrder int) (matcher, error) {
	segments := strings.Split(raw, ".")
	prefix := make([]int, 0, len(segments))
	wildSegs := 0
	sawWild := false
	for _, s := range segments {
		if s == "*" || s == "x" || s == "X" {
			sawWild = true
			wildSegs++
			continue
		}
		if sawWild {
			return matcher{}, fmt.Errorf("wildcard must be trailing in %q", raw)
		}
		n, err := strconv.Atoi(s)
		if err != nil {
			return matcher{}, fmt.Errorf("invalid wildcard version %q: %v", raw, err)
		}
		prefix = append(prefix, n)
	}
	if wildSegs == 0 {
		return matcher{}, fmt.Errorf("invalid wildcard version %q", raw)
	}
	return matcher{
		kind:       kindWildcard,
		wildcard:   semanticVersion{parts: prefix, raw: raw},
		wildSegs:   wildSegs,
		raw:        raw,
		entryOrder: entryOrder,
	}, nil
}

func parseRange(lowRaw, highRaw, raw string, entryOrder int) (matcher, error) {
	low, err := parseSemanticVersion(lowRaw)
	if err != nil {
		return matcher{}, fmt.Errorf("invalid range lower bound %q: %v", raw, err)
	}
	high, err := parseSemanticVersion(highRaw)
	if err != nil {
		return matcher{}, fmt.Errorf("invalid range upper bound %q: %v", raw, err)
	}
	if low.compare(high) > 0 {
		return matcher{}, fmt.Errorf("range lower bound %q exceeds upper bound %q", lowRaw, highRaw)
	}
	return matcher{
		kind:       kindRange,
		lower:      low,
		upper:      high,
		raw:        raw,
		entryOrder: entryOrder,
	}, nil
}

// matchResult is the outcome of selecting a definition version for a
// requested cluster version within one family.
type matchResult struct {
	version    string
	degraded   bool
	reason     string
	available  []string // version expressions offered by the family
	matchCount int
}

// selectVersion implements the deterministic overlap rule: among all
// entries matching the requested version, the narrowest matcher wins, and
// ties are broken by declaration order. When nothing matches, the family's
// explicitly declared default is used (degraded=true); otherwise an error
// is returned listing the family, requested version and available ranges.
func selectVersion(m *Manifest, requested string) (matchResult, error) {
	req, err := parseSemanticVersion(requested)
	if err != nil {
		return matchResult{}, fmt.Errorf("family %q: requested version %q is not valid: %v", m.Family, requested, err)
	}

	var best *matcher
	var bestVersion string
	matchCount := 0
	available := make([]string, 0, len(m.Baselines))

	for entryIdx, b := range m.Baselines {
		available = append(available, b.Version+"("+strings.Join(b.Versions, ",")+")")
		for _, expr := range b.Versions {
			mt, err := parseMatcher(expr, entryIdx)
			if err != nil {
				// Manifest validation should have caught this; keep the
				// error message limited to manifest location and entry id.
				return matchResult{}, fmt.Errorf("%s: entry %s has invalid version expression %q: %v",
					m.origin, b.Version, expr, err)
			}
			if mt.contains(req) {
				matchCount++
				if best == nil || lessSpecific(best.specificity(), mt.specificity()) {
					cur := mt
					best = &cur
					bestVersion = b.Version
				}
			}
		}
	}

	if best != nil {
		return matchResult{version: bestVersion, matchCount: matchCount, available: available}, nil
	}

	if m.Default != "" {
		if !m.declaresVersion(m.Default) {
			return matchResult{}, fmt.Errorf("%s: family %q default %q is not a registered version",
				m.origin, m.Family, m.Default)
		}
		return matchResult{
			version:    m.Default,
			degraded:   true,
			reason:     fmt.Sprintf("requested version %q matches no declared range for family %q; using declared default %q", requested, m.Family, m.Default),
			available:  available,
			matchCount: 0,
		}, nil
	}

	return matchResult{}, &NoMatchError{
		Family:    m.Family,
		Requested: requested,
		Available: available,
	}
}

func (m *Manifest) declaresVersion(version string) bool {
	for _, b := range m.Baselines {
		if b.Version == version {
			return true
		}
	}
	return false
}

// NoMatchError carries the information required by the failure path: the
// requested family and version plus the ranges the family actually offers.
type NoMatchError struct {
	Family    string
	Requested string
	Available []string
}

func (e *NoMatchError) Error() string {
	return fmt.Sprintf("no baseline in family %q matches requested version %q; available: %s",
		e.Family, e.Requested, strings.Join(e.Available, "; "))
}
