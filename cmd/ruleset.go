package cmd

import "github.com/aquasecurity/kube-bench/check"

// Selection modes recorded in the additive rule set metadata of a report.
const (
	selectionModeManual         = "manual"
	selectionModePlatform       = "platform"
	selectionModeVersionMapping = "version-mapping"
)

// ruleSetSelection captures how the rule set for the current run was chosen.
// It is populated by the existing version-selection code paths and read when
// each Controls section is built, so the report records manual selection and
// version-mapping fallbacks. These variables do not change any existing
// external behaviour of the selection functions.
var (
	// ruleSetSelectionMode is one of the selectionMode* constants.
	ruleSetSelectionMode string
	// ruleSetRequestedVersion is the input that drove selection.
	ruleSetRequestedVersion string
	// versionFallback records whether the last version mapping fell back to
	// an older rule set because no exact match existed.
	versionFallback fallbackTrace
)

// fallbackTrace is the audit trail of a rule set version fallback.
type fallbackTrace struct {
	used        bool
	fromVersion string
	toVersion   string
}

// recordVersionMappingSelection stores the selection context for a run driven
// by Kubernetes version mapping.
func recordVersionMappingSelection(kubeVersion string, fb fallbackTrace) {
	ruleSetSelectionMode = selectionModeVersionMapping
	ruleSetRequestedVersion = kubeVersion
	versionFallback = fb
}

// recordManualSelection stores the context for a run driven by --benchmark.
func recordManualSelection(benchmarkVersion string) {
	ruleSetSelectionMode = selectionModeManual
	ruleSetRequestedVersion = benchmarkVersion
	versionFallback = fallbackTrace{}
}

// recordPlatformSelection stores the context for a run whose rule set was
// chosen from a detected managed platform.
func recordPlatformSelection(benchmarkVersion string) {
	ruleSetSelectionMode = selectionModePlatform
	ruleSetRequestedVersion = benchmarkVersion
	versionFallback = fallbackTrace{}
}

// resetRuleSetSelection clears selection state. It is used by tests and at the
// start of benchmark-version resolution so stale state never leaks across runs.
func resetRuleSetSelection() {
	ruleSetSelectionMode = ""
	ruleSetRequestedVersion = ""
	versionFallback = fallbackTrace{}
}

// buildRuleSetInfo assembles the additive rule set metadata for one Controls
// section from the current run's selection state.
func buildRuleSetInfo(ruleSetVersion string) *check.RuleSetInfo {
	info := &check.RuleSetInfo{
		Version:             ruleSetVersion,
		ProductLine:         productLineOf(ruleSetVersion),
		SelectionMode:       ruleSetSelectionMode,
		RequestedVersion:    ruleSetRequestedVersion,
		DetectedVersion:     detecetedKubeVersion,
		FallbackUsed:        versionFallback.used,
		FallbackFromVersion: versionFallback.fromVersion,
		FallbackToVersion:   versionFallback.toVersion,
	}
	return info
}

// productLineOf derives the benchmark product line from a rule set version.
// Examples:
//
//	"k3s-cis-1.10" -> "k3s"
//	"cis-1.10"     -> "cis"
//	"eks-1.8.0"    -> "eks"
//	"cis-1.24-microk8s" -> "cis"
func productLineOf(ruleSetVersion string) string {
	v := ruleSetVersion
	for _, suffix := range []string{"-microk8s"} {
		if len(v) > len(suffix) && v[len(v)-len(suffix):] == suffix {
			v = v[:len(v)-len(suffix)]
			break
		}
	}
	for i := 0; i < len(v); i++ {
		if v[i] == '-' {
			return v[:i]
		}
	}
	return v
}
