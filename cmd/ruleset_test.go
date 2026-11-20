package cmd

import (
	"testing"

	"github.com/aquasecurity/kube-bench/check"
	"github.com/stretchr/testify/assert"
)

func TestProductLineOf(t *testing.T) {
	cases := map[string]string{
		"k3s-cis-1.10":      "k3s",
		"cis-1.10":          "cis",
		"eks-1.8.0":         "eks",
		"gke-1.6.0":         "gke",
		"cis-1.24-microk8s": "cis",
		"ack-1.0":           "ack",
	}
	for in, want := range cases {
		assert.Equal(t, want, productLineOf(in), in)
	}
}

func TestBuildRuleSetInfo_ManualSelection(t *testing.T) {
	resetRuleSetSelection()
	recordManualSelection("k3s-cis-1.10")
	detecetedKubeVersion = "none"

	info := buildRuleSetInfo("k3s-cis-1.10")
	assert.Equal(t, "k3s-cis-1.10", info.Version)
	assert.Equal(t, "k3s", info.ProductLine)
	assert.Equal(t, selectionModeManual, info.SelectionMode)
	assert.Equal(t, "k3s-cis-1.10", info.RequestedVersion)
	assert.False(t, info.FallbackUsed)
}

// Hard constraint: when version mapping falls back to a lower rule set
// version, the report must carry the fallback trail.
func TestBuildRuleSetInfo_FallbackTrail(t *testing.T) {
	resetRuleSetSelection()
	recordVersionMappingSelection("1.36", fallbackTrace{
		used:        true,
		fromVersion: "1.36",
		toVersion:   "cis-2.0",
	})
	detecetedKubeVersion = "1.36"

	info := buildRuleSetInfo("cis-2.0")
	assert.True(t, info.FallbackUsed)
	assert.Equal(t, "1.36", info.FallbackFromVersion)
	assert.Equal(t, "cis-2.0", info.FallbackToVersion)
	assert.Equal(t, selectionModeVersionMapping, info.SelectionMode)
}

// The existing mapToBenchmarkVersion return values must be unchanged; the
// only addition is the fallback side effect.
func TestMapToBenchmarkVersion_RecordsFallback(t *testing.T) {
	resetRuleSetSelection()
	m := map[string]string{
		"1.28": "cis-1.10",
		"1.29": "cis-1.11",
	}

	// Exact hit => no fallback.
	got, err := mapToBenchmarkVersion(m, "1.29")
	assert.NoError(t, err)
	assert.Equal(t, "cis-1.11", got)
	assert.False(t, versionFallback.used)

	// Miss on 1.31/1.30 which are absent from the tiny map, decrementing to
	// the 1.29 hit => fallback recorded, returned version unchanged.
	got, err = mapToBenchmarkVersion(m, "1.31")
	assert.NoError(t, err)
	assert.Equal(t, "cis-1.11", got)
	assert.True(t, versionFallback.used)
	assert.Equal(t, "1.31", versionFallback.fromVersion)
	assert.Equal(t, "cis-1.11", versionFallback.toVersion)

	// No hit at all => existing error behaviour preserved.
	_, err = mapToBenchmarkVersion(m, "2.99")
	assert.Error(t, err)
}

// The additive RuleSetInfo must round-trip through the check package JSON
// shape used in reports.
func TestRuleSetInfoJSONShape(t *testing.T) {
	resetRuleSetSelection()
	recordPlatformSelection("eks-1.8.0")
	info := buildRuleSetInfo("eks-1.8.0")

	c := &check.Controls{ID: "1", Version: "eks-1.8.0", RuleSet: info}
	raw, err := c.JSON()
	assert.NoError(t, err)
	s := string(raw)
	assert.Contains(t, s, `"rule_set":{`)
	assert.Contains(t, s, `"selection_mode":"platform"`)
}
