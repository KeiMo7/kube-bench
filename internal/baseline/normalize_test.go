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
	"testing"

	"github.com/aquasecurity/kube-bench/check"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func key(family, version, target string) SourceKey {
	return SourceKey{Family: family, Version: version, Target: target}
}

func controlsWith(t *testing.T, sel *Selection, checks ...*check.Check) *check.Controls {
	t.Helper()
	require.True(t, sel.SourceKey.Valid())
	g := &check.Group{ID: "g", Checks: checks}
	return &check.Controls{Type: check.NodeType(sel.Target), Groups: []*check.Group{g}}
}

func chk(id string, state check.State, typ, expected string) *check.Check {
	return &check.Check{ID: id, State: state, Type: typ, ExpectedResult: expected}
}

func TestSourceKeyValidity(t *testing.T) {
	assert.True(t, key("cis", "v1", "master").Valid())
	assert.False(t, SourceKey{Version: "v1", Target: "master"}.Valid())
	assert.False(t, SourceKey{Family: "cis", Target: "master"}.Valid())
	assert.False(t, SourceKey{Family: "cis", Version: "v1"}.Valid())
	assert.Equal(t, "cis/v1/master", key("cis", "v1", "master").String())
	assert.Equal(t, "cis/v1", key("cis", "v1", "master").NormalizedKey())
}

func TestNormalizerDedupSameSourceKey(t *testing.T) {
	sel := &Selection{Family: "cis", Version: "v1", Target: "master",
		SourceKey: key("cis", "v1", "master")}

	c := controlsWith(t, sel,
		chk("1.1.1", check.PASS, "", "bitmask '600'"),
		chk("1.1.1", check.FAIL, "", "bitmask '600'"), // duplicate under same key
		chk("1.1.2", check.FAIL, "", "root:root"),
	)

	n := NewNormalizer()
	n.AddControls(sel, c)
	report := n.Report()

	// First occurrence kept, duplicate excluded from all counters.
	require.Len(t, report.Items, 2)
	assert.Equal(t, 2, report.Summary.Total)
	assert.Equal(t, 1, report.Summary.Pass)
	assert.Equal(t, 1, report.Summary.Fail)
	assert.Equal(t, 0, report.Summary.Warn)
	assert.Equal(t, 0, report.Summary.Info)
	require.Len(t, report.Duplicates, 1)
	assert.Equal(t, "1.1.1", report.Duplicates[0].CheckID)
	assert.Equal(t, 2, report.Duplicates[0].Occurrence)
	assert.Equal(t, 1, report.Summary.DuplicateCount)
}

func TestNormalizerCrossFamilyIndependentItems(t *testing.T) {
	// Same check number under three different family/version sources with
	// different semantics: three independent items, no summing, conflicts
	// marked on both pairs, both original values retained.
	cisSel := &Selection{Family: "cis", Version: "cis-1.24", Target: "master",
		SourceKey: key("cis", "cis-1.24", "master")}
	eksSel := &Selection{Family: "eks", Version: "eks-1.8.0", Target: "master",
		SourceKey: key("eks", "eks-1.8.0", "master")}
	internalSel := &Selection{Family: "internal", Version: "internal-2025.1", Target: "node",
		SourceKey: key("internal", "internal-2025.1", "node")}

	n := NewNormalizer()
	n.AddControls(cisSel, controlsWith(t, cisSel, chk("1.1.1", check.PASS, "", "bitmask '600'")))
	n.AddControls(eksSel, controlsWith(t, eksSel, chk("1.1.1", check.PASS, "manual", "bitmask '600'")))
	n.AddControls(internalSel, controlsWith(t, internalSel, chk("1.1.1", check.PASS, "", "bitmask '644'")))

	report := n.Report()

	require.Len(t, report.Items, 3, "same number under different families must remain independent")
	assert.Equal(t, 3, report.Summary.Total, "merged total equals normalized independent item count")

	// All three stay PASS: states are never added together.
	assert.Equal(t, 3, report.Summary.Pass)
	assert.Equal(t, 0, report.Summary.Fail)

	// Three pairs of conflicts across three sources.
	assert.Len(t, report.Conflicts, 3)
	fields := map[string]bool{}
	for _, cf := range report.Conflicts {
		assert.Equal(t, "1.1.1", cf.CheckID)
		fields[cf.ConflictField] = true
		assert.NotEmpty(t, cf.SourceA)
		assert.NotEmpty(t, cf.SourceB)
		// Original values retained on both sides.
		if cf.ConflictField == "expected_result" {
			assert.NotEqual(t, cf.ExpectedA, cf.ExpectedB)
		} else {
			assert.NotEqual(t, cf.TypeA, cf.TypeB)
		}
	}
	assert.True(t, fields["type"])
	assert.True(t, fields["expected_result"])
	assert.Equal(t, 3, report.Summary.ConflictCount)
}

func TestNormalizerSameNumberSameSemanticsNoConflict(t *testing.T) {
	a := &Selection{Family: "cis", Version: "v1", Target: "master", SourceKey: key("cis", "v1", "master")}
	b := &Selection{Family: "cis", Version: "v2", Target: "master", SourceKey: key("cis", "v2", "master")}

	n := NewNormalizer()
	n.AddControls(a, controlsWith(t, a, chk("1.1.1", check.PASS, "", "same")))
	n.AddControls(b, controlsWith(t, b, chk("1.1.1", check.FAIL, "", "same")))

	report := n.Report()
	assert.Len(t, report.Items, 2)
	assert.Empty(t, report.Conflicts, "identical judgment semantics are not conflicts")
}

func TestNormalizerDefinitionErrors(t *testing.T) {
	sel := &Selection{Family: "cis", Version: "v1", Target: "master", SourceKey: key("cis", "v1", "master")}
	n := NewNormalizer()
	n.AddControls(sel, controlsWith(t, sel, chk("1.1.1", check.PASS, "", "x")))
	n.AddDefinitionError(sel.SourceKey, "1.1.2", "unparseable check")
	report := n.Report()

	require.Len(t, report.DefinitionErrors, 1)
	assert.Equal(t, "1.1.2", report.DefinitionErrors[0].EntryID)
	assert.Equal(t, 1, report.Summary.DefinitionErrors)
	assert.Equal(t, 1, report.Summary.Total, "definition errors do not inflate item totals")
}

func TestNormalizerInvalidSourceKeyRejected(t *testing.T) {
	bad := &Selection{Family: "", Version: "v1", Target: "master"}
	n := NewNormalizer()
	n.AddControls(bad, &check.Controls{Groups: []*check.Group{{Checks: []*check.Check{chk("1", check.PASS, "", "")}}}})
	report := n.Report()
	assert.Empty(t, report.Items)
}

func TestNormalizerDeterministicOrder(t *testing.T) {
	sels := []*Selection{
		{Family: "internal", Version: "v1", Target: "node", SourceKey: key("internal", "v1", "node")},
		{Family: "cis", Version: "v2", Target: "master", SourceKey: key("cis", "v2", "master")},
		{Family: "cis", Version: "v1", Target: "master", SourceKey: key("cis", "v1", "master")},
	}
	n := NewNormalizer()
	for i, s := range sels {
		n.AddControls(s, controlsWith(t, s, chk("2.0.1", check.PASS, "", "x"), chk("2.0.10", check.PASS, "", "x")))
		_ = i
	}
	report := n.Report()
	require.Len(t, report.Items, 6)
	// First item must come from the alphabetically first family/version.
	assert.Equal(t, "cis", report.Items[0].SourceKey.Family)
	assert.Equal(t, "v1", report.Items[0].SourceKey.Version)
	// Numeric check ordering: 2.0.1 before 2.0.10 within one source.
	assert.Equal(t, "2.0.1", report.Items[0].Check.ID)
	assert.Equal(t, "2.0.10", report.Items[1].Check.ID)
}

func TestParseRequest(t *testing.T) {
	cases := []struct {
		raw     string
		family  string
		cluster string
		pin     string
		wantErr bool
	}{
		{raw: "cis", family: "cis"},
		{raw: "cis:1.31", family: "cis", cluster: "1.31"},
		{raw: "cis@cis-1.24", family: "cis", pin: "cis-1.24"},
		{raw: " internal: 1.31 ", family: "internal", cluster: "1.31"},
		{raw: "", wantErr: true},
		{raw: ":1.31", wantErr: true},
		{raw: "cis:", wantErr: true},
		{raw: "cis@", wantErr: true},
	}
	for _, tc := range cases {
		req, err := ParseRequest(tc.raw)
		if tc.wantErr {
			assert.Error(t, err, tc.raw)
			continue
		}
		require.NoError(t, err, tc.raw)
		assert.Equal(t, tc.family, req.Family)
		assert.Equal(t, tc.cluster, req.ClusterVersion)
		assert.Equal(t, tc.pin, req.DefinitionPin)
	}
}

func TestRegistryResolveRequestAndTargetValidation(t *testing.T) {
	root := t.TempDir()
	writeRegistry(t, root, map[string]string{"a.yaml": validManifest})
	r := NewRegistry(root)
	require.NoError(t, r.LoadRoots(root))

	// Cluster version range resolution.
	sel, err := r.ResolveRequest(mustRequest(t, "internal:1.31"), "master", "")
	require.NoError(t, err)
	assert.Equal(t, "v1", sel.Version)
	assert.True(t, sel.SourceKey.Valid())

	// Definition pin.
	sel, err = r.ResolveRequest(mustRequest(t, "internal@v1"), "node", "")
	require.NoError(t, err)
	assert.Equal(t, "v1", sel.Version)

	// Unknown family.
	_, err = r.ResolveRequest(mustRequest(t, "ghost:1.31"), "master", "")
	assert.Error(t, err)

	// Unavailable target.
	_, err = r.ResolveRequest(mustRequest(t, "internal:1.31"), "etcd", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "target")

	// Out-of-range version triggers the declared default degradation.
	sel, err = r.ResolveRequest(mustRequest(t, "internal:9.9"), "master", "")
	require.NoError(t, err)
	assert.True(t, sel.Degraded)
	assert.Equal(t, "v1", sel.Version)
	assert.Contains(t, sel.DegradeReason, "default")
}

func mustRequest(t *testing.T, raw string) Request {
	t.Helper()
	req, err := ParseRequest(raw)
	require.NoError(t, err)
	return req
}
