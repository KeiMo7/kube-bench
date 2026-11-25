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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseMatcher(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		kind    matcherKind
		wantErr bool
	}{
		{name: "exact", raw: "1.24", kind: kindExact},
		{name: "wildcard minor", raw: "1.*", kind: kindWildcard},
		{name: "wildcard patch", raw: "1.2.*", kind: kindWildcard},
		{name: "range hyphen", raw: "1.22-1.24", kind: kindRange},
		{name: "range brackets", raw: "[1.22,1.24]", kind: kindRange},
		{name: "identifier with hyphens is exact", raw: "cis-1.6-k3s", kind: kindExact},
		{name: "identifier with prefix is exact", raw: "eks-stig-kubernetes-v1r6", kind: kindExact},
		{name: "empty", raw: "", wantErr: true},
		{name: "bad bracket range", raw: "[1.0]", wantErr: true},
		{name: "inverted range", raw: "1.30-1.20", wantErr: true},
		{name: "non trailing wildcard", raw: "1.*.2", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := parseMatcher(tc.raw, 0)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.kind, m.kind)
		})
	}
}

func TestMatcherContains(t *testing.T) {
	cases := []struct {
		expr string
		ver  string
		want bool
	}{
		{"1.24", "1.24", true},
		{"1.24", "1.24.0", true},
		{"1.24", "1.25", false},
		{"1.*", "1.31", true},
		{"1.*", "2.0", false},
		{"1.2.*", "1.2.9", true},
		{"1.2.*", "1.3.0", false},
		{"1.22-1.24", "1.21", false},
		{"1.22-1.24", "1.22", true},
		{"1.22-1.24", "1.23", true},
		{"1.22-1.24", "1.24", true},
		{"1.22-1.24", "1.25", false},
		{"[1.22,1.24]", "1.23", true},
	}
	for _, tc := range cases {
		m, err := parseMatcher(tc.expr, 0)
		require.NoError(t, err)
		v, err := parseSemanticVersion(tc.ver)
		require.NoError(t, err)
		assert.Equal(t, tc.want, m.contains(v), "expr=%s ver=%s", tc.expr, tc.ver)
	}
}

func manifestForSelection() *Manifest {
	return &Manifest{
		Family: "cis",
		origin: "manifest.yaml",
		Baselines: []Baseline{
			{Version: "cis-wide", Versions: []string{"1.*"}, declarationOrder: 0},
			{Version: "cis-range", Versions: []string{"1.29-1.33"}, declarationOrder: 1},
			{Version: "cis-exact", Versions: []string{"1.31"}, declarationOrder: 2},
			// Same width as cis-range but declared later: must lose.
			{Version: "cis-range-late", Versions: []string{"1.29-1.33"}, declarationOrder: 3},
			// Narrower range overlapping cis-range on 1.30-1.31.
			{Version: "cis-narrow", Versions: []string{"1.30-1.31"}, declarationOrder: 4},
		},
	}
}

func TestSelectVersionOverlapPriority(t *testing.T) {
	m := manifestForSelection()

	cases := []struct {
		requested string
		want      string
	}{
		// Exact beats wildcard and ranges.
		{"1.31", "cis-exact"},
		// Narrower range beats wider range and wildcard.
		{"1.30", "cis-narrow"},
		// Only the wide range matches (besides wildcard): range beats
		// wildcard because it is more specific.
		{"1.32", "cis-range"},
		// Only wildcard matches.
		{"1.99", "cis-wide"},
	}
	for _, tc := range cases {
		t.Run(tc.requested, func(t *testing.T) {
			res, err := selectVersion(m, tc.requested)
			require.NoError(t, err)
			assert.Equal(t, tc.want, res.version)
		})
	}
}

func TestSelectVersionDeclarationOrderTieBreak(t *testing.T) {
	m := manifestForSelection()
	// 1.29 matches both equal-width ranges; the earlier declaration wins.
	res, err := selectVersion(m, "1.29")
	require.NoError(t, err)
	assert.Equal(t, "cis-range", res.version)
	assert.Greater(t, res.matchCount, 1)
}

func TestSelectVersionNoMatchNoDefault(t *testing.T) {
	m := &Manifest{
		Family: "cis",
		origin: "manifest.yaml",
		Baselines: []Baseline{
			{Version: "a", Versions: []string{"1.0-1.10"}, declarationOrder: 0},
		},
	}
	_, err := selectVersion(m, "2.0")
	require.Error(t, err)

	var nme *NoMatchError
	require.ErrorAs(t, err, &nme)
	assert.Equal(t, "cis", nme.Family)
	assert.Equal(t, "2.0", nme.Requested)
	assert.NotEmpty(t, nme.Available)
}

func TestSelectVersionDefaultDegradation(t *testing.T) {
	m := &Manifest{
		Family:  "cis",
		origin:  "manifest.yaml",
		Default: "a",
		Baselines: []Baseline{
			{Version: "a", Versions: []string{"1.0-1.10"}, declarationOrder: 0},
		},
	}
	res, err := selectVersion(m, "9.9")
	require.NoError(t, err)
	assert.True(t, res.degraded)
	assert.Equal(t, "a", res.version)
	assert.Contains(t, res.reason, "default")
}

func TestSelectVersionInvalidDefault(t *testing.T) {
	m := &Manifest{
		Family:  "cis",
		origin:  "manifest.yaml",
		Default: "missing",
		Baselines: []Baseline{
			{Version: "a", Versions: []string{"1.0"}, declarationOrder: 0},
		},
	}
	_, err := selectVersion(m, "9.9")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "default")
}

func TestCheckNumberLess(t *testing.T) {
	assert.True(t, checkNumberLess("1.2.9", "1.2.10"))
	assert.False(t, checkNumberLess("1.2.10", "1.2.9"))
	assert.True(t, checkNumberLess("1.1", "1.1.1"))
}
