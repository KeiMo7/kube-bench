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

package check

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadControlsTolerantSkipsBadCheck(t *testing.T) {
	in := []byte(`
type: "master"
id: 1
text: "t"
groups:
  - id: G1
    text: "group"
    checks:
      - id: G1/C1
        text: "good check"
        scored: true
      - id: G1/C2
        scored: true
        tests:
          test_items:
            - compare:
                op: [this, is, not, a, string]
      - id: G1/C3
        text: "another good check"
        scored: true
`)
	controls, defErrs, err := LoadControlsTolerant(MASTER, in, "1.31")
	require.NoError(t, err)
	require.Len(t, controls.Groups, 1)

	// The two well-formed checks survive; the broken one is skipped.
	var ids []string
	for _, c := range controls.Groups[0].Checks {
		ids = append(ids, c.ID)
	}
	assert.Equal(t, []string{"G1/C1", "G1/C3"}, ids)

	require.Len(t, defErrs, 1)
	assert.Equal(t, "G1", defErrs[0].GroupID)
	assert.Equal(t, "G1/C2", defErrs[0].CheckID)
	assert.NotEmpty(t, defErrs[0].Reason)
	// Error message names the entry but does not dump audit commands.
	assert.Contains(t, defErrs[0].Error(), "G1/C2")
}

func TestLoadControlsTolerantEmptyID(t *testing.T) {
	in := []byte(`
type: "master"
groups:
  - id: G1
    checks:
      - text: "missing id"
        scored: true
      - id: G1/C1
`)
	controls, defErrs, err := LoadControlsTolerant(MASTER, in, "")
	require.NoError(t, err)
	require.Len(t, controls.Groups[0].Checks, 1)
	assert.Equal(t, "G1/C1", controls.Groups[0].Checks[0].ID)
	require.Len(t, defErrs, 1)
	assert.Contains(t, defErrs[0].Error(), "empty")
}

func TestLoadControlsTolerantStructuralFailure(t *testing.T) {
	// Wrong node type must still be a hard error.
	in := []byte(`
type: "node"
groups: []
`)
	_, _, err := LoadControlsTolerant(MASTER, in, "")
	require.Error(t, err)
	assert.EqualError(t, err, "non-master controls file specified")

	// Unparseable document envelope must still be a hard error.
	_, _, err = LoadControlsTolerant(MASTER, []byte("BOOM"), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal YAML")
}

func TestLoadControlsTolerantMatchesNewControlsForGoodInput(t *testing.T) {
	in := []byte(`
type: "master"
id: 1
version: "v1"
text: "t"
groups:
  - id: G1
    type: ""
    text: "group"
    checks:
      - id: G1/C1
        text: "check"
        scored: false
`)
	tolerant, defErrs, err := LoadControlsTolerant(MASTER, in, "1.31")
	require.NoError(t, err)
	assert.Empty(t, defErrs)

	strict, err := NewControls(MASTER, in, "1.31")
	require.NoError(t, err)

	assert.Equal(t, strict.ID, tolerant.ID)
	assert.Equal(t, strict.Type, tolerant.Type)
	assert.Equal(t, strict.DetectedVersion, tolerant.DetectedVersion)
	require.Len(t, tolerant.Groups, 1)
	require.Len(t, strict.Groups, 1)
	require.Len(t, tolerant.Groups[0].Checks, 1)
	require.Len(t, strict.Groups[0].Checks, 1)
	assert.Equal(t, strict.Groups[0].Checks[0].ID, tolerant.Groups[0].Checks[0].ID)
	assert.Equal(t, strict.Groups[0].Checks[0].Text, tolerant.Groups[0].Checks[0].Text)
}
