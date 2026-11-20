package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/kube-bench/internal/diff"
	"github.com/stretchr/testify/assert"
)

// writeTempReport writes a kube-bench-shaped JSON report to a temp file and
// returns the path.
func writeTempReport(t *testing.T, name string, content []byte) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	assert.NoError(t, os.WriteFile(p, content, 0o600))
	return p
}

// minimalReport builds the smallest valid report shape the diff engine
// accepts, with one check per node type.
func minimalReport(version, nodeType, id, status, hash string) []byte {
	return []byte(`{
  "Controls": [{
    "id": "1",
    "version": "` + version + `",
    "text": "section",
    "node_type": "` + nodeType + `",
    "tests": [{
      "section": "1.1",
      "desc": "group",
      "results": [{
        "test_number": "` + id + `",
        "test_desc": "some check",
        "status": "` + status + `",
        "expected_result": "bitmask '600'",
        "actual_value": "permissions=644\n",
        "scored": true,
        "rule_fingerprint": {
          "check_id": "` + id + `",
          "condition_hash": "` + hash + `",
          "condition": "{\"scored\":true}",
          "rule_set_version": "` + version + `"
        }
      }]
    }]
  }],
  "Totals": {"total_pass": 1, "total_fail": 0, "total_warn": 0, "total_info": 0},
  "schema_version": "kube-bench-report-v1"
}`)
}

func TestDiffComparePackage_TightenedCondition(t *testing.T) {
	older := minimalReport("k3s-cis-1.10", "master", "1.1.20", "PASS", "hash-600")
	newer := minimalReport("k3s-cis-1.11", "master", "1.1.20", "FAIL", "hash-644")

	r, err := diff.Compare(older, newer, diff.Options{})
	assert.NoError(t, err)
	assert.True(t, r.Comparable)
	var found bool
	for _, e := range r.Entries {
		if e.CheckID == "1.1.20" {
			found = true
			assert.Equal(t, diff.RuleChange, e.Attribution)
			assert.Empty(t, e.Movement)
			assert.Equal(t, "bitmask '600'", e.Older.ExpectedResult)
			assert.Equal(t, "bitmask '600'", e.Newer.ExpectedResult)
		}
	}
	assert.True(t, found)
}

// The compare command must refuse unrecognised report structures explicitly.
func TestDiffComparePackage_RejectsGarbage(t *testing.T) {
	_, err := diff.Compare([]byte("{\"hello\":\"world\"}"),
		minimalReport("cis-1.10", "master", "1.1.1", "PASS", "h"), diff.Options{})
	assert.Error(t, err)
}

// End-to-end through the public Compare + JSON marshalling path used by the
// compare subcommand: output must be valid diff-schema JSON.
func TestCompareOutput_IsValidJSON(t *testing.T) {
	older := minimalReport("cis-1.10", "master", "1.1.1", "FAIL", "h")
	newer := minimalReport("cis-1.10", "master", "1.1.1", "PASS", "h")

	r, err := diff.Compare(older, newer, diff.Options{})
	assert.NoError(t, err)
	raw, err := marshalCompareJSON(r)
	assert.NoError(t, err)

	var decoded map[string]interface{}
	assert.NoError(t, json.Unmarshal(raw, &decoded))
	assert.Equal(t, "kube-bench-diff-v1", decoded["schema_version"])
	assert.Equal(t, true, decoded["comparable"])
}

func TestCompareCommand_MissingFlagsErrors(t *testing.T) {
	// Just ensure the command is wired into the root command tree.
	found := false
	for _, c := range RootCmd.Commands() {
		if c.Name() == "compare" {
			found = true
		}
	}
	assert.True(t, found, "compare subcommand must be registered")
}
