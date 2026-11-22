package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aquasecurity/kube-bench/internal/aggregate"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestParseReportRefs(t *testing.T) {
	cases := []struct {
		name    string
		specs   []string
		want    []aggregate.ReportRef
		wantErr bool
	}{
		{
			name:  "single binding",
			specs: []string{"node-a=/tmp/a.json"},
			want:  []aggregate.ReportRef{{Source: "node-a", Path: "/tmp/a.json"}},
		},
		{
			name:  "paths may contain equals signs",
			specs: []string{"node-a=/dir/x=r.json"},
			want:  []aggregate.ReportRef{{Source: "node-a", Path: "/dir/x=r.json"}},
		},
		{
			name:    "bare path without source is rejected, never guessed",
			specs:   []string{"/tmp/a.json"},
			wantErr: true,
		},
		{
			name:    "empty source is rejected",
			specs:   []string{"=/tmp/a.json"},
			wantErr: true,
		},
		{
			name:    "empty path is rejected",
			specs:   []string{"node-a="},
			wantErr: true,
		},
		{
			name:    "no specs at all",
			specs:   []string{},
			wantErr: true,
		},
		{
			name:    "duplicate binding is rejected",
			specs:   []string{"node-a=/tmp/a.json", "node-a=/tmp/a.json"},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseReportRefs(tc.specs)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// writeCmdReport builds a minimal enveloped single-node report on disk.
func writeCmdReport(t *testing.T, dir, name, status string, mtime time.Time) string {
	t.Helper()
	report := map[string]any{
		"Controls": []map[string]any{
			{
				"id":        "1",
				"version":   "cis-1.10",
				"text":      "Master Node Security Configuration",
				"node_type": "master",
				"tests": []map[string]any{
					{
						"section": "1.1",
						"desc":    "Master Node Configuration Files",
						"results": []map[string]any{
							{
								"test_number": "1.1.1",
								"test_desc":   "API server pod spec permissions",
								"status":      status,
								"scored":      true,
							},
						},
					},
				},
				"total_pass": 1,
				"total_fail": 0,
				"total_warn": 0,
				"total_info": 0,
			},
		},
		"Totals": map[string]any{
			"total_pass": 1,
			"total_fail": 0,
			"total_warn": 0,
			"total_info": 0,
		},
	}
	data, err := json.Marshal(report)
	assert.NoError(t, err)
	path := filepath.Join(dir, name)
	assert.NoError(t, os.WriteFile(path, data, 0o600))
	assert.NoError(t, os.Chtimes(path, mtime, mtime))
	return path
}

// runAggregateCommand invokes the real cobra command and returns the process
// exit code the command would have used, captured instead of exiting.
// A fresh command tree is built per call because cobra persists SetArgs on the
// shared root command, which would otherwise replay earlier test arguments.
func runAggregateCommand(t *testing.T, args ...string) (code int, output []byte) {
	t.Helper()
	code = -1
	oldOsExit := osExit
	osExit = func(c int) { code = c }
	defer func() { osExit = oldOsExit }()

	outFile := filepath.Join(t.TempDir(), "out.json")
	root := &cobra.Command{Use: "kube-bench"}
	root.AddCommand(aggregateCmd)
	root.PersistentFlags().StringVar(&outputFile, "outputfile", "", "output file")
	fullArgs := append([]string{"aggregate"}, args...)
	fullArgs = append(fullArgs, "--outputfile", outFile)
	root.SetArgs(fullArgs)
	assert.NoError(t, root.Execute())
	data, err := os.ReadFile(outFile)
	assert.NoError(t, err)
	return code, data
}

func TestAggregateCommandEndToEnd(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	pathA := writeCmdReport(t, dir, "a.json", "FAIL", base)
	pathB := writeCmdReport(t, dir, "b.json", "PASS", base.Add(time.Hour))

	// Clean state: cobra registers persistent flags globally.
	aggregateReportSpecs = nil
	aggregateExpected = nil
	outputFile = ""

	code, out := runAggregateCommand(t,
		"--report", "node-a="+pathA,
		"--report", "node-b="+pathB,
	)
	assert.Equal(t, 0, code, "healthy aggregation must exit zero")

	var summary aggregate.ClusterSummary
	assert.NoError(t, json.Unmarshal(out, &summary))
	assert.Equal(t, 2, summary.NodesParticipating)
	assert.Equal(t, 0, len(summary.ParseErrors))
	assert.Equal(t, "aggregate/v1", summary.SchemaVersion)
}

func TestAggregateCommandPartialFailureExitCode(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	good := writeCmdReport(t, dir, "good.json", "PASS", base)
	bad := filepath.Join(dir, "bad.json")
	assert.NoError(t, os.WriteFile(bad, []byte("{broken"), 0o600))

	aggregateReportSpecs = nil
	aggregateExpected = nil
	outputFile = ""

	code, out := runAggregateCommand(t,
		"--report", "good-node="+good,
		"--report", "bad-node="+bad,
	)
	assert.Equal(t, aggregateExitPartialFail, code, "one bad report must yield the partial-failure exit code")

	var summary aggregate.ClusterSummary
	assert.NoError(t, json.Unmarshal(out, &summary))
	assert.Equal(t, 1, len(summary.ParseErrors))
	assert.Equal(t, "bad-node", summary.ParseErrors[0].Source)
}

func TestAggregateCommandAllFailureExitCode(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	assert.NoError(t, os.WriteFile(bad, []byte("nonsense"), 0o600))

	aggregateReportSpecs = nil
	aggregateExpected = nil
	outputFile = ""

	code := -1
	oldOsExit := osExit
	osExit = func(c int) { code = c }
	defer func() { osExit = oldOsExit }()

	root := &cobra.Command{Use: "kube-bench"}
	root.AddCommand(aggregateCmd)
	outFile := filepath.Join(t.TempDir(), "out.json")
	root.PersistentFlags().StringVar(&outputFile, "outputfile", "", "output file")
	root.SetArgs([]string{
		"aggregate",
		"--report", "bad-node=" + bad,
		"--outputfile", outFile,
	})
	assert.NoError(t, root.Execute())
	assert.Equal(t, aggregateExitAllFailed, code, "no usable reports must fail the pipeline")
}
