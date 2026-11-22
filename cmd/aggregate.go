package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/aquasecurity/kube-bench/internal/aggregate"
	"github.com/spf13/cobra"
)

// Exit codes for the aggregate command. They are distinct from the single-node
// run command's --exit-code value so pipelines can tell the failure modes apart.
const (
	aggregateExitAllFailed   = 1
	aggregateExitPartialFail = 2
)

// osExit is indirected so tests can observe the exit code without terminating
// the test process; production behaviour is unchanged.
var osExit = os.Exit

var (
	aggregateReportSpecs []string
	aggregateExpected    []string
)

func init() {
	RootCmd.AddCommand(aggregateCmd)
	aggregateCmd.Flags().StringSliceVar(&aggregateReportSpecs, "report", []string{},
		`Single-node JSON report to include, bound to an explicit source name as "<source>=<path>".
Repeat the flag or pass a comma-separated list for multiple reports, e.g.
--report node-a=/reports/a.json --report node-b=/reports/b.json
A report without a "<source>=" prefix is rejected: reports carry no source
identifier of their own and one must never be guessed.`)
	aggregateCmd.Flags().StringSliceVar(&aggregateExpected, "expected-source", []string{},
		`Optional list of source names that must participate. Sources listed here
but absent from the reports are reported as missing; any unlisted source with
a usable report is reported as extra. Repeat or comma-separate as with --report.`)
}

var aggregateCmd = &cobra.Command{
	Use:   "aggregate",
	Short: "Aggregate single-node JSON reports into a cluster-level summary",
	Long: `Build a cluster-level conclusion from already-generated single-node kube-bench
JSON reports. The command never re-runs checks and never connects to scanned
nodes: it only reads the report files given to it.

Controls are aligned by control number and benchmark version, never by title.
A control absent from a node's report counts as uncovered for that node, not
as a pass. Repeated reports for the same source are de-duplicated by keeping
the newest file, and every duplicate source is listed in the output.`,
	Run: func(cmd *cobra.Command, args []string) {
		refs, err := parseReportRefs(aggregateReportSpecs)
		if err != nil {
			exitWithError(err)
		}

		summary, err := aggregate.Aggregate(refs, aggregateExpected)
		if summary != nil {
			out, mErr := json.MarshalIndent(summary, "", "  ")
			if mErr != nil {
				exitWithError(fmt.Errorf("failed to encode aggregate result: %v", mErr))
			}
			// printOutput appends exactly one trailing newline on both stdout
			// and file paths, keeping the two byte-identical.
			printOutput(string(out), outputFile)

			for _, pe := range summary.ParseErrors {
				fmt.Fprintf(os.Stderr, "warning: report from source %q (%s) could not be parsed: %s\n",
					pe.Source, pe.Path, pe.Error)
			}
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "aggregation failed: %v\n", err)
			osExit(aggregateExitAllFailed)
			return
		}
		if len(summary.ParseErrors) > 0 {
			osExit(aggregateExitPartialFail)
			return
		}
		osExit(0)
	},
}

// parseReportRefs turns "<source>=<path>" arguments into ReportRefs. A bare
// path without an explicit source binding is an error, never a guess.
func parseReportRefs(specs []string) ([]aggregate.ReportRef, error) {
	var refs []aggregate.ReportRef
	seen := map[string]bool{}
	for _, spec := range specs {
		idx := strings.IndexByte(spec, '=')
		if idx <= 0 {
			return nil, fmt.Errorf(
				"invalid --report value %q: expected \"<source>=<path>\"; every report needs an explicit source identifier",
				spec)
		}
		source := strings.TrimSpace(spec[:idx])
		path := spec[idx+1:]
		if source == "" || path == "" {
			return nil, fmt.Errorf(
				"invalid --report value %q: source and path must both be non-empty", spec)
		}
		key := source + "=" + path
		if seen[key] {
			return nil, fmt.Errorf("duplicate --report entry: %s", key)
		}
		seen[key] = true
		refs = append(refs, aggregate.ReportRef{Source: source, Path: path})
	}
	if len(refs) == 0 {
		return nil, fmt.Errorf("no reports supplied: pass at least one --report <source>=<path>")
	}
	return refs, nil
}
