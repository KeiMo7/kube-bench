package cmd

import (
	"fmt"
	"os"

	"github.com/aquasecurity/kube-bench/internal/diff"
	"github.com/spf13/cobra"
)

var (
	compareOlderFile  string
	compareNewerFile  string
	compareOutputFile string
	compareTextFmt    bool
	compareMaxEntries int
)

func init() {
	RootCmd.AddCommand(compareCmd)
	compareCmd.Flags().StringVar(&compareOlderFile, "older", "", "Path to the pre-upgrade kube-bench JSON report")
	compareCmd.Flags().StringVar(&compareNewerFile, "newer", "", "Path to the post-upgrade kube-bench JSON report")
	compareCmd.Flags().StringVarP(&compareOutputFile, "outputfile", "o", "", "Write the comparison result to a file instead of stdout")
	compareCmd.Flags().BoolVar(&compareTextFmt, "text", false, "Emit a human-readable text report instead of JSON")
	compareCmd.Flags().IntVar(&compareMaxEntries, "max-entries", diff.DefaultMaxEntries,
		"Maximum number of difference entries to emit; excess entries are truncated and marked in the summary")
}

// compareCmd compares two kube-bench JSON reports and attributes the
// differences using the rule fingerprints recorded in the reports.
var compareCmd = &cobra.Command{
	Use:   "compare",
	Short: "Compare two kube-bench JSON reports",
	Long: `Compare a pre-upgrade and a post-upgrade kube-bench JSON report.

Differences are attributed solely from the rule fingerprints (check ID,
decision condition and rule set version) recorded inside the reports:
config_change, rule_change, added, removed, coverage_change, incomparable
or unattributable. Added, removed, coverage_change, incomparable and
unattributable entries never count as improvements or regressions.`,
	Run: func(cmd *cobra.Command, args []string) {
		if compareOlderFile == "" || compareNewerFile == "" {
			exitWithError(fmt.Errorf("both --older and --newer report paths are required"))
		}

		olderRaw, err := os.ReadFile(compareOlderFile)
		if err != nil {
			exitWithError(fmt.Errorf("cannot read older report: %v", err))
		}
		newerRaw, err := os.ReadFile(compareNewerFile)
		if err != nil {
			exitWithError(fmt.Errorf("cannot read newer report: %v", err))
		}

		report, err := diff.Compare(olderRaw, newerRaw, diff.Options{MaxEntries: compareMaxEntries})
		if err != nil {
			// Includes unrecognised report structures: refuse rather than
			// guessing.
			exitWithError(fmt.Errorf("comparison refused: %v", err))
		}

		var out string
		if compareTextFmt {
			out = diff.RenderText(report)
		} else {
			raw, mErr := marshalCompareJSON(report)
			if mErr != nil {
				exitWithError(fmt.Errorf("failed to marshal comparison: %v", mErr))
			}
			out = string(raw)
		}
		printOutput(out, compareOutputFile)
	},
}
