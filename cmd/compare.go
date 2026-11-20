package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/aquasecurity/kube-bench/check"
	"github.com/spf13/cobra"
)

var (
	compareBeforeFile string
	compareAfterFile  string
)

var compareCmd = &cobra.Command{
	Use:   "compare",
	Short: "Compare two kube-bench JSON scans",
	Long:  "Compare two kube-bench JSON scans. Reports are marked as not comparable when benchmark or check versions differ.",
	Run: func(cmd *cobra.Command, args []string) {
		before, err := loadScanResults(compareBeforeFile)
		if err != nil {
			exitWithError(fmt.Errorf("unable to load before scan: %v", err))
		}
		after, err := loadScanResults(compareAfterFile)
		if err != nil {
			exitWithError(fmt.Errorf("unable to load after scan: %v", err))
		}

		report := check.CompareScans(before, after)
		if jsonFmt {
			out, err := json.Marshal(report)
			if err != nil {
				exitWithError(fmt.Errorf("unable to encode comparison report: %v", err))
			}
			printOutput(string(out), outputFile)
			return
		}

		fmt.Printf("Comparison status: %s\n", report.Status)
		fmt.Printf("Baseline versions: before=%s, after=%s\n", report.BeforeBaselineVersion, report.AfterBaselineVersion)
		fmt.Printf("Check versions: before=%s, after=%s\n", report.BeforeCheckVersion, report.AfterCheckVersion)
		if !report.Comparable {
			fmt.Println(report.Message)
			return
		}
		if len(report.Items) == 0 {
			fmt.Println("No result changes.")
			return
		}
		for _, item := range report.Items {
			fmt.Printf("- %s: %s -> %s\n  %s\n", item.CheckID, item.Before, item.After, item.Explanation)
		}
	},
}

func init() {
	RootCmd.AddCommand(compareCmd)
	compareCmd.Flags().StringVar(&compareBeforeFile, "before", "", "Path to the before scan JSON report")
	compareCmd.Flags().StringVar(&compareAfterFile, "after", "", "Path to the after scan JSON report")
	_ = compareCmd.MarkFlagRequired("before")
	_ = compareCmd.MarkFlagRequired("after")
}

func loadScanResults(path string) ([]*check.Controls, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var controls []*check.Controls
	if err := json.Unmarshal(data, &controls); err == nil {
		return controls, nil
	}

	var overall check.OverallControls
	if err := json.Unmarshal(data, &overall); err != nil {
		return nil, err
	}
	if len(overall.Controls) == 0 {
		return nil, fmt.Errorf("report contains no controls")
	}
	return overall.Controls, nil
}
