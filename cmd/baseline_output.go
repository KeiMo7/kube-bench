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

package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aquasecurity/kube-bench/check"
	"github.com/aquasecurity/kube-bench/internal/baseline"
	"github.com/golang/glog"
)

// BaselineEnvelope is the additive JSON envelope for multi-baseline runs.
// The per-controls payload uses the exact historical serialization; the
// normalized merge view is carried alongside, never replacing it.
type BaselineEnvelope struct {
	Controls   []*check.Controls          `json:"Controls"`
	Totals     *check.Summary             `json:"Totals,omitempty"`
	Baselines  *baseline.NormalizedReport `json:"baseline_results,omitempty"`
	Selections []SelectionView            `json:"baseline_selections,omitempty"`
}

// SelectionView describes the resolved selections of a multi-baseline run.
type SelectionView struct {
	Family        string `json:"family"`
	Version       string `json:"definition_version"`
	Target        string `json:"target"`
	Degraded      bool   `json:"degraded,omitempty"`
	DegradeReason string `json:"degrade_reason,omitempty"`
}

// writeBaselineOutput dispatches to the same four historical output
// channels. Each channel keeps its legacy payload shape; the normalized
// report is attached as additive data where the channel permits it.
func writeBaselineOutput(controls []*check.Controls, report *baseline.NormalizedReport, sels []*baseline.Selection) {
	exitCode = exitCodeSelection(controls)

	switch {
	case junitFmt:
		writeBaselineJunit(controls)
	case jsonFmt:
		writeBaselineJSON(controls, report, sels)
	case pgSQL:
		writeBaselinePgsql(controls)
	case aSFF:
		writeBaselineASFF(controls)
	default:
		writeBaselineStdout(controls, report)
	}
}

func selectionViews(sels []*baseline.Selection) []SelectionView {
	out := make([]SelectionView, 0, len(sels))
	for _, s := range sels {
		out = append(out, SelectionView{
			Family:        s.Family,
			Version:       s.Version,
			Target:        s.Target,
			Degraded:      s.Degraded,
			DegradeReason: s.DegradeReason,
		})
	}
	return out
}

func writeBaselineJSON(controls []*check.Controls, report *baseline.NormalizedReport, sels []*baseline.Selection) {
	envelope := BaselineEnvelope{
		Controls:   controls,
		Baselines:  report,
		Selections: selectionViews(sels),
	}
	if !noTotals {
		totals := getSummaryTotals(controls)
		envelope.Totals = &totals
	}
	out, err := json.Marshal(envelope)
	if err != nil {
		exitWithError(fmt.Errorf("failed to output in JSON format: %v", err))
	}
	if err := printOutputAtomic(string(out), outputFile); err != nil {
		exitWithError(fmt.Errorf("failed to write JSON output: %v", err))
	}
}

func writeBaselineJunit(controls []*check.Controls) {
	prefix := "<testsuites>\n"
	suffix := "\n</testsuites>"
	var payload []byte
	for _, c := range controls {
		tempOut, err := c.JUnit()
		if err != nil {
			exitWithError(fmt.Errorf("failed to output in JUnit format: %v", err))
		}
		payload = append(payload, tempOut...)
	}
	if err := printOutputAtomic(prefix+string(payload)+suffix, outputFile); err != nil {
		exitWithError(fmt.Errorf("failed to write JUnit output: %v", err))
	}
}

func writeBaselinePgsql(controls []*check.Controls) {
	for _, c := range controls {
		out, err := c.JSON()
		if err != nil {
			exitWithError(fmt.Errorf("failed to output in Postgresql format: %v", err))
		}
		savePgsql(string(out))
	}
}

func writeBaselineASFF(controls []*check.Controls) {
	for _, c := range controls {
		out, err := c.ASFF()
		if err != nil {
			exitWithError(fmt.Errorf("failed to format findings as ASFF: %v", err))
		}
		// Batch send only after full serialization succeeds, so a failure
		// never leaves a partially reported set behind.
		if err := writeFinding(out); err != nil {
			exitWithError(fmt.Errorf("failed to output to ASFF: %v", err))
		}
	}
}

func writeBaselineStdout(controls []*check.Controls, report *baseline.NormalizedReport) {
	for _, c := range controls {
		prettyPrint(c, c.Summary)
	}
	if !noTotals {
		printSummary(getSummaryTotals(controls), "total")
	}
	if report != nil && (len(report.Conflicts) > 0 || len(report.Duplicates) > 0 || len(report.DefinitionErrors) > 0) {
		printNormalizationNotice(report)
	}
}

func printNormalizationNotice(report *baseline.NormalizedReport) {
	if report == nil {
		return
	}
	glog.V(1).Infof("normalized totals: %d independent items, %d duplicates, %d conflicts, %d definition errors",
		report.Summary.Total, report.Summary.DuplicateCount, report.Summary.ConflictCount, report.Summary.DefinitionErrors)
	if len(report.Conflicts) > 0 {
		colorPrint(check.WARN, fmt.Sprintf("== Cross-baseline semantic conflicts: %d ==\n", len(report.Conflicts)))
		for _, cf := range report.Conflicts {
			fmt.Printf("%s: %s vs %s (field %s)\n", cf.CheckID, cf.SourceA, cf.SourceB, cf.ConflictField)
		}
		fmt.Println()
	}
	if len(report.Duplicates) > 0 {
		colorPrint(check.INFO, fmt.Sprintf("== Duplicate occurrences excluded from counters: %d ==\n", len(report.Duplicates)))
		for _, d := range report.Duplicates {
			fmt.Printf("%s under %s (occurrence %d)\n", d.CheckID, d.SourceKey.String(), d.Occurrence)
		}
		fmt.Println()
	}
	if len(report.DefinitionErrors) > 0 {
		colorPrint(check.WARN, fmt.Sprintf("== Unparseable check definitions skipped: %d ==\n", len(report.DefinitionErrors)))
		for _, de := range report.DefinitionErrors {
			fmt.Printf("%s: %s\n", de.SourceKey.String(), de.EntryID)
		}
		fmt.Println()
	}
}

// printOutputAtomic writes to a temp file in the target directory and
// renames it into place, guaranteeing no partially written artifact. A
// retry therefore replaces the whole file instead of appending.
func printOutputAtomic(output, target string) error {
	if target == "" {
		fmt.Println(output)
		return nil
	}
	dir := filepath.Dir(target)
	tmp, err := os.CreateTemp(dir, ".kube-bench-output-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.WriteString(output); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	// Match the historical trailing newline behavior of Fprintln.
	if _, err := tmp.WriteString("\n"); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, target); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}
