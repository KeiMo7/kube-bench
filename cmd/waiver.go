package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aquasecurity/kube-bench/check"
	"gopkg.in/yaml.v2"
)

var (
	// waiverFile is the --waivers path, empty when the feature is unused.
	waiverFile string
	// waiverSet is loaded once per invocation.
	waiverSet *check.WaiverSet
	// waiverScopes records every controls file that belongs to the selected
	// benchmark, whether or not it is selected to run. Waivers are validated
	// against the benchmark definition, so using --targets or --check does not
	// turn a legitimate waiver into an "unknown check" error.
	waiverScopes []check.Scope
	// waiverResult keeps the post-processing outcome for reporting.
	waiverResult check.ApplyResult
	// waiverLoaded guards against loading/validating twice.
	waiverLoaded bool
	// waiverNow is injectable so tests can exercise expiry deterministically.
	waiverNow = time.Now
	// waiverBenchmark is the resolved benchmark version for reporting.
	waiverBenchmark string
	// exitWithErrorFunc lets tests observe fatal paths without os.Exit.
	exitWithErrorFunc = exitWithError
)

// initWaivers loads and validates the waiver file when one was supplied. A
// missing, unreadable or malformed file is a hard error: silently ignoring it
// would let the run look cleaner than it is.
func initWaivers() {
	if waiverLoaded {
		return
	}
	waiverLoaded = true
	if waiverFile == "" {
		return
	}

	set, err := check.LoadWaivers(waiverFile)
	if err != nil {
		exitWithErrorFunc(err)
	}
	waiverSet = set
}

// prepareWaiverScopes walks the controls files of the selected benchmark and
// records the check inventory. It is a no-op without a waiver file, and its
// failure is fatal because an unreadable benchmark definition makes waiver
// validation meaningless.
func prepareWaiverScopes(benchmarkVersion string) {
	if waiverSet == nil {
		return
	}
	waiverBenchmark = benchmarkVersion
	dir := filepath.Join(cfgDir, benchmarkVersion)

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		name := info.Name()
		if name == "config.yaml" || filepath.Ext(name) != ".yaml" {
			return nil
		}

		in, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var controls check.Controls
		if err := yaml.Unmarshal(in, &controls); err != nil {
			return fmt.Errorf("unable to parse %s for waiver validation: %w", path, err)
		}
		if controls.Type == "" {
			controls.Type = check.NodeType(strings.TrimSuffix(name, ".yaml"))
		}
		waiverScopes = append(waiverScopes, check.NewScope(&controls))
		return nil
	})
	if err != nil {
		exitWithErrorFunc(fmt.Errorf("unable to build waiver validation scope from %s: %v", dir, err))
	}
	// An empty inventory would turn every waiver into a "benchmark was not
	// selected" diagnostic instead of validating it. Refuse to continue.
	if len(waiverScopes) == 0 {
		exitWithErrorFunc(fmt.Errorf(
			"unable to build waiver validation scope: no controls files found in %s", dir))
	}
}

// applyWaivers reclassifies results once every check has executed. Unknown
// check references abort the run; expired, duplicate and conflicting entries
// are surfaced as diagnostics.
func applyWaivers() {
	if waiverSet == nil {
		return
	}

	result, err := waiverSet.Apply(controlsCollection, waiverScopes, waiverNow())
	// Diagnostics explain both the failure and any non-fatal oddity; print them
	// before aborting so the operator can see exactly which entries clash.
	for _, d := range result.Diagnostics {
		fmt.Fprintf(os.Stderr, "[WARN] waiver: %s\n", d)
	}
	if err != nil {
		exitWithErrorFunc(fmt.Errorf("waiver validation failed: %v", err))
	}
	waiverResult = result
}

func waiverReport() *check.WaiverReport {
	if waiverSet == nil {
		return nil
	}
	return &check.WaiverReport{
		File:          waiverSet.File(),
		Benchmark:     waiverBenchmark,
		Total:         waiverSet.Len(),
		Applied:       waiverResult.Applied,
		AcceptedRisk:  waiverResult.AcceptedRisk,
		NotApplicable: waiverResult.NotApplicable,
		Diagnostics:   waiverResult.Diagnostics,
	}
}
