// Command compare-demo generates two kube-bench JSON reports against the real
// k3s-cis-1.10 and k3s-cis-1.11 rule sets, simulating one machine whose
// on-disk configuration does not change between scans. A deterministic stub
// runner stands in for the machine audit (the checks' audit commands need a
// live k3s node), but every rule definition, fingerprint and report field is
// produced through the real kube-bench code path.
//
// Scenario baked into the stub:
//   - check 1.1.20 (PKI certificate permissions): the rule tightens/changes
//     from bitmask 600 (1.10, manual) to bitmask 644 (1.11, automated) while
//     the file on disk stays 644. The status flips PASS->FAIL and must be
//     attributed to the rule change.
//   - check 1.2.30 exists only in 1.11 => "added", not a new failure.
//   - check 1.1.21 is identical in both rule sets and keeps the same result
//     => no diff entry.
//   - check 1.1.1 has identical fingerprints and flips FAIL->PASS => a real
//     config improvement.
//   - the etcd role is covered only by the older run => coverage_change.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/aquasecurity/kube-bench/check"
)

// stubResult is the fixed, machine-side result the simulated node returns for
// a check. These values are identical for both rule set versions.
type stubResult struct {
	state          check.State
	actualValue    string
	expectedResult string
}

// cannedMachine is the unchanging machine configuration. Both scans read the
// same values.
var cannedMachine = map[string]stubResult{
	"1.1.1": {
		state:          check.FAIL, // overwritten per run below for the flip
		actualValue:    "permissions=644\n",
		expectedResult: "bitmask '600'",
	},
	"1.1.20": {
		state:          check.PASS,
		actualValue:    "permissions=644\n",
		expectedResult: "bitmask '600'",
	},
	"1.1.21": {
		state:          check.PASS,
		actualValue:    "permissions=600\n",
		expectedResult: "bitmask '600'",
	},
	"2.1": {
		state:          check.WARN,
		actualValue:    "",
		expectedResult: "'{.client-transport-security.cert-file}' is equal to '/var/lib/rancher/k3s/server/tls/etcd/server-client.crt'",
	},
}

// forcedStatus lets the scenario flip one check (1.1.1) between runs to
// demonstrate a genuine configuration change, while every other machine value
// stays constant.
var forcedStatus = map[string]map[string]check.State{}

type stubRunner struct{ version string }

func (s stubRunner) Run(c *check.Check) check.State {
	// Fingerprints are attached by RunChecks before Run is invoked; verify
	// they are present so the demo exercises the real report enrichment.
	if c.RuleFingerprint == nil {
		fmt.Fprintf(os.Stderr, "demo: check %s has no fingerprint\n", c.ID)
		os.Exit(2)
	}

	// The 1.1.20 rule flips state purely because its decision condition
	// changed (600/manual -> 644/automated) while the file stays 644.
	if c.ID == "1.1.20" {
		if s.version == "k3s-cis-1.10" {
			c.State = check.PASS
			c.ActualValue = "permissions=644\n"
			c.ExpectedResult = "bitmask '600'"
			return check.PASS
		}
		c.State = check.FAIL
		c.ActualValue = "permissions=644\n"
		c.ExpectedResult = "bitmask '644'"
		return check.FAIL
	}

	res, ok := cannedMachine[c.ID]
	if !ok {
		// Deterministic default for any check not explicitly scripted.
		c.State = check.PASS
		c.ActualValue = "permissions=600\n"
		c.ExpectedResult = "bitmask '600'"
		return check.PASS
	}

	state := res.state
	if byVersion, ok := forcedStatus[c.ID]; ok {
		if st, ok := byVersion[s.version]; ok {
			state = st
		}
	}
	c.State = state
	c.ActualValue = res.actualValue
	c.ExpectedResult = res.expectedResult
	return state
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintf(os.Stderr, "usage: compare-demo <repoRoot> <outDir> <older|newer>\n")
		os.Exit(2)
	}
	repoRoot, outDir, side := os.Args[1], os.Args[2], os.Args[3]

	var version string
	var targets []string
	switch side {
	case "older":
		version = "k3s-cis-1.10"
		// Older run covered etcd; the newer run drops that role.
		targets = []string{"master", "etcd"}
		// 1.1.1 fails before the simulated remediation.
		forcedStatus["1.1.1"] = map[string]check.State{version: check.FAIL}
	case "newer":
		version = "k3s-cis-1.11"
		targets = []string{"master"}
		forcedStatus["1.1.1"] = map[string]check.State{version: check.PASS}
	default:
		fmt.Fprintf(os.Stderr, "unknown side %q\n", side)
		os.Exit(2)
	}

	overall := check.OverallControls{
		SchemaVersion: check.ReportSchemaVersion,
	}

	for _, target := range targets {
		path := filepath.Join(repoRoot, "cfg", version, target+".yaml")
		raw, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read %s: %v\n", path, err)
			os.Exit(2)
		}
		nodeType := check.NodeType(target)
		controls, err := check.NewControls(nodeType, raw, "v1.31.5+k3s1")
		if err != nil {
			fmt.Fprintf(os.Stderr, "new controls: %v\n", err)
			os.Exit(2)
		}
		controls.RuleSet = &check.RuleSetInfo{
			Version:          version,
			ProductLine:      "k3s",
			SelectionMode:    "manual",
			RequestedVersion: version,
			DetectedVersion:  "v1.31.5+k3s1",
		}
		controls.RunChecks(stubRunner{version: version},
			func(g *check.Group, c *check.Check) bool { return true },
			map[string]bool{})
		overall.Controls = append(overall.Controls, controls)
	}

	// Deterministic section ordering by numeric id, mirroring writeOutput.
	sort.Slice(overall.Controls, func(i, j int) bool {
		return overall.Controls[i].ID < overall.Controls[j].ID
	})
	for _, ctl := range overall.Controls {
		overall.Totals.Pass += ctl.Pass
		overall.Totals.Fail += ctl.Fail
		overall.Totals.Warn += ctl.Warn
		overall.Totals.Info += ctl.Info
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir: %v\n", err)
		os.Exit(2)
	}
	out := filepath.Join(outDir, side+".json")
	raw, err := json.MarshalIndent(overall, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal: %v\n", err)
		os.Exit(2)
	}
	if err := os.WriteFile(out, raw, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write: %v\n", err)
		os.Exit(2)
	}
	fmt.Printf("wrote %s (%d sections)\n", out, len(overall.Controls))
}
