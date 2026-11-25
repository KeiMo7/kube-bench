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
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/kube-bench/check"
	"github.com/aquasecurity/kube-bench/internal/baseline"
	"github.com/golang/glog"
	"github.com/spf13/viper"
)

// baselineRegistry is built once at startup when --baseline is used. The
// source keys of every result originate from the selections this registry
// produces; all later stages only carry them through.
var baselineRegistry *baseline.Registry

// buildBaselineRegistry discovers manifests in the built-in registry and in
// every explicitly provided external registry directory.
func buildBaselineRegistry(externalDirs []string) (*baseline.Registry, error) {
	registry := baseline.NewRegistry(cfgDir)
	if err := registry.LoadRoots(cfgDir); err != nil {
		return nil, err
	}
	for _, dir := range externalDirs {
		if strings.TrimSpace(dir) == "" {
			continue
		}
		if err := registry.LoadRoots(dir); err != nil {
			return nil, err
		}
	}
	baselineRegistry = registry
	return registry, nil
}

// runBaselines executes one or more family/version selections in a single
// run and writes the merged output. The legacy code path is never used when
// --baseline is set, so historical single-baseline behavior stays byte for
// byte unchanged.
func runBaselines(rawRequests []string, externalDirs []string, requestedTargets []string) error {
	registry, err := buildBaselineRegistry(externalDirs)
	if err != nil {
		return err
	}

	requests, err := parseBaselineRequests(rawRequests)
	if err != nil {
		return err
	}

	detected := detectedClusterVersionForBaselines()
	normalizer := baseline.NewNormalizer()

	// Track the controls produced per selection so the four historical
	// output formats keep working, while the normalized report carries the
	// cross-baseline merge semantics.
	var mergedControls []*check.Controls
	var selections []*baseline.Selection

	for _, req := range requests {
		familyManifest, ok := registry.Family(req.Family)
		if !ok {
			return fmt.Errorf("baseline family %q is not registered", req.Family)
		}

		targets, err := targetsForRequest(registry, familyManifest, req, detected, requestedTargets)
		if err != nil {
			return err
		}

		for _, target := range targets {
			sel, err := registry.ResolveRequest(req, target, detected)
			if err != nil {
				return err
			}
			if sel.Degraded {
				glog.Warningf("baseline fallback: %s", sel.DegradeReason)
				fmt.Fprintf(os.Stderr, "Warning: %s\n", sel.DegradeReason)
			}
			if !sel.SourceKey.Valid() {
				return fmt.Errorf("internal error: selection for %s produced an incomplete source key", req.Raw)
			}

			controls, defErrs, err := executeSelection(sel)
			if err != nil {
				return err
			}
			for _, de := range defErrs {
				normalizer.AddDefinitionError(sel.SourceKey, de.CheckID, de.Error())
			}
			if controls != nil {
				attachSourceKey(controls, sel)
				mergedControls = append(mergedControls, controls)
				selections = append(selections, sel)
				normalizer.AddControls(sel, controls)
			}
		}
	}

	report := normalizer.Report()
	writeBaselineOutput(mergedControls, report, selections)
	// Expose the collection so the shared exit-code semantics apply to
	// multi-baseline runs exactly as they do to the legacy path.
	controlsCollection = mergedControls
	return nil
}

func parseBaselineRequests(raw []string) ([]baseline.Request, error) {
	out := make([]baseline.Request, 0, len(raw))
	seen := make(map[string]bool)
	for _, r := range raw {
		req, err := baseline.ParseRequest(r)
		if err != nil {
			return nil, err
		}
		key := req.Family + "|" + req.ClusterVersion + "|" + req.DefinitionPin
		if seen[key] {
			return nil, fmt.Errorf("duplicate baseline request %q", r)
		}
		seen[key] = true
		out = append(out, req)
	}
	return out, nil
}

// detectedClusterVersionForBaselines reuses the existing detection logic.
func detectedClusterVersionForBaselines() string {
	if !isEmpty(kubeVersion) {
		return kubeVersion
	}
	if !isEmpty(detecetedKubeVersion) && detecetedKubeVersion != "none" {
		return detecetedKubeVersion
	}
	platform := getPlatformInfo()
	if !isEmpty(platform.Version) {
		detecetedKubeVersion = platform.Version
		return platform.Version
	}
	kv, err := getKubeVersion()
	if err != nil {
		return ""
	}
	detecetedKubeVersion = kv.BaseVersion()
	return kv.BaseVersion()
}

// targetsForRequest resolves the target list: an explicit --targets flag is
// validated against the manifest; otherwise all declared targets run.
func targetsForRequest(registry *baseline.Registry, m *baseline.Manifest, req baseline.Request, detected string, requested []string) ([]string, error) {
	// Resolve the entry just to validate target availability.
	probeReq := req
	if probeReq.ClusterVersion == "" && probeReq.DefinitionPin == "" {
		probeReq.ClusterVersion = detected
	}
	// Determine the chosen definition version via a probe selection on the
	// first declared target.
	entry, err := resolveEntry(registry, m, probeReq, detected)
	if err != nil {
		return nil, err
	}

	if len(requested) == 0 {
		return append([]string(nil), entry.Targets...), nil
	}

	var out []string
	for _, t := range requested {
		tt := translate(strings.ToLower(t))
		if !entry.HasTarget(tt) {
			return nil, fmt.Errorf("target %q is not available for %s/%s; available targets: %s",
				t, m.Family, entry.Version, strings.Join(entry.Targets, ","))
		}
		out = append(out, tt)
	}
	return out, nil
}

// resolveEntry returns the Baseline entry a request selects without
// requiring a target, used for target-list validation.
func resolveEntry(registry *baseline.Registry, m *baseline.Manifest, req baseline.Request, detected string) (*baseline.Baseline, error) {
	if req.DefinitionPin != "" {
		if b, ok := m.Baseline(req.DefinitionPin); ok {
			return b, nil
		}
	}
	clusterVersion := req.ClusterVersion
	if clusterVersion == "" {
		clusterVersion = req.DefinitionPin
	}
	if clusterVersion == "" {
		clusterVersion = detected
	}
	if clusterVersion == "" {
		return nil, fmt.Errorf("family %q: no cluster version available for matching", m.Family)
	}
	res, err := selectManifestVersion(m, clusterVersion)
	if err != nil {
		return nil, err
	}
	b, ok := m.Baseline(res)
	if !ok {
		return nil, fmt.Errorf("resolved version %q is not registered for family %q", res, m.Family)
	}
	return b, nil
}

// selectManifestVersion is a thin wrapper around the package's selection
// logic, handling the explicit-pin case at the cmd boundary.
func selectManifestVersion(m *baseline.Manifest, clusterVersion string) (string, error) {
	version, _, _, err := baseline.SelectVersion(m, clusterVersion)
	return version, err
}

// executeSelection loads the definition file for one selection, runs every
// check through the existing runner/filter machinery and returns the
// controls plus per-check definition errors.
func executeSelection(sel *baseline.Selection) (*check.Controls, []*check.DefinitionLoadError, error) {
	defFile := filepath.Join(sel.Definitions, sel.Target+".yaml")
	in, err := os.ReadFile(defFile)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: cannot read definition for target %q: %v", sel.SourceKey, sel.Target, err)
	}

	nodeType := check.NodeType(sel.Target)

	// A per-selection viper instance keeps variable substitutions isolated
	// between baselines; the global viper instance used by the legacy path
	// is never mutated here.
	v := viper.New()
	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else {
		v.SetConfigName("config")
		v.AddConfigPath(cfgDir)
	}
	v.SetEnvPrefix(envVarsPrefix)
	v.AutomaticEnv()
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, nil, fmt.Errorf("%s: failed to read config: %v", sel.SourceKey, err)
		}
	}
	// Version-specific config next to the definitions, when present.
	versionCfg := filepath.Join(sel.Definitions, "config.yaml")
	v.SetConfigFile(versionCfg)
	if err := v.MergeInConfig(); err != nil {
		if !os.IsNotExist(err) {
			return nil, nil, fmt.Errorf("%s: failed to merge version config: %v", sel.SourceKey, err)
		}
	}

	// A target section is optional for fully self-contained external
	// definitions: when absent, substitution maps stay empty and the
	// definition's literal paths are used as-is. The legacy path keeps its
	// historical hard failure on a missing target section.
	typeConf := v.Sub(sel.Target)
	if typeConf == nil {
		typeConf = viper.New()
		glog.V(2).Infof("%s: no config section for target %q; running definitions without variable substitution",
			sel.SourceKey, sel.Target)
	}

	binmap, binErr := getBinaries(typeConf, nodeType)
	if binErr != nil {
		glog.V(1).Infof("failed to resolve binaries for %s: %v", sel.SourceKey, binErr)
	}
	s := string(in)
	s, binSubs := makeSubstitutions(s, "bin", binmap)
	s, _ = makeSubstitutions(s, "conf", getFiles(typeConf, "config"))
	s, _ = makeSubstitutions(s, "svc", getFiles(typeConf, "service"))
	s, _ = makeSubstitutions(s, "kubeconfig", getFiles(typeConf, "kubeconfig"))
	s, _ = makeSubstitutions(s, "cafile", getFiles(typeConf, "ca"))
	s, _ = makeSubstitutions(s, "datadir", getFiles(typeConf, "datadir"))

	controls, defErrs, err := check.LoadControlsTolerant(nodeType, []byte(s), detecetedKubeVersion)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %v", sel.SourceKey, err)
	}

	runner := check.NewRunner()
	filter, err := NewRunFilter(filterOpts)
	if err != nil {
		return nil, nil, fmt.Errorf("error setting up run filter: %v", err)
	}
	generateDefaultEnvAudit(controls, binSubs)
	controls.RunChecks(runner, filter, parseSkipIds(skipIds))
	return controls, defErrs, nil
}

// attachSourceKey stamps the selection's provenance onto the controls and
// every check. This is the single production point for source-key-derived
// output fields.
func attachSourceKey(controls *check.Controls, sel *baseline.Selection) {
	controls.SourceFamily = sel.Family
	controls.SourceDefinitionVersion = sel.Version
	controls.SourceTarget = sel.Target
	controls.NormalizationKey = sel.SourceKey.NormalizedKey()
	for _, g := range controls.Groups {
		for _, c := range g.Checks {
			c.SourceFamily = sel.Family
			c.SourceDefinitionVersion = sel.Version
			c.SourceTarget = sel.Target
			c.NormalizationKey = sel.SourceKey.NormalizedKey()
		}
	}
}
