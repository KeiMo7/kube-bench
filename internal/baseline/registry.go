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

package baseline

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v2"
)

const (
	// APIVersion is the supported manifest schema version.
	APIVersion = "kube-bench.io/v1alpha1"
	// Kind is the supported manifest object kind.
	Kind = "BaselineManifest"

	// manifestDir is the directory, relative to a registry root, that is
	// scanned for manifest files.
	manifestDir = "baselines"
)

// Registry holds all manifests discovered from one or more registry roots.
type Registry struct {
	// families maps family id to its manifest.
	families map[string]*Manifest
	// order records discovery order for deterministic iteration.
	order []string
	// roots are the trusted registry roots.
	roots []string
}

// LoadError reports a manifest location and a field path without echoing
// audit commands or environment variable values.
type LoadError struct {
	Location  string
	FieldPath string
	EntryID   string
	Reason    string
}

func (e *LoadError) Error() string {
	var b strings.Builder
	b.WriteString("invalid baseline manifest")
	if e.Location != "" {
		b.WriteString(" at " + e.Location)
	}
	if e.EntryID != "" {
		b.WriteString(" entry " + e.EntryID)
	}
	if e.FieldPath != "" {
		b.WriteString(" field " + e.FieldPath)
	}
	if e.Reason != "" {
		b.WriteString(": " + e.Reason)
	}
	return b.String()
}

// NewRegistry creates an empty registry rooted at the given trusted
// directories. Roots are used to confine every definition path.
func NewRegistry(roots ...string) *Registry {
	return &Registry{
		families: make(map[string]*Manifest),
		roots:    roots,
	}
}

// LoadRoots scans the "baselines" subdirectory of every trusted root for
// *.yaml / *.yml manifest files, then parses and validates them. Discovery
// order is roots in argument order, then manifest paths sorted
// lexicographically, which makes overlap tie-breaking deterministic.
func (r *Registry) LoadRoots(roots ...string) error {
	for _, root := range roots {
		absRoot, err := filepath.Abs(root)
		if err != nil {
			return &LoadError{Location: root, Reason: "cannot resolve registry root: " + err.Error()}
		}
		r.roots = append(r.roots, absRoot)
		dir := filepath.Join(absRoot, manifestDir)
		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return &LoadError{Location: dir, Reason: "cannot read registry directory: " + err.Error()}
		}

		var names []string
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			ext := strings.ToLower(filepath.Ext(e.Name()))
			if ext == ".yaml" || ext == ".yml" {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)

		for _, name := range names {
			manifestPath := filepath.Join(dir, name)
			if err := r.loadManifestFile(absRoot, manifestPath); err != nil {
				return err
			}
		}
	}
	return nil
}

// LoadManifestFile loads a single manifest file directly (used for external
// registries that point at a manifest rather than a baselines directory).
func (r *Registry) LoadManifestFile(root, manifestPath string) error {
	return r.loadManifestFile(root, manifestPath)
}

func (r *Registry) loadManifestFile(root, manifestPath string) error {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return &LoadError{Location: manifestPath, Reason: "cannot resolve registry root: " + err.Error()}
	}
	absManifest, err := filepath.EvalSymlinks(manifestPath)
	if err != nil {
		return &LoadError{Location: manifestPath, Reason: "manifest cannot be read: " + err.Error()}
	}
	if !withinRoot(absRoot, absManifest) {
		return &LoadError{Location: manifestPath, Reason: "manifest location escapes registry root"}
	}

	raw, err := os.ReadFile(absManifest)
	if err != nil {
		return &LoadError{Location: manifestPath, Reason: "manifest cannot be read: " + err.Error()}
	}

	var m Manifest
	if err := yaml.Unmarshal(raw, &m); err != nil {
		return &LoadError{Location: manifestPath, Reason: "manifest is not valid YAML: " + err.Error()}
	}
	m.origin = absManifest
	m.index = len(r.order)

	if err := r.validate(&m, absRoot); err != nil {
		return err
	}

	if existing, dup := r.families[m.Family]; dup {
		return &LoadError{
			Location: manifestPath,
			EntryID:  m.Family,
			Reason:   fmt.Sprintf("family already registered by %s; duplicate registration is not allowed", existing.origin),
		}
	}
	r.families[m.Family] = &m
	r.order = append(r.order, m.Family)
	return nil
}

func (r *Registry) validate(m *Manifest, root string) error {
	loc := m.origin
	if m.APIVersion != APIVersion {
		return &LoadError{Location: loc, FieldPath: "apiVersion", Reason: "must be " + APIVersion}
	}
	if m.Kind != Kind {
		return &LoadError{Location: loc, FieldPath: "kind", Reason: "must be " + Kind}
	}
	if strings.TrimSpace(m.Family) == "" {
		return &LoadError{Location: loc, FieldPath: "family", Reason: "must not be empty"}
	}
	if strings.ContainsAny(m.Family, `/\`) {
		return &LoadError{Location: loc, FieldPath: "family", Reason: "must not contain path separators"}
	}
	if len(m.Baselines) == 0 {
		return &LoadError{Location: loc, FieldPath: "baselines", EntryID: m.Family, Reason: "at least one baseline entry is required"}
	}

	seenVersions := make(map[string]bool)
	seenNormKeys := make(map[string]bool)
	for i := range m.Baselines {
		b := &m.Baselines[i]
		b.declarationOrder = i
		if strings.TrimSpace(b.Version) == "" {
			return &LoadError{Location: loc, FieldPath: fmt.Sprintf("baselines[%d].version", i), EntryID: m.Family, Reason: "must not be empty"}
		}
		if seenVersions[b.Version] {
			return &LoadError{Location: loc, FieldPath: fmt.Sprintf("baselines[%d].version", i), EntryID: b.Version, Reason: "duplicate version within family"}
		}
		seenVersions[b.Version] = true

		if len(b.Versions) == 0 {
			return &LoadError{Location: loc, FieldPath: fmt.Sprintf("baselines[%d].versions", i), EntryID: b.Version, Reason: "at least one version expression is required"}
		}
		for _, expr := range b.Versions {
			if _, err := parseMatcher(expr, i); err != nil {
				return &LoadError{Location: loc, FieldPath: fmt.Sprintf("baselines[%d].versions", i), EntryID: b.Version, Reason: err.Error()}
			}
		}

		if len(b.Targets) == 0 {
			return &LoadError{Location: loc, FieldPath: fmt.Sprintf("baselines[%d].targets", i), EntryID: b.Version, Reason: "at least one target is required"}
		}

		if strings.TrimSpace(b.Definitions) == "" {
			return &LoadError{Location: loc, FieldPath: fmt.Sprintf("baselines[%d].definitions", i), EntryID: b.Version, Reason: "must not be empty"}
		}
		// Resolve and confine the definition directory up front so that a
		// malicious path fails at load time, never at execution time.
		safeDef, err := r.safeResolve(root, m.origin, b.Definitions)
		if err != nil {
			return &LoadError{Location: loc, FieldPath: fmt.Sprintf("baselines[%d].definitions", i), EntryID: b.Version, Reason: sanitizePathReason(err)}
		}
		b.Definitions = safeDef

		if b.Config != "" {
			safeCfg, err := r.safeResolve(root, m.origin, b.Config)
			if err != nil {
				return &LoadError{Location: loc, FieldPath: fmt.Sprintf("baselines[%d].config", i), EntryID: b.Version, Reason: sanitizePathReason(err)}
			}
			b.Config = safeCfg
		}

		key := m.normalizationKey(b)
		if seenNormKeys[key] {
			return &LoadError{Location: loc, FieldPath: fmt.Sprintf("baselines[%d].normalizationKey", i), EntryID: b.Version, Reason: "duplicate normalization key " + key}
		}
		seenNormKeys[key] = true
	}

	if m.Default != "" && !m.declaresVersion(m.Default) {
		return &LoadError{Location: loc, FieldPath: "default", EntryID: m.Default, Reason: "default must reference a registered version"}
	}
	return nil
}

// safeResolve resolves a path declared in a manifest against the manifest's
// directory when relative, then verifies (after symlink evaluation) that the
// result stays inside the trusted registry root. No write is ever performed
// on the definition tree.
func (r *Registry) safeResolve(root, manifestPath, declared string) (string, error) {
	base := declared
	if !filepath.IsAbs(base) {
		base = filepath.Join(filepath.Dir(manifestPath), declared)
	}
	abs, err := filepath.Abs(filepath.Clean(base))
	if err != nil {
		return "", fmt.Errorf("cannot resolve path: %v", err)
	}

	// Evaluate symlinks on every existing component. EvalSymlinks requires
	// the leaf to exist; a not-yet-existing definition directory is still
	// checked lexically.
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		if os.IsNotExist(err) {
			resolved = abs
		} else {
			return "", fmt.Errorf("cannot evaluate path: %v", err)
		}
	}

	rootAbs, err := filepath.EvalSymlinks(root)
	if err != nil {
		rootAbs = root
	}
	if !withinRoot(rootAbs, resolved) {
		return "", fmt.Errorf("path %q escapes registry root", declared)
	}
	return resolved, nil
}

// withinRoot reports whether target is root or located beneath it. Both
// arguments must be cleaned absolute paths.
func withinRoot(root, target string) bool {
	if root == target {
		return true
	}
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	if strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." {
		return false
	}
	return !filepath.IsAbs(rel)
}

// sanitizePathReason turns a path resolution error into a category message
// that never echoes the declared path: manifests may reference environment
// variable names or audit-related paths, and load errors must be limited to
// the manifest location and entry identifier.
func sanitizePathReason(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "escapes registry root"):
		return "declared path escapes registry root"
	case strings.Contains(msg, "cannot evaluate path"):
		return "declared path cannot be evaluated"
	case strings.Contains(msg, "cannot resolve path"):
		return "declared path cannot be resolved"
	default:
		return "invalid declared path"
	}
}

// Family returns the manifest of a family, if registered.
func (r *Registry) Family(family string) (*Manifest, bool) {
	m, ok := r.families[family]
	return m, ok
}

// Families returns manifests in deterministic discovery order.
func (r *Registry) Families() []*Manifest {
	out := make([]*Manifest, 0, len(r.order))
	for _, id := range r.order {
		out = append(out, r.families[id])
	}
	return out
}

// FamilyForPlatform returns the manifest declaring the given platform name,
// including platform names that were unknown at compile time.
func (r *Registry) FamilyForPlatform(platform string) (*Manifest, bool) {
	if platform == "" {
		return nil, false
	}
	for _, id := range r.order {
		m := r.families[id]
		for _, p := range m.Platforms {
			if p == platform {
				return m, true
			}
		}
	}
	return nil, false
}

// Baseline returns one declared definition version of a family.
func (m *Manifest) Baseline(version string) (*Baseline, bool) {
	for i := range m.Baselines {
		if m.Baselines[i].Version == version {
			return &m.Baselines[i], true
		}
	}
	return nil, false
}

func (m *Manifest) normalizationKey(b *Baseline) string {
	if b.NormalizationKey != "" {
		return b.NormalizationKey
	}
	return m.Family + "/" + b.Version
}

// NormalizationKey exposes the resolved normalization key for an entry.
func (m *Manifest) NormalizationKey(b *Baseline) string {
	return m.normalizationKey(b)
}

// DefinitionFile returns the safe absolute path of the check definition
// file for a target. The caller never re-derives paths itself.
func (b *Baseline) DefinitionFile(target string) string {
	return filepath.Join(b.Definitions, target+".yaml")
}

// HasTarget reports whether the target is declared available.
func (b *Baseline) HasTarget(target string) bool {
	for _, t := range b.Targets {
		if t == target {
			return true
		}
	}
	return false
}
