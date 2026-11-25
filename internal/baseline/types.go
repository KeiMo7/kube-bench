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

// Package baseline implements declarative discovery, selection and
// normalization of security benchmark definitions.
//
// A baseline ("benchmark") belongs to a family (for example "cis", "eks" or
// an organization-internal family). Families and their available definition
// versions are registered through declarative YAML manifests instead of
// compile-time code. Manifests are discovered by scanning a registry
// directory at startup, so a fully external baseline only needs a manifest
// plus its check definition files.
package baseline

// Manifest is the declarative description of one baseline family. It is
// parsed from a manifest file located in a registry directory.
type Manifest struct {
	// APIVersion allows future schema evolution. Currently fixed to
	// "kube-bench.io/v1alpha1".
	APIVersion string `yaml:"apiVersion" json:"apiVersion"`
	// Kind is always "BaselineManifest".
	Kind string `yaml:"kind" json:"kind"`

	// Family is the stable identifier of the baseline family, for example
	// "cis" or "internal". It is the first layer of the normalized source
	// key and must be unique across the registry.
	Family string `yaml:"family" json:"family"`
	// DisplayName is a human readable family name.
	DisplayName string `yaml:"displayName" json:"displayName"`

	// Platforms maps a detected distribution/platform name (as produced by
	// the existing platform detection) to this family. New platform names
	// do not require any code change.
	Platforms []string `yaml:"platforms,omitempty" json:"platforms,omitempty"`

	// Default is the definition version (Baseline.Version) to fall back to
	// when a requested cluster version cannot be matched. A fallback only
	// happens when a default is explicitly declared.
	Default string `yaml:"default,omitempty" json:"default,omitempty"`

	// Baselines is the ordered list of definition versions registered for
	// this family. Declaration order is the final tie breaker for overlap
	// resolution.
	Baselines []Baseline `yaml:"baselines" json:"baselines"`

	// origin is the location of the manifest file inside the registry, used
	// for deterministic ordering and error messages. It is not serialized.
	origin string
	// index is the manifest's position in the global discovery order.
	index int
}

// Baseline declares one definition version of a family.
type Baseline struct {
	// Version is the definition version identifier, for example "1.24" or
	// "internal-2025.1". Together with the family it uniquely identifies a
	// set of definitions.
	Version string `yaml:"version" json:"version"`
	// DisplayName is a human readable description of this version.
	DisplayName string `yaml:"displayName,omitempty" json:"displayName,omitempty"`
	// Versions declares the cluster/platform version ranges this
	// definition version applies to. Entries may be exact versions
	// ("1.24"), wildcard versions ("1.*") or inclusive ranges
	// ("1.22-1.24", "[1.22,1.24]").
	Versions []string `yaml:"versions" json:"versions"`
	// Targets is the exhaustive list of check targets available for this
	// definition version (master, node, etcd, ...).
	Targets []string `yaml:"targets" json:"targets"`
	// Definitions is the location of the definition directory holding the
	// per-target YAML files. Relative paths resolve against the manifest
	// location and are confined to the registry root.
	Definitions string `yaml:"definitions" json:"definitions"`
	// NormalizationKey is the key used to namespace normalized results. It
	// defaults to "<family>/<version>" when empty.
	NormalizationKey string `yaml:"normalizationKey,omitempty" json:"normalizationKey,omitempty"`
	// Config optionally points at a config.yaml holding variable
	// substitutions for this definition version.
	Config string `yaml:"config,omitempty" json:"config,omitempty"`

	// declarationOrder is the position of this entry inside the manifest.
	declarationOrder int
}

// SourceKey is the three-layer provenance key attached to every normalized
// result. All three layers are mandatory: a result missing any layer is
// invalid. The key is produced exactly once (at load time) and only passed
// through filtering, execution, normalization and output stages.
type SourceKey struct {
	Family  string `json:"family"`
	Version string `json:"definition_version"`
	Target  string `json:"target"`
}

// Valid reports whether all three layers of the source key are present.
func (k SourceKey) Valid() bool {
	return k.Family != "" && k.Version != "" && k.Target != ""
}

// String renders the key as a stable, slash-separated identifier.
func (k SourceKey) String() string {
	return k.Family + "/" + k.Version + "/" + k.Target
}

// NormalizedKey returns the two-layer family/version normalization key of
// the entry owning this source key.
func (k SourceKey) NormalizedKey() string {
	return k.Family + "/" + k.Version
}
