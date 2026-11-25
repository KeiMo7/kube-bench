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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const validManifest = `apiVersion: kube-bench.io/v1alpha1
kind: BaselineManifest
family: internal
displayName: Internal
platforms:
  - internal
default: v1
baselines:
  - version: v1
    versions: ["1.30-1.32"]
    targets: [master, node]
    definitions: ../defs/v1
`

// writeRegistry creates a registry root with a baselines directory and
// returns its path.
func writeRegistry(t *testing.T, root string, files map[string]string) string {
	t.Helper()
	baseDir := filepath.Join(root, "baselines")
	require.NoError(t, os.MkdirAll(baseDir, 0o755))
	for name, content := range files {
		require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(baseDir, name)), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(baseDir, name), []byte(content), 0o644))
	}
	// Definition directory referenced by validManifest.
	require.NoError(t, os.MkdirAll(filepath.Join(root, "defs", "v1"), 0o755))
	return root
}

func TestRegistryDiscovery(t *testing.T) {
	root := t.TempDir()
	writeRegistry(t, root, map[string]string{
		"a.yaml":     validManifest,
		"ignore.txt": "not a manifest",
	})

	r := NewRegistry(root)
	require.NoError(t, r.LoadRoots(root))

	m, ok := r.Family("internal")
	require.True(t, ok)
	assert.Equal(t, "Internal", m.DisplayName)
	assert.Contains(t, r.Families(), m)

	// Platform mapping from manifest, including previously unknown names.
	pm, ok := r.FamilyForPlatform("internal")
	require.True(t, ok)
	assert.Equal(t, "internal", pm.Family)
	_, ok = r.FamilyForPlatform("unknown-platform")
	assert.False(t, ok)
}

func TestRegistryExternalNoCompileTimeRegistration(t *testing.T) {
	// The minimal external sample shipped in the repo must load directly.
	root := filepath.Join("..", "..", "examples", "external-baseline")
	r := NewRegistry(root)
	require.NoError(t, r.LoadRoots(root))

	m, ok := r.Family("internal")
	require.True(t, ok)
	require.Len(t, m.Baselines, 1)
	b := m.Baselines[0]
	assert.Equal(t, "internal-2025.1", b.Version)
	assert.True(t, b.HasTarget("master"))
	assert.True(t, b.HasTarget("node"))
	assert.DirExists(t, b.Definitions)
}

func TestRegistryBuiltinManifestCoverage(t *testing.T) {
	// Every manifest shipped under cfg/baselines must validate and every
	// declared definition directory must exist.
	root := filepath.Join("..", "..", "cfg")
	r := NewRegistry(root)
	require.NoError(t, r.LoadRoots(root))

	families := r.Families()
	assert.GreaterOrEqual(t, len(families), 11)
	rootAbs, err := filepath.Abs(root)
	require.NoError(t, err)
	seenDefDirs := map[string]bool{}
	for _, m := range families {
		for _, b := range m.Baselines {
			info, err := os.Stat(b.Definitions)
			require.NoError(t, err, "family %s version %s", m.Family, b.Version)
			assert.True(t, info.IsDir())
			seenDefDirs[b.Definitions] = true
			// Every declared target must have a definition file.
			for _, target := range b.Targets {
				_, err := os.Stat(b.DefinitionFile(target))
				require.NoError(t, err, "missing %s for %s/%s", target, m.Family, b.Version)
			}
		}
	}
	// All historical definition directories must be represented.
	entries, err := os.ReadDir(root)
	require.NoError(t, err)
	var dirCount int
	for _, e := range entries {
		if e.IsDir() && e.Name() != "baselines" {
			dirCount++
			assert.True(t, seenDefDirs[filepath.Join(rootAbs, e.Name())],
				"definition directory %s is not registered by any manifest", e.Name())
		}
	}
	assert.Equal(t, 51, dirCount)
}

func TestRegistryDuplicateFamilyFails(t *testing.T) {
	root := t.TempDir()
	writeRegistry(t, root, map[string]string{
		"a.yaml": validManifest,
		"b.yaml": validManifest,
	})
	r := NewRegistry(root)
	err := r.LoadRoots(root)
	require.Error(t, err)

	var le *LoadError
	require.ErrorAs(t, err, &le)
	assert.Equal(t, "internal", le.EntryID)
	assert.Contains(t, err.Error(), "already registered")
	// Error must reference manifest locations, never audit/env content.
	assert.Contains(t, le.Location, "b.yaml")
}

func TestRegistryBrokenManifestFails(t *testing.T) {
	cases := map[string]string{
		"invalid yaml":         ":::not yaml:::\n  - [",
		"wrong apiVersion":     strings.Replace(validManifest, APIVersion, "wrong/v1", 1),
		"wrong kind":           strings.Replace(validManifest, Kind, "SomethingElse", 1),
		"missing family":       strings.Replace(validManifest, "family: internal", "family: \"\"", 1),
		"missing baselines":    "apiVersion: kube-bench.io/v1alpha1\nkind: BaselineManifest\nfamily: x\nbaselines: []\n",
		"invalid version expr": strings.Replace(validManifest, `"1.30-1.32"`, `"1.32-1.30"`, 1),
		"empty targets":        strings.Replace(validManifest, "targets: [master, node]", "targets: []", 1),
		"bad default":          strings.Replace(validManifest, "default: v1", "default: nope", 1),
		"duplicate version":    strings.Replace(validManifest, "definitions: ../defs/v1", "definitions: ../defs/v1\n  - version: v1\n    versions: [\"1.33\"]\n    targets: [master]\n    definitions: ../defs/v1", 1),
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeRegistry(t, root, map[string]string{"a.yaml": content})
			r := NewRegistry(root)
			err := r.LoadRoots(root)
			require.Error(t, err)
			var le *LoadError
			require.ErrorAs(t, err, &le)
			assert.NotEmpty(t, le.Location)
		})
	}
}

func TestRegistryPathTraversalRejected(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(outside, []byte("x"), 0o644))

	manifest := strings.Replace(validManifest, "../defs/v1", "../../"+filepath.Base(filepath.Dir(outside))+"/"+filepath.Base(outside), 1)
	writeRegistry(t, root, map[string]string{"a.yaml": manifest})
	r := NewRegistry(root)
	err := r.LoadRoots(root)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "escapes registry root")
}

func TestRegistrySymlinkEscapeRejected(t *testing.T) {
	root := t.TempDir()
	writeRegistry(t, root, map[string]string{"a.yaml": validManifest})

	// Replace the definitions directory with a symlink pointing outside
	// the registry root.
	outside := t.TempDir()
	defDir := filepath.Join(root, "defs", "v1")
	require.NoError(t, os.RemoveAll(defDir))
	require.NoError(t, os.Symlink(outside, defDir))

	r := NewRegistry(root)
	err := r.LoadRoots(root)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "escapes registry root")
}

func TestRegistryManifestSymlinkEscapeRejected(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "baselines"), 0o755))
	outsideManifest := filepath.Join(t.TempDir(), "evil.yaml")
	require.NoError(t, os.WriteFile(outsideManifest, []byte(validManifest), 0o644))
	require.NoError(t, os.Symlink(outsideManifest, filepath.Join(root, "baselines", "evil.yaml")))

	r := NewRegistry(root)
	err := r.LoadRoots(root)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "escapes registry root")
}

func TestRegistryDuplicateFamilyAcrossRootsFails(t *testing.T) {
	// A family registered by a built-in manifest and again by an external
	// registry must fail rather than silently override.
	rootA := t.TempDir()
	writeRegistry(t, rootA, map[string]string{"a.yaml": validManifest})
	rootB := t.TempDir()
	writeRegistry(t, rootB, map[string]string{"b.yaml": validManifest})

	r := NewRegistry()
	require.NoError(t, r.LoadRoots(rootA))
	err := r.LoadRoots(rootB)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already registered")
}

func TestRegistryNewFamilyDiscoveredWithoutCode(t *testing.T) {
	// A family name and platform name that exist in no compiled-in table
	// are discovered purely from the manifest.
	root := t.TempDir()
	content := strings.Replace(validManifest, "family: internal", "family: brandnew", 1)
	content = strings.Replace(content, "- internal", "- brandnew-platform", 1)
	writeRegistry(t, root, map[string]string{"a.yaml": content})

	r := NewRegistry(root)
	require.NoError(t, r.LoadRoots(root))
	m, ok := r.Family("brandnew")
	require.True(t, ok)
	pm, ok := r.FamilyForPlatform("brandnew-platform")
	require.True(t, ok)
	assert.Equal(t, m.Family, pm.Family)
}

func TestRegistryLoadErrorOmitsSensitiveContent(t *testing.T) {
	// Error text is limited to manifest location and entry identifier; it
	// must never echo audit commands or environment variable values.
	root := t.TempDir()
	secretManifest := strings.Replace(validManifest,
		"definitions: ../defs/v1",
		"definitions: ../defs/v1\n    config: /etc/secret/$AWS_SECRET_ACCESS_KEY/audit.sh", 1)
	writeRegistry(t, root, map[string]string{"a.yaml": secretManifest})
	r := NewRegistry(root)
	err := r.LoadRoots(root)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "AWS_SECRET_ACCESS_KEY")
	assert.NotContains(t, err.Error(), "audit.sh")
}
