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

package check

import (
	"fmt"

	yaml2 "gopkg.in/yaml.v2"
	yaml3 "gopkg.in/yaml.v3"
)

// DefinitionLoadError identifies one check definition that could not be
// parsed. It carries the check entry's id when recoverable, plus the group
// location inside the definition document.
type DefinitionLoadError struct {
	GroupID string
	CheckID string
	Reason  string
}

func (e *DefinitionLoadError) Error() string {
	if e.CheckID != "" {
		return fmt.Sprintf("unparseable check %q in group %q: %s", e.CheckID, e.GroupID, e.Reason)
	}
	return fmt.Sprintf("unparseable check in group %q: %s", e.GroupID, e.Reason)
}

// rawGroup mirrors the on-disk group envelope for tolerant decoding. Each
// check is kept as a raw YAML node so one bad check does not poison the
// others. Node values (not pointers) are required for yaml.v3 to populate
// sequence entries when unmarshaling into a typed struct.
type rawGroup struct {
	ID     string       `yaml:"id"`
	Type   string       `yaml:"type"`
	Text   string       `yaml:"text"`
	Checks []yaml3.Node `yaml:"checks"`
}

type rawControls struct {
	Version string     `yaml:"version"`
	ID      string     `yaml:"id"`
	Text    string     `yaml:"text"`
	Type    NodeType   `yaml:"type"`
	Groups  []rawGroup `yaml:"groups"`
}

// LoadControlsTolerant decodes a controls definition document the same way
// NewControls does, but a single unparseable check definition does not fail
// the whole document: the offending check is skipped and reported in
// defErrors while every other check remains executable. A structurally
// invalid document (wrong node type, unparseable group envelope) still
// returns an error because no partial result would be trustworthy.
//
// yaml.v3 is used only to isolate individual check nodes; each surviving
// node is re-encoded and decoded through yaml.v2 so check structs use the
// exact same decoder and tags as the legacy path.
func LoadControlsTolerant(t NodeType, in []byte, detectedVersion string) (*Controls, []*DefinitionLoadError, error) {
	var raw rawControls
	if err := yaml3.Unmarshal(in, &raw); err != nil {
		// Preserve the historical error wording produced by yaml.v2 so
		// callers relying on the legacy message keep the same behavior at
		// the document level.
		var legacy Controls
		if err2 := yaml2.Unmarshal(in, &legacy); err2 != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal YAML: %s", err2)
		}
		return nil, nil, fmt.Errorf("failed to unmarshal YAML: %s", err)
	}
	if t != raw.Type {
		return nil, nil, fmt.Errorf("non-%s controls file specified", t)
	}

	c := &Controls{
		Version:         raw.Version,
		ID:              raw.ID,
		Text:            raw.Text,
		Type:            raw.Type,
		DetectedVersion: detectedVersion,
		Groups:          make([]*Group, 0, len(raw.Groups)),
	}

	var defErrors []*DefinitionLoadError
	for _, rg := range raw.Groups {
		g := &Group{
			ID:     rg.ID,
			Type:   rg.Type,
			Text:   rg.Text,
			Checks: make([]*Check, 0, len(rg.Checks)),
		}
		for i := range rg.Checks {
			node := &rg.Checks[i]
			if node == nil || node.Kind == 0 {
				continue
			}
			// Re-serialize the isolated node and decode it with the
			// historical yaml.v2 decoder.
			nodeBytes, err := yaml3.Marshal(node)
			if err != nil {
				defErrors = append(defErrors, &DefinitionLoadError{
					GroupID: rg.ID,
					CheckID: recoverCheckID(node),
					Reason:  err.Error(),
				})
				continue
			}
			var checkItem Check
			if err := yaml2.Unmarshal(nodeBytes, &checkItem); err != nil {
				defErrors = append(defErrors, &DefinitionLoadError{
					GroupID: rg.ID,
					CheckID: recoverCheckID(node),
					Reason:  err.Error(),
				})
				continue
			}
			if checkItem.ID == "" {
				defErrors = append(defErrors, &DefinitionLoadError{
					GroupID: rg.ID,
					Reason:  "check id is empty",
				})
				continue
			}
			g.Checks = append(g.Checks, &checkItem)
		}
		c.Groups = append(c.Groups, g)
	}

	return c, defErrors, nil
}

// recoverCheckID makes a best-effort attempt to extract an "id" field from
// an otherwise unparseable check node, so error messages can name the entry
// without echoing audit commands or environment values.
func recoverCheckID(node *yaml3.Node) string {
	if node.Kind != yaml3.MappingNode {
		return ""
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == "id" {
			return node.Content[i+1].Value
		}
	}
	return ""
}
