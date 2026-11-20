package diff

import (
	"encoding/json"
	"fmt"
)

// ErrUnrecognisedStructure is returned when a report cannot be recognised as a
// kube-bench JSON report. The comparison engine refuses to guess in that case
// rather than producing speculative attribution.
type ErrUnrecognisedStructure struct{ detail string }

func (e *ErrUnrecognisedStructure) Error() string {
	return "unrecognised report structure: " + e.detail
}

// rawFingerprint mirrors the additive rule_fingerprint object of a check.
type rawFingerprint struct {
	CheckID        string `json:"check_id"`
	ConditionHash  string `json:"condition_hash"`
	Condition      string `json:"condition"`
	RuleSetVersion string `json:"rule_set_version"`
}

// rawCheck mirrors the check-level fields the comparison relies on.
type rawCheck struct {
	TestNumber     string          `json:"test_number"`
	TestDesc       string          `json:"test_desc"`
	Status         string          `json:"status"`
	ExpectedResult string          `json:"expected_result"`
	ActualValue    string          `json:"actual_value"`
	Fingerprint    *rawFingerprint `json:"rule_fingerprint,omitempty"`
}

// rawGroup mirrors a tests/section group.
type rawGroup struct {
	ID     string      `json:"section"`
	Text   string      `json:"desc"`
	Checks []*rawCheck `json:"results"`
}

// rawRuleSet mirrors the additive per-section rule_set object.
type rawRuleSet struct {
	Version             string `json:"version"`
	ProductLine         string `json:"product_line"`
	SelectionMode       string `json:"selection_mode"`
	RequestedVersion    string `json:"requested_version"`
	DetectedVersion     string `json:"detected_version"`
	FallbackUsed        bool   `json:"fallback_used"`
	FallbackFromVersion string `json:"fallback_from_version"`
	FallbackToVersion   string `json:"fallback_to_version"`
}

// rawControls mirrors one section (node type) of a report.
type rawControls struct {
	ID              string      `json:"id"`
	Version         string      `json:"version"`
	DetectedVersion string      `json:"detected_version"`
	Text            string      `json:"text"`
	NodeType        string      `json:"node_type"`
	Groups          []*rawGroup `json:"tests"`
	RuleSet         *rawRuleSet `json:"rule_set,omitempty"`
}

// rawOverall mirrors the top-level report with totals.
type rawOverall struct {
	Controls      []*rawControls `json:"Controls"`
	SchemaVersion string         `json:"schema_version"`
}

// parsedReport is the normalised, indexable view of one input report.
type parsedReport struct {
	meta     SideMeta
	controls []*rawControls
	// checks keyed by node type + check ID. kube-bench check IDs are unique
	// within a node type; the first occurrence wins deterministically.
	checks map[key]*rawCheck
	// owner remembers which node type a key first appeared under.
	owner map[key]string
}

type key struct {
	nodeType string
	checkID  string
}

// parseReport recognises and normalises one kube-bench JSON report. It accepts
// both the totals form ({"Controls":[...]}) and the no-totals array form.
// Unrecognised structures are rejected explicitly.
func parseReport(raw []byte) (*parsedReport, error) {
	// Decode into a raw message first to distinguish object vs array without
	// relying on a second full parse for control flow.
	var head map[string]json.RawMessage
	objErr := json.Unmarshal(raw, &head)

	var sections []*rawControls
	schema := ""
	if objErr == nil {
		controlsRaw, ok := head["Controls"]
		if !ok {
			return nil, &ErrUnrecognisedStructure{detail: "top-level object has no \"Controls\" array"}
		}
		if err := json.Unmarshal(controlsRaw, &sections); err != nil {
			return nil, &ErrUnrecognisedStructure{detail: fmt.Sprintf("cannot parse \"Controls\": %v", err)}
		}
		if sv, ok := head["schema_version"]; ok {
			_ = json.Unmarshal(sv, &schema)
		}
	} else {
		if err := json.Unmarshal(raw, &sections); err != nil {
			return nil, &ErrUnrecognisedStructure{detail: "neither a report object nor a controls array: " + err.Error()}
		}
	}

	if len(sections) == 0 {
		return nil, &ErrUnrecognisedStructure{detail: "report contains no control sections"}
	}
	for i, c := range sections {
		if c == nil || c.NodeType == "" || len(c.Groups) == 0 {
			return nil, &ErrUnrecognisedStructure{
				detail: fmt.Sprintf("section %d is missing node_type or tests", i),
			}
		}
	}

	p := &parsedReport{
		controls: sections,
		checks:   make(map[key]*rawCheck),
		owner:    make(map[key]string),
	}

	versionSeen := map[string]bool{}
	nodeSeen := map[string]bool{}
	var firstRuleSet *rawRuleSet
	missingVersion := false

	for _, c := range sections {
		if c.Version == "" {
			missingVersion = true
		} else {
			versionSeen[c.Version] = true
		}
		nodeSeen[c.NodeType] = true
		if c.RuleSet != nil && firstRuleSet == nil {
			firstRuleSet = c.RuleSet
		}
		for _, g := range c.Groups {
			if g == nil {
				continue
			}
			for _, chk := range g.Checks {
				if chk == nil || chk.TestNumber == "" {
					return nil, &ErrUnrecognisedStructure{
						detail: fmt.Sprintf("section %q contains a check without test_number", c.NodeType),
					}
				}
				k := key{nodeType: c.NodeType, checkID: chk.TestNumber}
				if _, exists := p.checks[k]; !exists {
					p.checks[k] = chk
					p.owner[k] = c.NodeType
				}
			}
		}
	}

	versions := sortedKeys(versionSeen)
	nodeTypes := sortedKeys(nodeSeen)
	p.meta = SideMeta{
		RuleSetVersions: versions,
		NodeTypes:       nodeTypes,
		MissingVersion:  missingVersion,
		CheckCount:      len(p.checks),
	}
	if len(versions) > 0 {
		p.meta.RuleSetVersion = versions[0]
	}
	if len(versions) > 0 {
		p.meta.ProductLine = productLineOf(versions[0])
	}
	if firstRuleSet != nil {
		p.meta.RuleSet = &RuleSetMeta{
			Version:             firstRuleSet.Version,
			ProductLine:         firstRuleSet.ProductLine,
			SelectionMode:       firstRuleSet.SelectionMode,
			RequestedVersion:    firstRuleSet.RequestedVersion,
			DetectedVersion:     firstRuleSet.DetectedVersion,
			FallbackUsed:        firstRuleSet.FallbackUsed,
			FallbackFromVersion: firstRuleSet.FallbackFromVersion,
			FallbackToVersion:   firstRuleSet.FallbackToVersion,
		}
	}
	_ = schema
	return p, nil
}

// productLineOf derives the benchmark product line from a rule set version.
// "k3s-cis-1.10" -> "k3s", "cis-1.10" -> "cis", "eks-1.8.0" -> "eks",
// "cis-1.24-microk8s" -> "cis".
func productLineOf(ruleSetVersion string) string {
	v := ruleSetVersion
	const microk8s = "-microk8s"
	if len(v) > len(microk8s) && v[len(v)-len(microk8s):] == microk8s {
		v = v[:len(v)-len(microk8s)]
	}
	for i := 0; i < len(v); i++ {
		if v[i] == '-' {
			return v[:i]
		}
	}
	return v
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sortStrings(out)
	return out
}
