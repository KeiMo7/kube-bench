package diff

import "encoding/json"

// fixtureBuilder assembles kube-bench-shaped JSON reports for tests, including
// the additive rule fingerprint and rule set metadata emitted by modern
// kube-bench runs.
type fixtureBuilder struct {
	version   string
	product   string
	nodeTypes map[string][]*rawCheck
	ruleSet   *rawRuleSet
	noVersion bool
}

func newFixture(version string) *fixtureBuilder {
	return &fixtureBuilder{
		version:   version,
		product:   productLineOf(version),
		nodeTypes: map[string][]*rawCheck{},
	}
}

func (f *fixtureBuilder) withoutVersion() *fixtureBuilder {
	f.noVersion = true
	return f
}

func (f *fixtureBuilder) withFallback(from, to string) *fixtureBuilder {
	f.ruleSet = &rawRuleSet{
		Version:             f.version,
		ProductLine:         f.product,
		SelectionMode:       "version-mapping",
		RequestedVersion:    from,
		FallbackUsed:        true,
		FallbackFromVersion: from,
		FallbackToVersion:   to,
	}
	return f
}

// check adds a check with an explicit fingerprint.
func (f *fixtureBuilder) check(nodeType, id, status, conditionHash, expected, actual, desc string) *fixtureBuilder {
	version := f.version
	if f.noVersion {
		version = ""
	}
	c := &rawCheck{
		TestNumber:     id,
		TestDesc:       desc,
		Status:         status,
		ExpectedResult: expected,
		ActualValue:    actual,
		Fingerprint: &rawFingerprint{
			CheckID:        id,
			ConditionHash:  conditionHash,
			Condition:      `{"scored":true,"test_items":[]}`,
			RuleSetVersion: version,
		},
	}
	f.nodeTypes[nodeType] = append(f.nodeTypes[nodeType], c)
	return f
}

// legacyCheck adds a check without any fingerprint, simulating a report
// produced before rule fingerprints existed.
func (f *fixtureBuilder) legacyCheck(nodeType, id, status, expected, actual, desc string) *fixtureBuilder {
	f.nodeTypes[nodeType] = append(f.nodeTypes[nodeType], &rawCheck{
		TestNumber:     id,
		TestDesc:       desc,
		Status:         status,
		ExpectedResult: expected,
		ActualValue:    actual,
	})
	return f
}

func (f *fixtureBuilder) json() []byte {
	var sections []*rawControls
	// deterministic node type order
	nodeNames := make([]string, 0, len(f.nodeTypes))
	for n := range f.nodeTypes {
		nodeNames = append(nodeNames, n)
	}
	sortStrings(nodeNames)
	for i, n := range nodeNames {
		version := f.version
		if f.noVersion {
			version = ""
		}
		sections = append(sections, &rawControls{
			ID:       string(rune('1' + i)),
			Version:  version,
			Text:     n + " section",
			NodeType: n,
			Groups: []*rawGroup{{
				ID:     "g",
				Text:   "group",
				Checks: f.nodeTypes[n],
			}},
			RuleSet: f.ruleSet,
		})
	}
	raw, _ := json.Marshal(rawOverall{
		Controls:      sections,
		SchemaVersion: "kube-bench-report-v1",
	})
	return raw
}

// findEntry returns the entry for a check ID and whether it exists.
func findEntry(r *Report, id string) (Entry, bool) {
	for _, e := range r.Entries {
		if e.CheckID == id {
			return e, true
		}
	}
	return Entry{}, false
}
