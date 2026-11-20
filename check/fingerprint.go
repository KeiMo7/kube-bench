// Copyright © 2026 Aqua Security Software Ltd. <info@aquasec.com>
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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// ReportSchemaVersion identifies the on-disk JSON report structure. It is
// attached additively to reports so consumers (including the report
// comparison engine) can recognise the report structure without guessing.
const ReportSchemaVersion = "kube-bench-report-v1"

// RuleFingerprint is the stable identity of the rule that produced a check
// result. Attribution of differences between two scans is based solely on
// these three elements recorded in the reports themselves:
//   - the check identifier (CheckID)
//   - the decision condition that was evaluated (ConditionHash / Condition)
//   - the rule set version the check belongs to (RuleSetVersion)
//
// The fingerprint never contains machine output, file contents or key
// material: Condition is a canonical rendering of the rule definition only.
type RuleFingerprint struct {
	// CheckID is the identifier of the check, e.g. "1.1.20".
	CheckID string `json:"check_id"`
	// ConditionHash is a SHA-256 hex digest of the canonical decision
	// condition (test items, compare operators/values, check type, scored).
	ConditionHash string `json:"condition_hash"`
	// Condition is the canonical JSON rendering that ConditionHash is
	// computed from. It is kept alongside the hash so a human reviewer can
	// see exactly which decision condition changed without any external
	// documentation.
	Condition string `json:"condition"`
	// RuleSetVersion is the benchmark rule set version the check came from,
	// e.g. "k3s-cis-1.10".
	RuleSetVersion string `json:"rule_set_version"`
}

// canonicalCondition is the rule-definition-only view of a check's decision
// logic. Runtime fields (state, actual value, audit output, ...) are
// deliberately excluded so the rendering only changes when the rule itself
// changes.
type canonicalCondition struct {
	Type      string          `json:"type"`
	Scored    bool            `json:"scored"`
	BinOp     string          `json:"bin_op,omitempty"`
	TestItems []canonicalTest `json:"test_items"`
}

type canonicalTest struct {
	Flag    string           `json:"flag,omitempty"`
	Env     string           `json:"env,omitempty"`
	Path    string           `json:"path,omitempty"`
	Set     bool             `json:"set"`
	Compare canonicalCompare `json:"compare,omitempty"`
}

type canonicalCompare struct {
	Op    string `json:"op,omitempty"`
	Value string `json:"value,omitempty"`
}

// ComputeFingerprint builds the RuleFingerprint for this check. The rule set
// version is supplied by the caller because the check itself does not know
// which rule set it was loaded from.
func (c *Check) ComputeFingerprint(ruleSetVersion string) *RuleFingerprint {
	cond := canonicalCondition{
		Type:   c.Type,
		Scored: c.Scored,
	}
	if c.Tests != nil {
		if c.Tests.BinOp != "" {
			cond.BinOp = string(c.Tests.BinOp)
		}
		for _, item := range c.Tests.TestItems {
			if item == nil {
				continue
			}
			cond.TestItems = append(cond.TestItems, canonicalTest{
				Flag: item.Flag,
				Env:  item.Env,
				Path: item.Path,
				Set:  item.Set,
				Compare: canonicalCompare{
					Op:    item.Compare.Op,
					Value: item.Compare.Value,
				},
			})
		}
	}

	// json.Marshal on a fixed struct with deterministic slice order gives a
	// stable rendering across runs; no maps are involved, so no sorting is
	// needed and the same inputs always produce the same output.
	raw, err := json.Marshal(cond)
	if err != nil {
		// Marshal on this closed struct cannot realistically fail; fall back
		// to the zero rendering rather than dropping the fingerprint.
		raw = []byte("{}")
	}

	sum := sha256.Sum256(raw)
	return &RuleFingerprint{
		CheckID:        c.ID,
		ConditionHash:  hex.EncodeToString(sum[:]),
		Condition:      string(raw),
		RuleSetVersion: ruleSetVersion,
	}
}
