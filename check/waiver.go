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
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

// Waiver kinds. A waiver records why a check result is allowed not to
// participate in the pass/fail conclusion; it never changes the check that was
// executed nor its raw output.
const (
	// WaiverAcceptedRisk records that the organisation knowingly accepted the
	// risk represented by the check result.
	WaiverAcceptedRisk = "accepted-risk"
	// WaiverNotApplicable records that the control does not apply to this
	// environment (for example because a managed service owns it).
	WaiverNotApplicable = "not-applicable"

	// PermanentWaiver is the expiry label used for waivers without an end date.
	PermanentWaiver = "permanent"
)

// WaiverInfo is attached to a Check whose result has been classified by an
// active waiver. It is serialized with the check in every structured output so
// that the reason, approver and expiry remain auditable.
type WaiverInfo struct {
	Name          string `json:"name,omitempty"`
	Kind          string `json:"kind"`
	Reason        string `json:"reason"`
	Requester     string `json:"requester"`
	Approver      string `json:"approver"`
	Benchmark     string `json:"benchmark"`
	NodeType      string `json:"node_type,omitempty"`
	Check         string `json:"check,omitempty"`
	Group         string `json:"group,omitempty"`
	Starts        string `json:"starts,omitempty"`
	Expires       string `json:"expires"`
	MeasuredState string `json:"measured_status,omitempty"`
}

// Summary renders the human-readable waiver annotation used by the stdout and
// JUnit reports. All output formats derive their wording from this method so
// that the same result is described consistently.
func (w *WaiverInfo) Summary() string {
	name := w.Name
	if name == "" {
		name = w.target()
	}
	return fmt.Sprintf("%s (%s): %s; requester: %s; approver: %s; expires: %s",
		name, w.Kind, w.Reason, w.Requester, w.Approver, w.Expires)
}

func (w *WaiverInfo) target() string {
	switch {
	case w.Check != "":
		return w.Check
	case w.Group != "":
		return w.Group
	default:
		return w.NodeType
	}
}

// Waiver is one entry in a waiver file.
type Waiver struct {
	Name      string `yaml:"name"`
	Benchmark string `yaml:"benchmark"`
	NodeType  string `yaml:"node_type"`
	Check     string `yaml:"check"`
	Group     string `yaml:"group"`
	Kind      string `yaml:"kind"`
	Reason    string `yaml:"reason"`
	Requester string `yaml:"requester"`
	Approver  string `yaml:"approver"`
	Starts    string `yaml:"starts"`
	Expires   string `yaml:"expires"`
}

// WaiverFile is the on-disk representation of a waiver file.
type WaiverFile struct {
	// Benchmark is the default benchmark version for entries that do not
	// specify one. Every entry is still bound to an explicit benchmark version
	// so a benchmark upgrade can never silently re-target a waiver onto a
	// different check with the same number.
	Benchmark string   `yaml:"benchmark"`
	Waivers   []Waiver `yaml:"waivers"`
}

// WaiverReport is the structured summary of a waiver run. It is only emitted
// when a waiver file was supplied.
type WaiverReport struct {
	File          string   `json:"file"`
	Benchmark     string   `json:"benchmark,omitempty"`
	Total         int      `json:"total"`
	Applied       int      `json:"applied"`
	AcceptedRisk  int      `json:"accepted_risk"`
	NotApplicable int      `json:"not_applicable"`
	Diagnostics   []string `json:"diagnostics,omitempty"`
}

type waiverEntry struct {
	Waiver
	index        int
	start        time.Time
	hasStart     bool
	end          time.Time
	hasEnd       bool
	expiresLabel string
	startsLabel  string
}

// WaiverSet is a parsed and validated waiver file.
type WaiverSet struct {
	path    string
	file    WaiverFile
	entries []*waiverEntry
}

// Scope records the checks that were available in one controls file. It is
// captured before run filtering so that a waiver for a check excluded by
// --check is still recognised as referring to a real check.
type Scope struct {
	NodeType NodeType
	Version  string
	CheckIDs map[string]bool
	GroupIDs map[string]bool
}

// NewScope builds a Scope from a fully loaded Controls object.
func NewScope(c *Controls) Scope {
	s := Scope{
		NodeType: c.Type,
		Version:  c.Version,
		CheckIDs: make(map[string]bool),
		GroupIDs: make(map[string]bool),
	}
	for _, g := range c.Groups {
		s.GroupIDs[g.ID] = true
		for _, ck := range g.Checks {
			s.CheckIDs[ck.ID] = true
		}
	}
	return s
}

// ApplyResult reports what a WaiverSet did to a run.
type ApplyResult struct {
	Applied       int
	AcceptedRisk  int
	NotApplicable int
	// Conflicts counts checks whose matching waivers contradict each other at
	// the same scope. Non-zero means the caller must fail the run.
	Conflicts   int
	Diagnostics []string
}

// LoadWaivers reads and validates a waiver file. Any read or syntax error is
// returned to the caller: an unreadable or malformed file must never degrade
// into an implicitly waiver-free (all passing) run.
func LoadWaivers(path string) (*WaiverSet, error) {
	in, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("unable to read waiver file %s: %w", path, err)
	}

	var file WaiverFile
	// UnmarshalStrict turns unknown fields and duplicate keys into errors so
	// that a typo cannot silently disable a waiver.
	if err := yaml.UnmarshalStrict(in, &file); err != nil {
		return nil, fmt.Errorf("unable to parse waiver file %s: %w", path, err)
	}

	set := &WaiverSet{path: path, file: file}
	for i, w := range file.Waivers {
		e, err := newWaiverEntry(w, file.Benchmark, i)
		if err != nil {
			return nil, fmt.Errorf("invalid waiver in %s: %w", path, err)
		}
		set.entries = append(set.entries, e)
	}
	return set, nil
}

// File returns the path the set was loaded from.
func (s *WaiverSet) File() string {
	if s == nil {
		return ""
	}
	return s.path
}

// Len returns the number of entries in the file.
func (s *WaiverSet) Len() int {
	if s == nil {
		return 0
	}
	return len(s.entries)
}

func newWaiverEntry(w Waiver, defaultBenchmark string, index int) (*waiverEntry, error) {
	label := w.Name
	if label == "" {
		label = fmt.Sprintf("#%d", index+1)
	}

	if w.Benchmark == "" {
		w.Benchmark = defaultBenchmark
	}
	if strings.TrimSpace(w.Benchmark) == "" {
		return nil, fmt.Errorf("waiver %s: benchmark is required", label)
	}
	if w.Kind != WaiverAcceptedRisk && w.Kind != WaiverNotApplicable {
		return nil, fmt.Errorf("waiver %s: kind must be %q or %q, got %q",
			label, WaiverAcceptedRisk, WaiverNotApplicable, w.Kind)
	}
	if strings.TrimSpace(w.Reason) == "" {
		return nil, fmt.Errorf("waiver %s: reason is required", label)
	}
	if strings.TrimSpace(w.Requester) == "" {
		return nil, fmt.Errorf("waiver %s: requester is required", label)
	}
	if strings.TrimSpace(w.Approver) == "" {
		return nil, fmt.Errorf("waiver %s: approver is required", label)
	}
	if w.NodeType != "" && !validNodeType(w.NodeType) {
		return nil, fmt.Errorf("waiver %s: unknown node_type %q", label, w.NodeType)
	}
	if w.Check != "" && w.Group != "" {
		return nil, fmt.Errorf("waiver %s: check and group are mutually exclusive", label)
	}
	if w.Check == "" && w.Group == "" && w.NodeType == "" {
		return nil, fmt.Errorf("waiver %s: one of check, group or node_type is required", label)
	}
	if w.Name == "" {
		w.Name = fmt.Sprintf("%s/%s", w.Benchmark, waiverTarget(w))
	}

	e := &waiverEntry{Waiver: w, index: index}
	if w.Starts != "" {
		t, err := parseWaiverTime(w.Starts, false)
		if err != nil {
			return nil, fmt.Errorf("waiver %s: invalid starts %q: %w", label, w.Starts, err)
		}
		e.start, e.hasStart = t, true
		e.startsLabel = w.Starts
	}
	if w.Expires != "" {
		t, err := parseWaiverTime(w.Expires, true)
		if err != nil {
			return nil, fmt.Errorf("waiver %s: invalid expires %q: %w", label, w.Expires, err)
		}
		e.end, e.hasEnd = t, true
		e.expiresLabel = w.Expires
	} else {
		e.expiresLabel = PermanentWaiver
	}
	if e.hasStart && e.hasEnd && !e.end.After(e.start) {
		return nil, fmt.Errorf("waiver %s: expires %q must be after starts %q", label, w.Expires, w.Starts)
	}
	return e, nil
}

func waiverTarget(w Waiver) string {
	switch {
	case w.Check != "":
		return w.Check
	case w.Group != "":
		return w.Group
	default:
		return w.NodeType
	}
}

func validNodeType(t string) bool {
	switch NodeType(t) {
	case MASTER, NODE, FEDERATED, ETCD, CONTROLPLANE, POLICIES, NodeType(MANAGEDSERVICES):
		return true
	}
	return false
}

// parseWaiverTime accepts either a full RFC3339 timestamp or a calendar date.
// A calendar date used as an end boundary is treated as inclusive: the waiver
// remains active for the whole named day (UTC).
func parseWaiverTime(s string, isEnd bool) (time.Time, error) {
	s = strings.TrimSpace(s)
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		t = t.UTC()
		if isEnd {
			t = t.AddDate(0, 0, 1)
		}
		return t, nil
	}
	return time.Time{}, fmt.Errorf("expected YYYY-MM-DD or RFC3339")
}

func (e *waiverEntry) active(now time.Time) bool {
	if e.hasStart && now.Before(e.start) {
		return false
	}
	if e.hasEnd && !now.Before(e.end) {
		return false
	}
	return true
}

func (e *waiverEntry) expired(now time.Time) bool {
	return e.hasEnd && !now.Before(e.end)
}

func (e *waiverEntry) notYetActive(now time.Time) bool {
	return e.hasStart && now.Before(e.start)
}

func (e *waiverEntry) specificity() int {
	s := 0
	if e.Check != "" {
		s += 4
	}
	if e.Group != "" {
		s += 2
	}
	if e.NodeType != "" {
		s++
	}
	return s
}

func (e *waiverEntry) matches(benchmark string, nodeType NodeType, groupID, checkID string) bool {
	if e.Benchmark != benchmark {
		return false
	}
	if e.NodeType != "" && e.NodeType != string(nodeType) {
		return false
	}
	if e.Check != "" && e.Check != checkID {
		return false
	}
	if e.Group != "" && e.Group != groupID {
		return false
	}
	return true
}

func (e *waiverEntry) info(measured State) *WaiverInfo {
	return &WaiverInfo{
		Name:          e.Name,
		Kind:          e.Kind,
		Reason:        e.Reason,
		Requester:     e.Requester,
		Approver:      e.Approver,
		Benchmark:     e.Benchmark,
		NodeType:      e.NodeType,
		Check:         e.Check,
		Group:         e.Group,
		Starts:        e.startsLabel,
		Expires:       e.expiresLabel,
		MeasuredState: string(measured),
	}
}

func scopeHas(s Scope, e *waiverEntry) bool {
	switch {
	case e.Check != "":
		return s.CheckIDs[e.Check]
	case e.Group != "":
		return s.GroupIDs[e.Group]
	default:
		return true
	}
}

func (e *waiverEntry) selectorDescription() string {
	switch {
	case e.Check != "":
		return fmt.Sprintf("check %q", e.Check)
	case e.Group != "":
		return fmt.Sprintf("group %q", e.Group)
	default:
		return fmt.Sprintf("node type %q", e.NodeType)
	}
}

// Apply validates the waiver set against the executed scopes and reclassifies
// matching checks in the collection. It is deliberately a post-processing step:
// every check has already been executed and its raw output preserved, so a
// waiver can only change how the conclusion is presented.
func (s *WaiverSet) Apply(collection []*Controls, scopes []Scope, now time.Time) (ApplyResult, error) {
	res := ApplyResult{}
	if s == nil {
		return res, nil
	}
	if len(scopes) == 0 {
		for _, c := range collection {
			scopes = append(scopes, NewScope(c))
		}
	}
	now = now.UTC()

	byVersion := make(map[string][]Scope)
	for _, sc := range scopes {
		byVersion[sc.Version] = append(byVersion[sc.Version], sc)
	}

	// Per-waiver validation and validity-window diagnostics. These are emitted
	// once per entry rather than once per matching check so a section waiver
	// does not produce hundreds of identical lines.
	for _, e := range s.entries {
		diags, err := s.validateEntry(e, byVersion[e.Benchmark], now)
		if err != nil {
			return res, err
		}
		res.Diagnostics = append(res.Diagnostics, diags...)
	}

	for _, controls := range collection {
		for _, group := range controls.Groups {
			for _, c := range group.Checks {
				s.applyToCheck(controls, group, c, now, &res)
			}
		}
	}

	sort.Strings(res.Diagnostics)
	if res.Conflicts > 0 {
		return res, fmt.Errorf(
			"%d check(s) have waivers that contradict each other; resolve them in the waiver file", res.Conflicts)
	}
	return res, nil
}

// validateEntry reports structural problems with one waiver entry. A reference
// to something that does not exist is fatal; a validity-window problem or an
// entry that cannot apply is a diagnostic.
func (s *WaiverSet) validateEntry(e *waiverEntry, scs []Scope, now time.Time) ([]string, error) {
	var diags []string

	if len(scs) == 0 {
		return append(diags, fmt.Sprintf(
			"waiver %q targets benchmark %s, which was not selected; not applied",
			e.Name, e.Benchmark)), nil
	}

	if e.NodeType != "" {
		found := false
		for _, sc := range scs {
			if string(sc.NodeType) == e.NodeType {
				found = true
				break
			}
		}
		if !found {
			return append(diags, fmt.Sprintf(
				"waiver %q targets node type %s, which is not part of benchmark %s; not applied",
				e.Name, e.NodeType, e.Benchmark)), nil
		}
	}

	if e.Check != "" || e.Group != "" {
		var matchedNodeTypes []string
		for _, sc := range scs {
			if e.NodeType != "" && string(sc.NodeType) != e.NodeType {
				continue
			}
			if scopeHas(sc, e) {
				matchedNodeTypes = append(matchedNodeTypes, string(sc.NodeType))
			}
		}
		if len(matchedNodeTypes) == 0 {
			return nil, fmt.Errorf(
				"waiver %q references %s, which does not exist in benchmark %s",
				e.Name, e.selectorDescription(), e.Benchmark)
		}
		// A selector that exists on more than one node type must say which one
		// it means; otherwise the waiver would silently spread across node
		// types (see benchmarks that reuse identifiers, e.g. STIG).
		if e.NodeType == "" && len(matchedNodeTypes) > 1 {
			sort.Strings(matchedNodeTypes)
			return nil, fmt.Errorf(
				"waiver %q references %s, which exists on multiple node types (%s) in benchmark %s; set node_type to disambiguate",
				e.Name, e.selectorDescription(), strings.Join(matchedNodeTypes, ", "), e.Benchmark)
		}
	}

	if e.notYetActive(now) {
		diags = append(diags, fmt.Sprintf(
			"waiver %q is not yet active (starts %s); not applied", e.Name, e.startsLabel))
	}
	if e.expired(now) {
		diags = append(diags, fmt.Sprintf(
			"waiver %q expired on %s; the check is reported as its measured result",
			e.Name, e.expiresLabel))
	}
	return diags, nil
}

// applyToCheck picks the waiver that governs one check and reclassifies it.
func (s *WaiverSet) applyToCheck(controls *Controls, group *Group, c *Check, now time.Time, res *ApplyResult) {
	// Do not reclassify an already-waived check (idempotent Apply).
	if c.Waiver != nil {
		return
	}

	var active []*waiverEntry
	for _, e := range s.entries {
		if e.active(now) && e.matches(controls.Version, controls.Type, group.ID, c.ID) {
			active = append(active, e)
		}
	}
	if len(active) == 0 {
		return
	}

	// Prefer the most specific waiver; ties are resolved by file order. This
	// makes the conclusion independent of the order checks are evaluated in.
	sort.SliceStable(active, func(i, j int) bool {
		return active[i].specificity() > active[j].specificity()
	})
	chosen := active[0]
	if msg, fatal := overlapConflict(c.ID, active); fatal {
		res.Diagnostics = append(res.Diagnostics, msg)
		res.Conflicts++
		return
	} else if msg != "" {
		res.Diagnostics = append(res.Diagnostics, msg)
	}

	// Accepted risk only makes sense for a result that actually carries risk.
	// Reclassifying a pass would hide it, and an INFO/skip result has nothing
	// to accept. Both are no-ops, reported so the operator can fix the selector.
	if chosen.Kind == WaiverAcceptedRisk && c.State != FAIL && c.State != WARN {
		res.Diagnostics = append(res.Diagnostics, fmt.Sprintf(
			"waiver %q matches check %s, whose measured result is %s; accepted-risk only applies to FAIL or WARN",
			chosen.Name, c.ID, c.State))
		return
	}

	reclassify(controls, group, c, chosen.info(c.State))
	res.Applied++
	if chosen.Kind == WaiverNotApplicable {
		res.NotApplicable++
	} else {
		res.AcceptedRisk++
	}
}

// overlapConflict decides what to do when several waivers match one check.
//
//   - Same kind: harmless. The most specific entry wins (ties by file order),
//     with a diagnostic for exact duplicates.
//   - Different kinds at different specificity: a deliberate refinement, e.g. a
//     group-level "not applicable" narrowed by a single-check "accepted risk".
//     The most specific wins, with a diagnostic so the choice is visible.
//   - Different kinds at the same specificity: a contradiction that cannot be
//     resolved on the operator's behalf, so the run must stop.
//
// The returned message is the diagnostic; fatal=true means the caller aborts.
func overlapConflict(checkID string, active []*waiverEntry) (msg string, fatal bool) {
	if len(active) < 2 {
		return "", false
	}
	chosen := active[0]
	names := []string{chosen.Name}
	sameKind := true
	for _, other := range active[1:] {
		names = append(names, other.Name)
		if other.Kind != chosen.Kind {
			sameKind = false
		}
	}
	joined := strings.Join(names, ", ")

	// active is sorted by descending specificity; equal top specificity means
	// the entries are competing at the same scope.
	sameScope := active[1].specificity() == chosen.specificity()

	if !sameKind {
		if sameScope {
			return fmt.Sprintf(
				"conflicting waivers for check %s at the same scope: %s; they use different kinds (%s vs %s)",
				checkID, joined, chosen.Kind, firstOtherKind(active, chosen.Kind)), true
		}
		return fmt.Sprintf(
			"waivers of different kinds match check %s: %s; using the most specific %q (%s)",
			checkID, joined, chosen.Name, chosen.Kind), false
	}
	if sameScope {
		return fmt.Sprintf(
			"duplicate waivers match check %s: %s; using %q", checkID, joined, chosen.Name), false
	}
	return "", false
}

func firstOtherKind(active []*waiverEntry, kind string) string {
	for _, e := range active[1:] {
		if e.Kind != kind {
			return e.Kind
		}
	}
	return ""
}

func reclassify(controls *Controls, group *Group, c *Check, info *WaiverInfo) {
	from := c.State
	to := ACCEPTEDRISK
	if info.Kind == WaiverNotApplicable {
		to = NOTAPPLICABLE
	}

	decrementSummary(&controls.Summary, from)
	decrementGroup(group, from)
	c.State = to
	c.Waiver = info
	incrementSummary(&controls.Summary, to)
	incrementGroup(group, to)
}

func decrementSummary(s *Summary, state State) {
	switch state {
	case PASS:
		if s.Pass > 0 {
			s.Pass--
		}
	case FAIL:
		if s.Fail > 0 {
			s.Fail--
		}
	case WARN:
		if s.Warn > 0 {
			s.Warn--
		}
	case INFO:
		if s.Info > 0 {
			s.Info--
		}
	}
}

func incrementSummary(s *Summary, state State) {
	switch state {
	case PASS:
		s.Pass++
	case FAIL:
		s.Fail++
	case WARN:
		s.Warn++
	case INFO:
		s.Info++
	case NOTAPPLICABLE:
		s.NotApplicable++
	case ACCEPTEDRISK:
		s.AcceptedRisk++
	}
}

func decrementGroup(g *Group, state State) {
	switch state {
	case PASS:
		if g.Pass > 0 {
			g.Pass--
		}
	case FAIL:
		if g.Fail > 0 {
			g.Fail--
		}
	case WARN:
		if g.Warn > 0 {
			g.Warn--
		}
	case INFO:
		if g.Info > 0 {
			g.Info--
		}
	}
}

func incrementGroup(g *Group, state State) {
	switch state {
	case PASS:
		g.Pass++
	case FAIL:
		g.Fail++
	case WARN:
		g.Warn++
	case INFO:
		g.Info++
	case NOTAPPLICABLE:
		g.NotApplicable++
	case ACCEPTEDRISK:
		g.AcceptedRisk++
	}
}
