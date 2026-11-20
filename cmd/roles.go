package cmd

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/aquasecurity/kube-bench/check"
	"github.com/golang/glog"
	"github.com/spf13/viper"
)

// Machine roles. Role detection only uses observable facts: which configured
// components are running on this machine, plus a manually specified scope.
// It never derives a role from the hostname, environment variables or
// directory conventions.
const (
	RoleControlPlane = "controlplane"
	RoleWorker       = "worker"
	RoleEtcd         = "etcd"
)

// roleComponents maps a machine role to the config sections that describe its
// components (first existing section wins) and the components whose presence
// is evidence for the role.
//
// Each role is judged only by its own configured components. A machine that
// runs control-plane components and kubelet therefore yields both roles, which
// is exactly the mixed case: neither one may be chosen over the other.
var roleComponents = []struct {
	role       string
	sections   []string
	components []string
}{
	{role: RoleControlPlane, sections: []string{"master", "controlplane"}, components: []string{"apiserver", "scheduler", "controllermanager"}},
	{role: RoleWorker, sections: []string{"node"}, components: []string{"kubelet"}},
	{role: RoleEtcd, sections: []string{"etcd"}, components: []string{"etcd"}},
}

// roleDetectionAvailable is injectable so tests can simulate a missing or
// non-executable detection command.
var roleDetectionAvailable = defaultRoleDetectionAvailable

// isRoleTarget reports whether the target's applicability is role-dependent.
// Policies and managed services are cluster-scoped, so they are not.
func isRoleTarget(t check.NodeType) bool {
	switch t {
	case check.MASTER, check.CONTROLPLANE, check.NODE, check.ETCD:
		return true
	default:
		return false
	}
}

// targetRole returns the role a target belongs to and whether the target is
// cluster-scoped (policies and managed services are, so they are always
// applicable).
func targetRole(t check.NodeType) (role string, clusterScoped bool) {
	switch t {
	case check.MASTER, check.CONTROLPLANE:
		return RoleControlPlane, false
	case check.NODE:
		return RoleWorker, false
	case check.ETCD:
		return RoleEtcd, false
	default:
		return "", true
	}
}

func defaultRoleDetectionAvailable() (string, error) {
	candidates := []string{"/bin/ps", "/usr/bin/ps"}
	for _, candidate := range candidates {
		info, err := os.Stat(candidate)
		if err != nil {
			continue
		}
		if info.Mode()&0111 == 0 {
			return "", fmt.Errorf("detection command %s is not executable", candidate)
		}
		return candidate, nil
	}
	return "", fmt.Errorf("detection command not found (looked for /bin/ps and /usr/bin/ps)")
}

// manualRoleHints derives roles from an explicitly specified target list.
// A manual scope is observable evidence, so an explicitly requested target is
// treated as present even when component probing cannot confirm it. This keeps
// long-standing explicit invocations (for example `run --targets controlplane`
// from a worker while auditing a managed cluster) working as before.
func manualRoleHints(targets []string) (roles map[string]bool, evidence []string) {
	roles = make(map[string]bool)
	for _, raw := range targets {
		name := check.NodeType(translate(raw))
		role, clusterScoped := targetRole(name)
		if clusterScoped || role == "" {
			continue
		}
		if !roles[role] {
			roles[role] = true
			evidence = append(evidence, fmt.Sprintf("manual scope: target %q implies %s role", string(name), role))
		}
	}
	sort.Strings(evidence)
	return roles, evidence
}

// detectRoles observes which configured components are running on this
// machine and combines that with any manually specified target scope. The
// result is deterministic: components are probed in config order and the role
// set and evidence are sorted before being reported.
func detectRoles(v *viper.Viper, manualTargets []string) *check.RoleReport {
	report := &check.RoleReport{
		Roles:    []string{},
		Source:   "observed",
		Evidence: []string{},
	}

	observed := make(map[string]bool)
	var evidence []string
	var unresolved []string

	detectionCommand, detectionErr := roleDetectionAvailable()
	if detectionErr != nil {
		report.Source = "unavailable"
		report.Determined = false
		report.Fallback = true
		report.ReasonCode = check.ReasonRoleDetectionUnavailable
		report.Reason = fmt.Sprintf("machine role could not be determined: %v; every role-dependent target is executed and marked undetermined", detectionErr)
		evidence = append(evidence, fmt.Sprintf("role detection unavailable: %v", detectionErr))
	} else {
		detectionEvidence := fmt.Sprintf("role detection command: %s", detectionCommand)
		evidence = append(evidence, detectionEvidence)
		observed, evidence, unresolved = observeRoles(v, evidence)
	}

	if detectionErr != nil {
		// Without the detection command no role can be asserted absent. Any
		// role not pinned by an explicit scope stays unresolved, so its target
		// is executed and reported as undetermined rather than trimmed.
		for _, rc := range roleComponents {
			unresolved = append(unresolved, rc.role)
		}
		sort.Strings(unresolved)
	}

	manual, manualEvidence := manualRoleHints(manualTargets)
	evidence = append(evidence, manualEvidence...)

	for role := range manual {
		observed[role] = true
	}

	roles := make([]string, 0, len(observed))
	for role := range observed {
		roles = append(roles, role)
	}
	sort.Strings(roles)
	report.Roles = roles
	sort.Strings(evidence)
	report.Evidence = evidence
	report.Unresolved = unresolved

	if detectionErr != nil {
		if len(manual) > 0 {
			report.Determined = true
			report.Source = "manual"
			report.Fallback = false
			report.ReasonCode = check.ReasonRoleDetectionUnavailable
			report.Reason = "role detection was unavailable; roles come from the manually specified scope, other role-dependent targets are undetermined"
		}
		return report
	}

	if len(roles) == 0 {
		report.Determined = false
		report.Source = "default"
		report.Fallback = true
		report.ReasonCode = check.ReasonNoComponentsObserved
		report.Reason = "no control-plane, worker or etcd components were observed; defaulting to executing every role-dependent target and marking coverage undetermined"
		return report
	}

	report.Determined = true
	if len(manual) > 0 && len(observed) == len(manual) {
		// Every role came from the explicit scope, none from probing.
		report.Source = "manual"
	}
	return report
}

// observeRoles probes every configured role component and records the
// observable evidence for both presence and absence. A role is unresolved when
// its configuration or probe list is missing, because absence cannot be
// asserted from a target that was never probed.
func observeRoles(v *viper.Viper, evidence []string) (map[string]bool, []string, []string) {
	observed := make(map[string]bool)
	unresolved := []string{}

	for _, rc := range roleComponents {
		section := firstSection(v, rc.sections)
		if section == nil {
			evidence = append(evidence, fmt.Sprintf("%s role: no component configuration found (sections %v)", rc.role, rc.sections))
			unresolved = append(unresolved, rc.role)
			continue
		}

		probed := 0
		for _, component := range rc.components {
			bins := section.GetStringSlice(component + ".bins")
			if len(bins) == 0 {
				continue
			}
			probed++
			bin, err := findExecutable(bins)
			if err != nil {
				evidence = append(evidence, fmt.Sprintf("%s role: component %s not running (searched: %s)", rc.role, component, strings.Join(bins, ", ")))
				continue
			}
			observed[rc.role] = true
			evidence = append(evidence, fmt.Sprintf("%s role: component %s running (%s)", rc.role, component, bin))
		}

		if probed == 0 {
			evidence = append(evidence, fmt.Sprintf("%s role: no components configured to probe", rc.role))
			unresolved = append(unresolved, rc.role)
		}
	}

	sort.Strings(unresolved)
	return observed, evidence, unresolved
}

func firstSection(v *viper.Viper, names []string) *viper.Viper {
	for _, name := range names {
		if v == nil {
			return nil
		}
		s := v.Sub(name)
		if s != nil {
			return s
		}
	}
	return nil
}

// applicabilityDecision is the resolved coverage decision for one target.
type applicabilityDecision struct {
	State      check.ApplicabilityState
	ReasonCode string
	Reason     string
	Source     string
	Evidence   []string
}

// decideApplicability resolves how a target relates to the detected roles.
//
// Rules, in order:
//  1. Cluster-scoped targets (policies, managed services) are always covered.
//  2. A target explicitly named on the command line is pinned to covered, as
//     before; the explicit scope is itself observable evidence.
//  3. If the target's role was observed, it is covered.
//  4. If role detection was unavailable, nothing at all was observed, or the
//     target's own role could not be probed, the checks are still executed and
//     the target is reported as undetermined, with the reason; the whole
//     section is never silently skipped.
//  5. Otherwise the role is known to be absent: the checks are trimmed and
//     reported as not applicable.
func decideApplicability(t check.NodeType, report *check.RoleReport, manual map[check.NodeType]bool) applicabilityDecision {
	role, clusterScoped := targetRole(t)
	if clusterScoped {
		return applicabilityDecision{
			State:    check.ApplicabilityCovered,
			Source:   "cluster-scoped",
			Evidence: []string{fmt.Sprintf("target %q is cluster-scoped and does not depend on a machine role", string(t))},
		}
	}

	if manual[t] {
		return applicabilityDecision{
			State:    check.ApplicabilityCovered,
			Source:   "manual",
			Evidence: []string{fmt.Sprintf("target %q was explicitly specified on the command line", string(t))},
		}
	}

	if report == nil {
		return applicabilityDecision{
			State:      check.ApplicabilityUndetermined,
			ReasonCode: check.ReasonRoleDetectionUnavailable,
			Reason:     "no role report was available; checks were executed but coverage is undetermined",
			Source:     "unavailable",
		}
	}

	for _, observed := range report.Roles {
		if observed == role {
			return applicabilityDecision{
				State:    check.ApplicabilityCovered,
				Source:   report.Source,
				Evidence: []string{fmt.Sprintf("role %s observed on this machine", role)},
			}
		}
	}

	if report.Source == "unavailable" || report.Fallback {
		code := report.ReasonCode
		if code == "" {
			code = check.ReasonRoleDetectionUnavailable
		}
		return applicabilityDecision{
			State:      check.ApplicabilityUndetermined,
			ReasonCode: code,
			Reason:     report.Reason,
			Source:     report.Source,
			Evidence:   report.Evidence,
		}
	}

	for _, unresolved := range report.Unresolved {
		if unresolved == role {
			return applicabilityDecision{
				State:      check.ApplicabilityUndetermined,
				ReasonCode: check.ReasonRoleDetectionUnavailable,
				Reason:     fmt.Sprintf("the %s role could not be probed (no components available to inspect); checks were executed but coverage is undetermined", role),
				Source:     "observed",
				Evidence:   []string{fmt.Sprintf("role %s could not be probed", role)},
			}
		}
	}

	return applicabilityDecision{
		State:      check.ApplicabilityNotApplicable,
		ReasonCode: check.ReasonRoleNotObserved,
		Reason:     fmt.Sprintf("check belongs to the %s role, which was not observed on this machine", role),
		Source:     "observed",
		Evidence:   []string{fmt.Sprintf("role %s was not observed on this machine", role)},
	}
}

// newRoleReport builds the role report for a run. It is a function variable so
// tests can avoid probing the host.
var newRoleReport = detectRoles

// targetDecision resolves the coverage decision for a target using the role
// report and explicit target scope of the current run.
func targetDecision(t check.NodeType) applicabilityDecision {
	return decideApplicability(t, activeRoleReport, activeManualTargets)
}

// buildCoverage aggregates the coverage accounting of a finished report.
func buildCoverage(collection []*check.Controls) *check.Coverage {
	coverage := &check.Coverage{Reasons: map[string]int{}}
	for _, controls := range collection {
		coverage.Covered += controls.Pass + controls.Fail + controls.Warn + controls.Info
		coverage.NotApplicable += controls.NotApplicable
		if controls.Applicability != nil {
			coverage.Deduplicated += controls.Applicability.Deduplicated
		}
		for _, group := range controls.Groups {
			for _, c := range group.Checks {
				if c.State != check.NOT_APPLICABLE {
					continue
				}
				code := c.ReasonCode
				if code == "" {
					code = check.ReasonRoleNotObserved
				}
				coverage.Reasons[code]++
			}
		}
	}
	if len(coverage.Reasons) == 0 {
		coverage.Reasons = nil
	}
	return coverage
}

// logRoleReport writes the determination and its evidence to the debug log,
// which is where operational diagnostics already live.
func logRoleReport(report *check.RoleReport) {
	if report == nil {
		return
	}
	glog.V(1).Infof("Machine roles: %v (determined=%t source=%s)", report.Roles, report.Determined, report.Source)
	for _, ev := range report.Evidence {
		glog.V(2).Infof("Role evidence: %s", ev)
	}
	if report.Reason != "" {
		glog.V(1).Infof("Role determination: %s", report.Reason)
	}
}
