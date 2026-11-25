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
	"strings"
)

// Request is one parsed --baseline argument.
//
// Syntax:
//
//	<family>                 use platform/cluster version detection for the
//	                         family's range matching
//	<family>:<clusterVer>    resolve the family against an explicit cluster
//	                         version (range/wildcard matching)
//	<family>@<defVersion>    pin an exact registered definition version;
//	                         when defVersion is not a registered version it
//	                         is treated as a cluster version instead
type Request struct {
	Family         string
	ClusterVersion string
	DefinitionPin  string
	Raw            string
}

// ParseRequest parses one --baseline value.
func ParseRequest(raw string) (Request, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Request{}, fmt.Errorf("empty baseline request")
	}
	req := Request{Raw: raw}

	// Definition pin takes lexical priority, then cluster-version selector.
	if at := strings.Index(raw, "@"); at >= 0 {
		req.Family = strings.TrimSpace(raw[:at])
		req.DefinitionPin = strings.TrimSpace(raw[at+1:])
	} else if colon := strings.Index(raw, ":"); colon >= 0 {
		req.Family = strings.TrimSpace(raw[:colon])
		req.ClusterVersion = strings.TrimSpace(raw[colon+1:])
	} else {
		req.Family = raw
	}

	if req.Family == "" {
		return Request{}, fmt.Errorf("baseline request %q is missing a family", raw)
	}
	if req.DefinitionPin == "" && strings.Contains(raw, "@") {
		return Request{}, fmt.Errorf("baseline request %q is missing a definition version", raw)
	}
	if req.ClusterVersion == "" && strings.Contains(raw, ":") {
		return Request{}, fmt.Errorf("baseline request %q is missing a cluster version", raw)
	}
	return req, nil
}

// SelectVersion resolves a cluster version to a definition version for a
// manifest, applying the deterministic overlap rule and default fallback.
func SelectVersion(m *Manifest, clusterVersion string) (version string, degraded bool, reason string, err error) {
	res, err := selectVersion(m, clusterVersion)
	if err != nil {
		return "", false, "", err
	}
	return res.version, res.degraded, res.reason, nil
}

// ResolveRequest resolves a request against the registry. When a definition
// pin does not match a registered version, it is interpreted as a cluster
// version transparently.
func (r *Registry) ResolveRequest(req Request, target, detectedClusterVersion string) (*Selection, error) {
	m, ok := r.Family(req.Family)
	if !ok {
		return nil, fmt.Errorf("family %q is not registered", req.Family)
	}

	if req.DefinitionPin != "" {
		if b, ok := m.Baseline(req.DefinitionPin); ok {
			if err := validateTarget(b, target); err != nil {
				return nil, err
			}
			return r.newSelection(m, b, target, false, ""), nil
		}
		// Not a registered definition version: treat the pin value as a
		// cluster version expression.
		return r.Resolve(req.Family, req.DefinitionPin, target)
	}

	clusterVersion := req.ClusterVersion
	if clusterVersion == "" {
		clusterVersion = detectedClusterVersion
	}
	if clusterVersion == "" {
		return nil, fmt.Errorf("family %q: no cluster version available for matching", req.Family)
	}
	return r.Resolve(req.Family, clusterVersion, target)
}
