package checks

import (
	"strings"

	"github.com/sv222/ai-guard-k8s/pkg/target"
)

var kongPluginKeys = []string{"konghq.com/plugins", "plugins.konghq.com"}

// meshProtects reports whether an Istio AuthorizationPolicy that refuses
// unauthenticated requests applies to the workload, directly, through the
// Service it is reached by, or through a parent Gateway. A policy that relies
// on request principals also needs a RequestAuthentication that applies.
func meshProtects(w target.WorkloadTarget, svc string, gateways []string, pols []target.MeshPolicyEntry) bool {
	var jwt bool
	for _, p := range pols {
		jwt = jwt || p.Kind == "RequestAuthentication" && meshApplies(p, w, svc, gateways)
	}
	for _, p := range pols {
		if p.Kind == "AuthorizationPolicy" && (jwt || !p.JWT) && meshApplies(p, w, svc, gateways) {
			return true
		}
	}
	return false
}

func meshApplies(p target.MeshPolicyEntry, w target.WorkloadTarget, svc string, gateways []string) bool {
	if len(p.Targets) == 0 {
		return p.Namespace == w.Namespace && (len(p.Selector) == 0 || selectorSubset(p.Selector, w.Labels))
	}
	for _, t := range p.Targets {
		if t == "Service/"+w.Namespace+"/"+svc {
			return true
		}
		for _, g := range gateways {
			if t == "Gateway/"+g {
				return true
			}
		}
	}
	return false
}

// kongProtects reports whether an authenticating KongPlugin or
// KongClusterPlugin is bound to a resource of namespace ns by the
// konghq.com/plugins annotation or by an ExtensionRef filter.
func kongProtects(ns string, ann map[string]string, refs []string, plugins []target.KongPluginEntry) bool {
	names := refs
	for _, k := range kongPluginKeys {
		for _, n := range strings.Split(ann[k], ",") {
			names = append(names, strings.TrimSpace(n))
		}
	}
	for _, n := range names {
		for _, p := range plugins {
			if p.Name == n && (p.Cluster || p.Namespace == ns) {
				return true
			}
		}
	}
	return false
}
