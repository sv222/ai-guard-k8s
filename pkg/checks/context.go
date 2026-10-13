package checks

import (
	"github.com/aiguard/ai-guard-k8s/pkg/target"
)

type ScanContext struct {
	NetPols  []target.NetworkPolicyEntry
	Services []target.ServiceEntry
}

// AIG-009/AIG-010: need the pass-1 index (NetPols, Services).
func RunContextChecks(w target.WorkloadTarget, ctx ScanContext) []Finding {
	var out []Finding
	if !netPolCovers(w, ctx.NetPols) {
		out = append(out, Finding{ID: "AIG-009", Title: "no NetworkPolicy isolation", Severity: "Medium",
			Evidence: "no NetworkPolicy podSelector covers this workload's labels",
			Hint:     "add default-deny + allowlist policies (see `ai-guard enforce`)"}.on(w))
	}
	for _, s := range ctx.Services {
		if s.Namespace != w.Namespace || (s.Type != "LoadBalancer" && s.Type != "NodePort") {
			continue
		}
		if selectorSubset(s.Selector, w.Labels) {
			out = append(out, Finding{ID: "AIG-010", Title: "inference exposed via " + s.Type, Severity: "High",
				Evidence: "Service " + s.Name + " (" + s.Type + ") selects this workload",
				Hint:     "require auth at gateway or restrict via internal Service + ingress"}.on(w))
		}
	}
	return out
}

func netPolCovers(w target.WorkloadTarget, pols []target.NetworkPolicyEntry) bool {
	for _, p := range pols {
		if p.Namespace != w.Namespace {
			continue
		}
		if selectorSubset(p.PodSelector.MatchLabels, w.Labels) {
			return true
		}
	}
	return false
}

// selectorSubset: every key in sel exists with equal value in labels.
// An empty sel covers everything (k8s semantics for NetworkPolicy podSelector).
func selectorSubset(sel, labels map[string]string) bool {
	for k, v := range sel {
		if labels[k] != v {
			return false
		}
	}
	return true
}
