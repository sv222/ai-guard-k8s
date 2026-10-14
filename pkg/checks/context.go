package checks

import (
	"fmt"
	"strings"

	"github.com/sv222/ai-guard-k8s/pkg/detect"
	"github.com/sv222/ai-guard-k8s/pkg/target"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

const GatewayAuthKey = "ai.infra.guard/gateway-auth"

var ingressAuthHints = []string{"auth-url", "auth-type", "auth-signin", "auth-secret", "oauth2"}

type ScanContext struct {
	NetPols   []target.NetworkPolicyEntry
	Services  []target.ServiceEntry
	Ingresses []target.IngressEntry
}

func RunContextChecks(w target.WorkloadTarget, ctx ScanContext) []Finding {
	var out []Finding
	if isolated, detail := netPolIsolates(w, ctx.NetPols); !isolated {
		out = append(out, Finding{ID: "AIG-009", Title: "no NetworkPolicy isolation", Severity: "Medium",
			Evidence: detail,
			Hint:     "add default-deny + allowlist policies (see `ai-guard enforce`)"}.on(w))
	}
	if hasGatewayAuth(w) || workloadHasAuth(w) {
		return out
	}
	for _, s := range ctx.Services {
		if s.Namespace != w.Namespace || (s.Type != "LoadBalancer" && s.Type != "NodePort") {
			continue
		}
		if selectorSubset(s.Selector, w.Labels) {
			out = append(out, Finding{ID: "AIG-010", Title: "inference exposed via " + s.Type, Severity: "High",
				Evidence: "Service " + s.Name + " (" + s.Type + ") selects this workload and no auth evidence was found",
				Hint:     "add engine auth (--api-key), or require auth at a gateway and annotate the workload " + GatewayAuthKey + ": \"true\", or use an internal Service"}.on(w))
		}
	}
	for _, ing := range ctx.Ingresses {
		if ing.Namespace != w.Namespace || ingressHasAuth(ing.Annotations) {
			continue
		}
		for _, name := range ing.Services {
			for _, s := range ctx.Services {
				if s.Namespace != w.Namespace || s.Name != name || !selectorSubset(s.Selector, w.Labels) {
					continue
				}
				out = append(out, Finding{ID: "AIG-010", Title: "inference exposed via Ingress", Severity: "High",
					Evidence: "Ingress " + ing.Name + " routes to Service " + s.Name + " which selects this workload and no auth evidence was found",
					Hint:     "add engine auth (--api-key), or add auth at the Ingress, or annotate the workload " + GatewayAuthKey + ": \"true\" if a gateway authenticates"}.on(w))
			}
		}
	}
	return out
}

func ingressHasAuth(ann map[string]string) bool {
	if ann[GatewayAuthKey] == "true" {
		return true
	}
	for k := range ann {
		k = strings.ToLower(k)
		for _, hint := range ingressAuthHints {
			if strings.Contains(k, hint) {
				return true
			}
		}
	}
	return false
}

func hasGatewayAuth(w target.WorkloadTarget) bool {
	return w.MergedLabels()[GatewayAuthKey] == "true" || w.MergedAnnotations()[GatewayAuthKey] == "true"
}

func workloadHasAuth(w target.WorkloadTarget) bool {
	matched := detect.EngineContainers(w)
	if len(matched) == 0 {
		matched = w.Containers()
	}
	for _, c := range matched {
		if hasAuthEvidence(c) {
			return true
		}
	}
	return false
}

func netPolIsolates(w target.WorkloadTarget, pols []target.NetworkPolicyEntry) (bool, string) {
	var ingressSeen, ingressOpen bool
	var selecting []string
	for _, p := range pols {
		if p.Namespace != w.Namespace || !selects(p.Spec.PodSelector, w.Labels) {
			continue
		}
		selecting = append(selecting, p.Name)
		if ingress, _ := policyTypes(p.Spec); !ingress {
			continue
		}
		ingressSeen = true
		for _, r := range p.Spec.Ingress {
			if openRule(r.From) {
				ingressOpen = true
			}
		}
	}
	if len(selecting) == 0 {
		return false, "no NetworkPolicy in namespace " + w.Namespace + " selects this workload's pod labels"
	}
	if ingressSeen && !ingressOpen {
		return true, ""
	}
	if !ingressSeen {
		return false, fmt.Sprintf("NetworkPolicy %s selects this workload but has no Ingress policyType, so ingress traffic is not restricted",
			strings.Join(selecting, ", "))
	}
	return false, fmt.Sprintf("NetworkPolicy %s selects this workload but an ingress rule allows traffic from every source",
		strings.Join(selecting, ", "))
}

func selects(sel metav1.LabelSelector, podLabels map[string]string) bool {
	s, err := metav1.LabelSelectorAsSelector(&sel)
	if err != nil {
		return false
	}
	return s.Matches(labels.Set(podLabels))
}

func policyTypes(spec netv1.NetworkPolicySpec) (ingress, egress bool) {
	if len(spec.PolicyTypes) == 0 {
		return true, len(spec.Egress) > 0
	}
	for _, t := range spec.PolicyTypes {
		switch t {
		case netv1.PolicyTypeIngress:
			ingress = true
		case netv1.PolicyTypeEgress:
			egress = true
		}
	}
	return ingress, egress
}

func openRule(peers []netv1.NetworkPolicyPeer) bool {
	if len(peers) == 0 {
		return true
	}
	for _, p := range peers {
		if openPeer(p) {
			return true
		}
	}
	return false
}

func openPeer(p netv1.NetworkPolicyPeer) bool {
	if p.IPBlock != nil {
		return len(p.IPBlock.Except) == 0 && (p.IPBlock.CIDR == "0.0.0.0/0" || p.IPBlock.CIDR == "::/0")
	}
	if p.NamespaceSelector == nil && p.PodSelector == nil {
		return true
	}
	return p.NamespaceSelector != nil && selectsEverything(*p.NamespaceSelector) &&
		(p.PodSelector == nil || selectsEverything(*p.PodSelector))
}

func selectsEverything(sel metav1.LabelSelector) bool {
	return len(sel.MatchLabels) == 0 && len(sel.MatchExpressions) == 0
}

func selectorSubset(sel, podLabels map[string]string) bool {
	if len(sel) == 0 {
		return false
	}
	for k, v := range sel {
		if got, ok := podLabels[k]; !ok || got != v {
			return false
		}
	}
	return true
}
