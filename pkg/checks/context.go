package checks

import (
	"fmt"
	"strings"

	"github.com/sv222/ai-guard-k8s/pkg/detect"
	"github.com/sv222/ai-guard-k8s/pkg/target"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

const GatewayAuthKey = "ai.infra.guard/gateway-auth"

type ScanContext struct {
	NetPols  []target.NetworkPolicyEntry
	Services []target.ServiceEntry
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
	return out
}

func hasGatewayAuth(w target.WorkloadTarget) bool {
	return w.MergedLabels()[GatewayAuthKey] == "true" || w.MergedAnnotations()[GatewayAuthKey] == "true"
}

func workloadHasAuth(w target.WorkloadTarget) bool {
	var matched []corev1.Container
	for _, c := range w.Containers() {
		if detect.IsAIContainer(c) {
			matched = append(matched, c)
		}
	}
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
	var ingressSeen, egressSeen, ingressOpen, egressOpen bool
	var selecting []string
	for _, p := range pols {
		if p.Namespace != w.Namespace || !selects(p.Spec.PodSelector, w.Labels) {
			continue
		}
		selecting = append(selecting, p.Name)
		ingress, egress := policyTypes(p.Spec)
		if ingress {
			ingressSeen = true
			for _, r := range p.Spec.Ingress {
				if openRule(r.From, r.Ports) {
					ingressOpen = true
				}
			}
		}
		if egress {
			egressSeen = true
			for _, r := range p.Spec.Egress {
				if openRule(r.To, r.Ports) {
					egressOpen = true
				}
			}
		}
	}
	if len(selecting) == 0 {
		return false, "no NetworkPolicy in namespace " + w.Namespace + " selects this workload's pod labels"
	}
	if (ingressSeen && !ingressOpen) || (egressSeen && !egressOpen) {
		return true, ""
	}
	return false, fmt.Sprintf("NetworkPolicy %s selects this workload but does not restrict traffic (no Ingress/Egress policyType, or an allow-all rule)",
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

func openRule(peers []netv1.NetworkPolicyPeer, ports []netv1.NetworkPolicyPort) bool {
	if len(ports) > 0 {
		return false
	}
	if len(peers) == 0 {
		return true
	}
	for _, p := range peers {
		if p.IPBlock != nil && len(p.IPBlock.Except) == 0 &&
			(p.IPBlock.CIDR == "0.0.0.0/0" || p.IPBlock.CIDR == "::/0") {
			return true
		}
	}
	return false
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
