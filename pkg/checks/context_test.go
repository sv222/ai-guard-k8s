package checks

import (
	"strings"
	"testing"

	"github.com/aiguard/ai-guard-k8s/pkg/target"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func aiWorkload(labels map[string]string) target.WorkloadTarget {
	return target.WorkloadTarget{
		Kind: "Deployment", Namespace: "llm", Name: "vllm", Labels: labels,
		PodSpec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "vllm/vllm-openai"}}},
	}
}

func pol(sel metav1.LabelSelector, types []netv1.PolicyType, ingress []netv1.NetworkPolicyIngressRule, egress []netv1.NetworkPolicyEgressRule) target.NetworkPolicyEntry {
	return target.NetworkPolicyEntry{Namespace: "llm", Name: "p", Spec: netv1.NetworkPolicySpec{
		PodSelector: sel, PolicyTypes: types, Ingress: ingress, Egress: egress,
	}}
}

func matchApp(v string) metav1.LabelSelector {
	return metav1.LabelSelector{MatchLabels: map[string]string{"app": v}}
}

func TestAIG009(t *testing.T) {
	both := []netv1.PolicyType{netv1.PolicyTypeIngress, netv1.PolicyTypeEgress}
	ingressOnly := []netv1.PolicyType{netv1.PolicyTypeIngress}
	egressOnly := []netv1.PolicyType{netv1.PolicyTypeEgress}
	port := intstr.FromInt32(8000)
	allowAllIngress := []netv1.NetworkPolicyIngressRule{{}}
	allowAllEgress := []netv1.NetworkPolicyEgressRule{{}}
	cidrAll := []netv1.NetworkPolicyPeer{{IPBlock: &netv1.IPBlock{CIDR: "0.0.0.0/0"}}}
	cidrAllExcept := []netv1.NetworkPolicyPeer{{IPBlock: &netv1.IPBlock{CIDR: "0.0.0.0/0", Except: []string{"10.0.0.0/8"}}}}
	nsPeer := []netv1.NetworkPolicyPeer{{NamespaceSelector: &metav1.LabelSelector{}}}
	exprIn := metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
		{Key: "app", Operator: metav1.LabelSelectorOpIn, Values: []string{"vllm", "other"}}}}
	exprNotIn := metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
		{Key: "app", Operator: metav1.LabelSelectorOpNotIn, Values: []string{"vllm"}}}}
	exprExists := metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
		{Key: "app", Operator: metav1.LabelSelectorOpExists}}}
	exprDoesNotExist := metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
		{Key: "app", Operator: metav1.LabelSelectorOpDoesNotExist}}}
	badOp := metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
		{Key: "app", Operator: "Bogus"}}}
	mixed := metav1.LabelSelector{
		MatchLabels:      map[string]string{"app": "vllm"},
		MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "tier", Operator: metav1.LabelSelectorOpExists}},
	}

	tests := []struct {
		name     string
		labels   map[string]string
		pols     []target.NetworkPolicyEntry
		wantFlag bool
	}{
		{"no policies", map[string]string{"app": "vllm"}, nil, true},
		{"empty selector deny-all", map[string]string{"app": "vllm"}, []target.NetworkPolicyEntry{pol(metav1.LabelSelector{}, both, nil, nil)}, false},
		{"matchLabels selects, deny ingress", map[string]string{"app": "vllm"}, []target.NetworkPolicyEntry{pol(matchApp("vllm"), ingressOnly, nil, nil)}, false},
		{"matchLabels other app", map[string]string{"app": "vllm"}, []target.NetworkPolicyEntry{pol(matchApp("other"), both, nil, nil)}, true},
		{"policy in other namespace", map[string]string{"app": "vllm"}, []target.NetworkPolicyEntry{
			{Namespace: "other", Name: "p", Spec: netv1.NetworkPolicySpec{PodSelector: matchApp("vllm"), PolicyTypes: both}}}, true},
		{"expression In selects", map[string]string{"app": "vllm"}, []target.NetworkPolicyEntry{pol(exprIn, ingressOnly, nil, nil)}, false},
		{"expression NotIn excludes", map[string]string{"app": "vllm"}, []target.NetworkPolicyEntry{pol(exprNotIn, ingressOnly, nil, nil)}, true},
		{"expression NotIn selects other", map[string]string{"app": "x"}, []target.NetworkPolicyEntry{pol(exprNotIn, ingressOnly, nil, nil)}, false},
		{"expression Exists", map[string]string{"app": "vllm"}, []target.NetworkPolicyEntry{pol(exprExists, egressOnly, nil, nil)}, false},
		{"expression DoesNotExist no match", map[string]string{"app": "vllm"}, []target.NetworkPolicyEntry{pol(exprDoesNotExist, egressOnly, nil, nil)}, true},
		{"invalid selector never selects", map[string]string{"app": "vllm"}, []target.NetworkPolicyEntry{pol(badOp, both, nil, nil)}, true},
		{"labels and expressions both required", map[string]string{"app": "vllm", "tier": "x"}, []target.NetworkPolicyEntry{pol(mixed, ingressOnly, nil, nil)}, false},
		{"labels ok but expression fails", map[string]string{"app": "vllm"}, []target.NetworkPolicyEntry{pol(mixed, ingressOnly, nil, nil)}, true},
		{"empty policyTypes defaults to ingress", map[string]string{"app": "vllm"}, []target.NetworkPolicyEntry{pol(matchApp("vllm"), nil, nil, nil)}, false},
		{"empty ingress rule is allow-all", map[string]string{"app": "vllm"}, []target.NetworkPolicyEntry{pol(matchApp("vllm"), ingressOnly, allowAllIngress, nil)}, true},
		{"empty egress rule is allow-all", map[string]string{"app": "vllm"}, []target.NetworkPolicyEntry{pol(matchApp("vllm"), egressOnly, nil, allowAllEgress)}, true},
		{"allow-all ingress but restricted egress", map[string]string{"app": "vllm"}, []target.NetworkPolicyEntry{pol(matchApp("vllm"), both, allowAllIngress, nil)}, false},
		{"allow-all both directions", map[string]string{"app": "vllm"}, []target.NetworkPolicyEntry{pol(matchApp("vllm"), both, allowAllIngress, allowAllEgress)}, true},
		{"cidr 0.0.0.0/0 ingress is allow-all", map[string]string{"app": "vllm"}, []target.NetworkPolicyEntry{
			pol(matchApp("vllm"), ingressOnly, []netv1.NetworkPolicyIngressRule{{From: cidrAll}}, nil)}, true},
		{"cidr with except is restricting", map[string]string{"app": "vllm"}, []target.NetworkPolicyEntry{
			pol(matchApp("vllm"), ingressOnly, []netv1.NetworkPolicyIngressRule{{From: cidrAllExcept}}, nil)}, false},
		{"open peers but ports restrict", map[string]string{"app": "vllm"}, []target.NetworkPolicyEntry{
			pol(matchApp("vllm"), ingressOnly, []netv1.NetworkPolicyIngressRule{{Ports: []netv1.NetworkPolicyPort{{Port: &port}}}}, nil)}, false},
		{"namespace peer restricts", map[string]string{"app": "vllm"}, []target.NetworkPolicyEntry{
			pol(matchApp("vllm"), ingressOnly, []netv1.NetworkPolicyIngressRule{{From: nsPeer}}, nil)}, false},
		{"deny-all plus separate allow-all stays open", map[string]string{"app": "vllm"}, []target.NetworkPolicyEntry{
			pol(matchApp("vllm"), ingressOnly, nil, nil),
			pol(matchApp("vllm"), ingressOnly, allowAllIngress, nil),
		}, true},
		{"egress policy deny-all", map[string]string{"app": "vllm"}, []target.NetworkPolicyEntry{pol(matchApp("vllm"), egressOnly, nil, nil)}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := RunContextChecks(aiWorkload(tt.labels), ScanContext{NetPols: tt.pols})
			if got := has(ids(fs), "AIG-009"); got != tt.wantFlag {
				t.Errorf("AIG-009 flagged = %v, want %v (%+v)", got, tt.wantFlag, fs)
			}
		})
	}
}

func TestAIG009EvidenceMentionsPolicy(t *testing.T) {
	p := pol(matchApp("vllm"), []netv1.PolicyType{netv1.PolicyTypeIngress}, []netv1.NetworkPolicyIngressRule{{}}, nil)
	p.Name = "wide-open"
	fs := RunContextChecks(aiWorkload(map[string]string{"app": "vllm"}), ScanContext{NetPols: []target.NetworkPolicyEntry{p}})
	if len(fs) != 1 || fs[0].Evidence == "" || !strings.Contains(fs[0].Evidence, "wide-open") {
		t.Errorf("evidence should name the policy: %+v", fs)
	}
}

func TestAIG010(t *testing.T) {
	lb := func(sel map[string]string, typ string) target.ServiceEntry {
		return target.ServiceEntry{Namespace: "llm", Name: "svc", Type: typ, Selector: sel, Ports: []int32{80}}
	}
	withContainer := func(f func(c *corev1.Container)) target.WorkloadTarget {
		w := aiWorkload(map[string]string{"app": "vllm"})
		f(&w.PodSpec.Containers[0])
		return w
	}
	tests := []struct {
		name string
		w    target.WorkloadTarget
		svcs []target.ServiceEntry
		want bool
	}{
		{"LoadBalancer exposed", aiWorkload(map[string]string{"app": "vllm"}), []target.ServiceEntry{lb(map[string]string{"app": "vllm"}, "LoadBalancer")}, true},
		{"NodePort exposed", aiWorkload(map[string]string{"app": "vllm"}), []target.ServiceEntry{lb(map[string]string{"app": "vllm"}, "NodePort")}, true},
		{"ClusterIP not flagged", aiWorkload(map[string]string{"app": "vllm"}), []target.ServiceEntry{lb(map[string]string{"app": "vllm"}, "ClusterIP")}, false},
		{"selector mismatch", aiWorkload(map[string]string{"app": "vllm"}), []target.ServiceEntry{lb(map[string]string{"app": "x"}, "LoadBalancer")}, false},
		{"selectorless service", aiWorkload(map[string]string{"app": "vllm"}), []target.ServiceEntry{lb(nil, "LoadBalancer")}, false},
		{"other namespace", aiWorkload(map[string]string{"app": "vllm"}), []target.ServiceEntry{
			{Namespace: "other", Name: "svc", Type: "LoadBalancer", Selector: map[string]string{"app": "vllm"}}}, false},
		{"api-key arg is auth evidence", withContainer(func(c *corev1.Container) { c.Args = []string{"--api-key", "k"} }),
			[]target.ServiceEntry{lb(map[string]string{"app": "vllm"}, "LoadBalancer")}, false},
		{"api key env is auth evidence", withContainer(func(c *corev1.Container) {
			c.Env = []corev1.EnvVar{{Name: "VLLM_API_KEY", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{}}}}
		}), []target.ServiceEntry{lb(map[string]string{"app": "vllm"}, "LoadBalancer")}, false},
		{"gateway-auth annotation on workload", func() target.WorkloadTarget {
			w := aiWorkload(map[string]string{"app": "vllm"})
			w.MetaAnnotations = map[string]string{GatewayAuthKey: "true"}
			return w
		}(), []target.ServiceEntry{lb(map[string]string{"app": "vllm"}, "LoadBalancer")}, false},
		{"gateway-auth label on workload", func() target.WorkloadTarget {
			w := aiWorkload(map[string]string{"app": "vllm"})
			w.MetaLabels = map[string]string{GatewayAuthKey: "true"}
			return w
		}(), []target.ServiceEntry{lb(map[string]string{"app": "vllm"}, "LoadBalancer")}, false},
		{"gateway-auth false does not count", func() target.WorkloadTarget {
			w := aiWorkload(map[string]string{"app": "vllm"})
			w.Annotations = map[string]string{GatewayAuthKey: "false"}
			return w
		}(), []target.ServiceEntry{lb(map[string]string{"app": "vllm"}, "LoadBalancer")}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := RunContextChecks(tt.w, ScanContext{Services: tt.svcs})
			if got := has(ids(fs), "AIG-010"); got != tt.want {
				t.Errorf("AIG-010 flagged = %v, want %v (%+v)", got, tt.want, fs)
			}
		})
	}
}
