package checks

import (
	"testing"

	"github.com/aiguard/ai-guard-k8s/pkg/target"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func aiWorkload(labels map[string]string) target.WorkloadTarget {
	return target.WorkloadTarget{
		Kind: "Deployment", Namespace: "llm", Name: "vllm", Labels: labels,
		PodSpec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "vllm/vllm-openai"}}},
	}
}

func TestAIG009NoNetPol(t *testing.T) {
	fs := RunContextChecks(aiWorkload(map[string]string{"app": "vllm"}), ScanContext{})
	if !has(ids(fs), "AIG-009") {
		t.Errorf("expected AIG-009, got %v", ids(fs))
	}
}

func TestAIG009CoveredByNetPol(t *testing.T) {
	ctx := ScanContext{NetPols: []target.NetworkPolicyEntry{
		{Namespace: "llm", PodSelector: metav1LabelSelector(map[string]string{"app": "vllm"})},
	}}
	fs := RunContextChecks(aiWorkload(map[string]string{"app": "vllm"}), ctx)
	if has(ids(fs), "AIG-009") {
		t.Error("AIG-009 must not fire when a matching NetworkPolicy exists")
	}
}

func TestAIG010ExposedLB(t *testing.T) {
	ctx := ScanContext{Services: []target.ServiceEntry{
		{Namespace: "llm", Name: "svc", Type: "LoadBalancer", Selector: map[string]string{"app": "vllm"}, Ports: []int32{80}},
	}}
	fs := RunContextChecks(aiWorkload(map[string]string{"app": "vllm"}), ctx)
	if !has(ids(fs), "AIG-010") {
		t.Errorf("expected AIG-010, got %v", ids(fs))
	}
}

func metav1LabelSelector(m map[string]string) metav1.LabelSelector {
	return metav1.LabelSelector{MatchLabels: m}
}
