package checks

import (
	"testing"

	"github.com/aiguard/ai-guard-k8s/pkg/target"
	corev1 "k8s.io/api/core/v1"
)

func vllm(args []string, env []corev1.EnvVar, sec *corev1.SecurityContext) target.WorkloadTarget {
	return target.WorkloadTarget{
		Kind: "Deployment", Namespace: "llm", Name: "vllm",
		PodSpec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "server", Image: "vllm/vllm-openai:v0.6.0",
			Args: args, Env: env, SecurityContext: sec,
		}}},
	}
}

func ids(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.ID)
	}
	return out
}

func TestAIG001NoApiKey(t *testing.T) {
	fs := RunPodSpecChecks(vllm([]string{"--model", "m"}, nil, nil))
	found := false
	for _, id := range ids(fs) {
		if id == "AIG-001" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected AIG-001, got %v", ids(fs))
	}
}

func TestAIG001ApiKeyArgOK(t *testing.T) {
	fs := RunPodSpecChecks(vllm([]string{"--api-key", "secret"}, nil, nil))
	for _, id := range ids(fs) {
		if id == "AIG-001" {
			t.Errorf("AIG-001 should not fire when --api-key present")
		}
	}
}

func TestAIG002Debug(t *testing.T) {
	fs := RunPodSpecChecks(vllm([]string{"--debug"}, nil, nil))
	if !has(ids(fs), "AIG-002") {
		t.Errorf("expected AIG-002, got %v", ids(fs))
	}
}

func TestAIG003HostNetwork(t *testing.T) {
	w := vllm(nil, nil, nil)
	w.PodSpec.HostNetwork = true
	if !has(ids(RunPodSpecChecks(w)), "AIG-003") {
		t.Error("expected AIG-003")
	}
}

func TestAIG005Root(t *testing.T) {
	fs := RunPodSpecChecks(vllm(nil, nil, &corev1.SecurityContext{RunAsUser: ptr64(0)}))
	if !has(ids(fs), "AIG-005") {
		t.Error("expected AIG-005 for runAsUser=0")
	}
}

func TestAIG008TrustRemoteCodeAndPickle(t *testing.T) {
	fs := RunPodSpecChecks(vllm([]string{"--trust-remote-code", "--model", "/data/model.pt"}, nil, nil))
	if !has(ids(fs), "AIG-008") {
		t.Errorf("expected AIG-008, got %v", ids(fs))
	}
}

func has(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func ptr64(i int64) *int64 { return &i }
