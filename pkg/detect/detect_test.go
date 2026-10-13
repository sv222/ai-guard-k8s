package detect

import (
	"testing"

	"github.com/aiguard/ai-guard-k8s/pkg/target"
	corev1 "k8s.io/api/core/v1"
)

func mk(name, image string, labels map[string]string) target.WorkloadTarget {
	return target.WorkloadTarget{
		Kind: "Deployment", Namespace: "default", Name: name, Labels: labels,
		PodSpec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: image}}},
	}
}

func TestImageMatch(t *testing.T) {
	for _, img := range []string{
		"vllm/vllm-openai:v0.6.0",
		"registry.io/platform/genai:v1", // no match expected
	} {
		got := IsAIWorkload(mk("x", img, nil), "")
		want := img == "vllm/vllm-openai:v0.6.0"
		if got != want {
			t.Errorf("IsAIWorkload(%s) = %v, want %v", img, got, want)
		}
	}
}

func TestLabelOptIn(t *testing.T) {
	w := mk("genai", "internal-registry.io/platform/genai-service:v1.2",
		map[string]string{"ai.infra.guard/enabled": "true"})
	if !IsAIWorkload(w, "") {
		t.Error("label opt-in should detect renamed enterprise image")
	}
}

func TestSelectorOverride(t *testing.T) {
	w := mk("svc", "nginx", map[string]string{"tier": "inference"})
	if !IsAIWorkload(w, "tier=inference") {
		t.Error("selector override should detect")
	}
	if IsAIWorkload(w, "tier=web") {
		t.Error("non-matching selector must not detect")
	}
}
