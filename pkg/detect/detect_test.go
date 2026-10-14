package detect

import (
	"testing"

	"github.com/sv222/ai-guard-k8s/pkg/target"
	corev1 "k8s.io/api/core/v1"
)

func mk(name, image string, labels map[string]string) target.WorkloadTarget {
	return target.WorkloadTarget{
		Kind: "Deployment", Namespace: "default", Name: name, Labels: labels,
		PodSpec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: image}}},
	}
}

func TestImageMatch(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{"vllm/vllm-openai:v0.6.0", true},
		{"ollama/ollama:latest", true},
		{"nvcr.io/nvidia/tritonserver:24.05-py3", true},
		{"ghcr.io/huggingface/text-generation-inference:2.0", true},
		{"rayproject/ray-serve:2.9", true},
		{"registry.io/platform/genai:v1", false},
		{"nginx:1.27", false},
		{"ghcr.io/huggingface/text-embeddings-inference:cpu-1.9", true},
		{"quay.io/go-skynet/local-ai:latest", true},
		{"localai/localai:latest-aio-cpu", true},
		{"lmsysorg/sglang:v0.4.6", true},
		{"ghcr.io/ggml-org/llama.cpp:server", true},
		{"openmmlab/lmdeploy:latest", true},
		{"postgis/postgis:16-3.4", false},
		{"ghcr.io/huggingface/tgi:3.0", true},
		{"registry.io/ml/tgi-server:1", true},
		{"registry.io/ml/server-tgi", true},
	}
	for _, tt := range tests {
		if got := IsAIWorkload(mk("x", tt.image, nil), ""); got != tt.want {
			t.Errorf("IsAIWorkload(%s) = %v, want %v", tt.image, got, tt.want)
		}
	}
}

func TestNameMatch(t *testing.T) {
	if !IsAIWorkload(mk("my-ollama", "internal/img", nil), "") {
		t.Error("workload name containing ollama should match")
	}
}

func TestLabelOptIn(t *testing.T) {
	w := mk("genai", "internal-registry.io/platform/genai-service:v1.2",
		map[string]string{"ai.infra.guard/enabled": "true"})
	if !IsAIWorkload(w, "") {
		t.Error("label opt-in should detect renamed enterprise image")
	}
}

func TestLabelOptInFromWorkloadMetadata(t *testing.T) {
	w := mk("genai", "internal/genai:v1", nil)
	w.MetaLabels = map[string]string{"ai.infra.guard/enabled": "true"}
	if !IsAIWorkload(w, "") {
		t.Error("opt-in label on workload metadata should detect")
	}
	w.MetaLabels = map[string]string{"ai.infra.guard/enabled": "false"}
	if IsAIWorkload(w, "") {
		t.Error("opt-in label with value false must not detect")
	}
}

func TestAnnotationOptIn(t *testing.T) {
	w := mk("genai", "internal/genai:v1", nil)
	w.MetaAnnotations = map[string]string{"ai.infra.guard/enabled": "true"}
	if !IsAIWorkload(w, "") {
		t.Error("opt-in annotation should detect")
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
	if !IsAIWorkload(w, "tier in (inference,batch)") {
		t.Error("set-based selector should detect")
	}
}

func TestSelectorMatchesMetaLabels(t *testing.T) {
	w := mk("svc", "nginx", nil)
	w.MetaLabels = map[string]string{"tier": "inference"}
	if !IsAIWorkload(w, "tier=inference") {
		t.Error("selector should consider workload metadata labels")
	}
}

func TestValidateSelector(t *testing.T) {
	if err := ValidateSelector(""); err != nil {
		t.Error(err)
	}
	if err := ValidateSelector("a=b,c!=d"); err != nil {
		t.Error(err)
	}
	if err := ValidateSelector("a=b=="); err == nil {
		t.Error("expected error for malformed selector")
	}
}

func TestIsAIContainer(t *testing.T) {
	if !IsAIContainer(corev1.Container{Image: "VLLM/vllm"}) || IsAIContainer(corev1.Container{Image: "envoy"}) {
		t.Error("IsAIContainer wrong")
	}
}
