package detect

import (
	"strings"

	"github.com/aiguard/ai-guard-k8s/pkg/target"
	corev1 "k8s.io/api/core/v1"
)

const EnableLabel = "ai.infra.guard/enabled"

var patterns = []string{
	"vllm", "ollama", "tritonserver", "text-generation-inference", "tgi", "ray-serve",
}

// IsAIWorkload reports whether w is an AI inference workload:
// image/name pattern, opt-in label, or user selector (k=v,k=v AND semantics).
func IsAIWorkload(w target.WorkloadTarget, extraSelector string) bool {
	if w.Labels[EnableLabel] == "true" {
		return true
	}
	if extraSelector != "" && selectorMatches(extraSelector, w.Labels) {
		return true
	}
	hay := strings.ToLower(w.Name)
	for _, c := range w.Containers() {
		hay += " " + strings.ToLower(c.Image)
	}
	for _, p := range patterns {
		if strings.Contains(hay, p) {
			return true
		}
	}
	return false
}

func selectorMatches(sel string, labels map[string]string) bool {
	for _, kv := range strings.Split(sel, ",") {
		parts := strings.SplitN(strings.TrimSpace(kv), "=", 2)
		if len(parts) != 2 || labels[parts[0]] != parts[1] {
			return false
		}
	}
	return true
}

// IsAIContainer reports whether one container matches known inference images.
func IsAIContainer(c corev1.Container) bool {
	img := strings.ToLower(c.Image)
	for _, p := range patterns {
		if strings.Contains(img, p) {
			return true
		}
	}
	return false
}
