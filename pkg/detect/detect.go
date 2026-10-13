package detect

import (
	"strings"

	"github.com/aiguard/ai-guard-k8s/pkg/target"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
)

const EnableLabel = "ai.infra.guard/enabled"

var patterns = []string{
	"vllm", "ollama", "tritonserver", "text-generation-inference", "tgi", "ray-serve",
}

func ValidateSelector(sel string) error {
	if strings.TrimSpace(sel) == "" {
		return nil
	}
	_, err := labels.Parse(sel)
	return err
}

func IsAIWorkload(w target.WorkloadTarget, extraSelector string) bool {
	all := w.MergedLabels()
	if all[EnableLabel] == "true" || w.MergedAnnotations()[EnableLabel] == "true" {
		return true
	}
	if strings.TrimSpace(extraSelector) != "" {
		if sel, err := labels.Parse(extraSelector); err == nil && sel.Matches(labels.Set(all)) {
			return true
		}
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

func IsAIContainer(c corev1.Container) bool {
	img := strings.ToLower(c.Image)
	for _, p := range patterns {
		if strings.Contains(img, p) {
			return true
		}
	}
	return false
}
