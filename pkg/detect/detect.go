package detect

import (
	"strings"

	"github.com/sv222/ai-guard-k8s/pkg/target"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
)

const EnableLabel = "ai.infra.guard/enabled"

var patterns = []string{
	"vllm", "ollama", "tritonserver", "text-generation-inference", "tgi", "ray-serve",
	"text-embeddings-inference", "local-ai", "localai", "sglang", "llama.cpp", "llama-cpp", "lmdeploy", "tensorrt-llm",
}

var wordPatterns = map[string]bool{"tgi": true}

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
	return matchesPattern(hay)
}

func matchesPattern(s string) bool {
	for _, p := range patterns {
		if containsPattern(s, p) {
			return true
		}
	}
	return false
}

func containsPattern(s, p string) bool {
	if !wordPatterns[p] {
		return strings.Contains(s, p)
	}
	for from := 0; from < len(s); {
		i := strings.Index(s[from:], p)
		if i < 0 {
			return false
		}
		start := from + i
		end := start + len(p)
		if (start == 0 || !isAlnum(s[start-1])) && (end == len(s) || !isAlnum(s[end])) {
			return true
		}
		from = start + 1
	}
	return false
}

func isAlnum(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= '0' && b <= '9'
}

func IsAIContainer(c corev1.Container) bool {
	return matchesPattern(strings.ToLower(c.Image))
}
