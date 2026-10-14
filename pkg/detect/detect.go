package detect

import (
	"path"
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

func OptedIn(w target.WorkloadTarget, extraSelector string) bool {
	all := w.MergedLabels()
	if all[EnableLabel] == "true" || w.MergedAnnotations()[EnableLabel] == "true" {
		return true
	}
	if strings.TrimSpace(extraSelector) != "" {
		if sel, err := labels.Parse(extraSelector); err == nil && sel.Matches(labels.Set(all)) {
			return true
		}
	}
	return false
}

func EngineContainers(w target.WorkloadTarget) []corev1.Container {
	var out []corev1.Container
	for _, c := range w.Containers() {
		if IsAIContainer(c) {
			out = append(out, c)
		}
	}
	if len(out) == 0 && w.OptIn && len(w.Containers()) == 1 {
		return w.Containers()
	}
	return out
}

func IsAIWorkload(w target.WorkloadTarget, extraSelector string) bool {
	if OptedIn(w, extraSelector) {
		return true
	}
	hay := strings.ToLower(w.Name)
	for _, c := range w.Containers() {
		hay += " " + strings.ToLower(c.Image)
	}
	if matchesPattern(hay) {
		return true
	}
	for _, c := range w.Containers() {
		if Engine(c) != "" {
			return true
		}
	}
	return false
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

func Engine(c corev1.Container) string {
	img := strings.ToLower(c.Image)
	for _, p := range patterns {
		if containsPattern(img, p) {
			return p
		}
	}
	if isRayImage(img) && hasServeToken(target.CommandLine(c)) {
		return "ray-serve"
	}
	return engineFromCommand(target.CommandLine(c))
}

func IsAIContainer(c corev1.Container) bool {
	return Engine(c) != ""
}

var engineBinaries = map[string]string{
	"vllm":                     "vllm",
	"ollama":                   "ollama",
	"tritonserver":             "tritonserver",
	"text-generation-launcher": "text-generation-inference",
	"text-generation-router":   "text-generation-inference",
	"text-embeddings-router":   "text-embeddings-inference",
	"llama-server":             "llama.cpp",
	"sglang":                   "sglang",
	"lmdeploy":                 "lmdeploy",
	"local-ai":                 "local-ai",
	"trtllm-serve":             "tensorrt-llm",
}

var engineModules = map[string]string{
	"vllm":   "vllm",
	"sglang": "sglang",
}

var commandStarters = map[string]bool{"-c": true, "exec": true, "&&": true, "||": true, ";": true, "|": true, "then": true, "do": true}

func engineFromCommand(tokens []string) string {
	for i := 0; i < len(tokens); i++ {
		afterModule := i > 0 && tokens[i-1] == "-m"
		if i > 0 && !commandStarters[tokens[i-1]] && !afterModule {
			continue
		}
		t := strings.ToLower(strings.Trim(tokens[i], "\"';"))
		if afterModule {
			if e, ok := engineModules[strings.SplitN(t, ".", 2)[0]]; ok {
				return e
			}
			continue
		}
		if e, ok := engineBinaries[path.Base(t)]; ok {
			return e
		}
	}
	return ""
}

func isRayImage(img string) bool {
	if i := strings.IndexAny(img, "@"); i >= 0 {
		img = img[:i]
	}
	if i := strings.LastIndex(img, ":"); i > strings.LastIndex(img, "/") {
		img = img[:i]
	}
	base := path.Base(img)
	return strings.Contains(img, "rayproject/ray") || base == "ray" || strings.HasPrefix(base, "ray-")
}

func hasServeToken(tokens []string) bool {
	for _, t := range tokens {
		if strings.ToLower(strings.Trim(t, "\"';")) == "serve" {
			return true
		}
	}
	return false
}
