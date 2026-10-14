package checks

import (
	"fmt"
	"strings"

	"github.com/sv222/ai-guard-k8s/pkg/detect"
	"github.com/sv222/ai-guard-k8s/pkg/target"
	corev1 "k8s.io/api/core/v1"
)

var Registry = []CheckFunc{aig001, aig002, aig003, aig004, aig005, aig006, aig007, aig008}

var engineAuthEnv = map[string][]string{
	"vllm":                      {"VLLM_API_KEY"},
	"text-embeddings-inference": {"API_KEY"},
	"llama.cpp":                 {"LLAMA_API_KEY"},
	"llama-cpp":                 {"LLAMA_API_KEY"},
	"local-ai":                  {"LOCALAI_API_KEY", "API_KEY"},
	"localai":                   {"LOCALAI_API_KEY", "API_KEY"},
}

var unknownEngineAuthEnv = []string{"API_KEY", "VLLM_API_KEY", "LLAMA_API_KEY", "LOCALAI_API_KEY"}

var authSecretHints = []string{"api-key", "apikey", "api_key", "api-token", "apitoken", "api_token", "auth", "bearer"}

var nonAuthSecretWords = map[string]bool{
	"hf": true, "huggingface": true, "hugging": true, "aws": true, "s3": true, "gcs": true, "gcp": true, "azure": true,
	"registry": true, "pull": true, "docker": true, "tls": true, "ssh": true,
}

var unsafeModelExts = []string{".bin", ".pt", ".pth", ".pkl", ".pickle", ".ckpt"}

func RunPodSpecChecks(w target.WorkloadTarget) []Finding {
	var out []Finding
	for _, c := range Registry {
		out = append(out, c(w)...)
	}
	return out
}

func aig001(w target.WorkloadTarget) []Finding {
	if hasGatewayAuth(w) {
		return nil
	}
	var out []Finding
	for _, c := range detect.EngineContainers(w) {
		if hasAuthEvidence(c) {
			continue
		}
		if detect.Engine(c) == "vllm" {
			out = append(out, Finding{
				ID: "AIG-001", Title: "vLLM without API key auth", Severity: "High",
				Evidence: fmt.Sprintf("container %s: no --api-key arg and no VLLM_API_KEY env", c.Name),
				Hint:     "start vllm with --api-key or front it with an authenticating gateway",
			}.on(w))
			continue
		}
		out = append(out, Finding{
			ID: "AIG-001", Title: "Inference engine without engine/gateway auth evidence", Severity: "Medium",
			Evidence: fmt.Sprintf("container %s (%s) has no auth evidence and engine has no native auth", c.Name, c.Image),
			Hint:     "front with an authenticating gateway (Envoy/Ingress + OAuth2), the engine lacks native auth",
		}.on(w))
	}
	return out
}

func aig002(w target.WorkloadTarget) []Finding {
	var out []Finding
	for _, c := range detect.EngineContainers(w) {
		if hasArg(c, "--debug") || hasArg(c, "--allow-http") {
			out = append(out, Finding{
				ID: "AIG-002", Title: "Debug/insecure endpoint enabled", Severity: "Medium",
				Evidence: fmt.Sprintf("container %s: args contain --debug or --allow-http", c.Name),
				Hint:     "remove debug flags in production",
			}.on(w))
		}
		if v := strings.ToLower(envValue(c, "OLLAMA_DEBUG")); v == "true" || v == "1" {
			out = append(out, Finding{
				ID: "AIG-002", Title: "OLLAMA_DEBUG enabled", Severity: "Medium",
				Evidence: fmt.Sprintf("container %s: env OLLAMA_DEBUG=%s", c.Name, envValue(c, "OLLAMA_DEBUG")),
				Hint:     "unset OLLAMA_DEBUG in production",
			}.on(w))
		}
	}
	return out
}

func aig003(w target.WorkloadTarget) []Finding {
	var out []Finding
	if w.PodSpec.HostNetwork {
		out = append(out, Finding{ID: "AIG-003", Title: "hostNetwork enabled", Severity: "High",
			Evidence: "spec.hostNetwork: true", Hint: "disable hostNetwork; use Services"}.on(w))
	}
	if w.PodSpec.HostPID {
		out = append(out, Finding{ID: "AIG-003", Title: "hostPID enabled", Severity: "High",
			Evidence: "spec.hostPID: true", Hint: "disable hostPID"}.on(w))
	}
	return out
}

func aig004(w target.WorkloadTarget) []Finding {
	var out []Finding
	for _, v := range w.PodSpec.Volumes {
		if v.HostPath != nil {
			out = append(out, Finding{ID: "AIG-004", Title: "hostPath volume", Severity: "High",
				Evidence: fmt.Sprintf("volume %s mounts host path %s", v.Name, v.HostPath.Path),
				Hint:     "use PVCs or emptyDir"}.on(w))
		}
	}
	return out
}

func aig005(w target.WorkloadTarget) []Finding {
	var out []Finding
	pod := w.PodSpec.SecurityContext
	for _, c := range w.AllContainers() {
		user := effectiveRunAsUser(pod, c.SecurityContext)
		nonRoot := effectiveRunAsNonRoot(pod, c.SecurityContext)
		switch {
		case user != nil && *user == 0:
			out = append(out, Finding{ID: "AIG-005", Title: "runs as root", Severity: "High",
				Evidence: fmt.Sprintf("container %s: effective runAsUser: 0", c.Name),
				Hint:     "set runAsUser to a non-zero UID and runAsNonRoot: true (PSS Restricted)"}.on(w))
		case nonRoot != nil && *nonRoot:
		case user != nil:
			out = append(out, Finding{ID: "AIG-005", Title: "runAsNonRoot not enforced", Severity: "High",
				Evidence: fmt.Sprintf("container %s: runAsUser: %d is set but runAsNonRoot is not true (container or pod level)", c.Name, *user),
				Hint:     "set runAsNonRoot: true; PSS Restricted does not accept runAsUser alone"}.on(w))
		default:
			out = append(out, Finding{ID: "AIG-005", Title: "runAsNonRoot not enforced", Severity: "High",
				Evidence: fmt.Sprintf("container %s: runAsNonRoot: true is not set (container or pod level)", c.Name),
				Hint:     "set runAsNonRoot: true (PSS Restricted)"}.on(w))
		}
		if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
			out = append(out, Finding{ID: "AIG-005", Title: "privileged container", Severity: "High",
				Evidence: fmt.Sprintf("container %s: securityContext.privileged: true", c.Name),
				Hint:     "remove privileged: true and grant only the needed capabilities"}.on(w))
		}
		var ape *bool
		if c.SecurityContext != nil {
			ape = c.SecurityContext.AllowPrivilegeEscalation
		}
		switch {
		case ape == nil:
			out = append(out, Finding{ID: "AIG-005", Title: "allowPrivilegeEscalation not disabled", Severity: "High",
				Evidence: fmt.Sprintf("container %s: allowPrivilegeEscalation unset (defaults to true)", c.Name),
				Hint:     "set allowPrivilegeEscalation: false (PSS Restricted)"}.on(w))
		case *ape:
			out = append(out, Finding{ID: "AIG-005", Title: "allowPrivilegeEscalation", Severity: "High",
				Evidence: fmt.Sprintf("container %s: allowPrivilegeEscalation: true", c.Name),
				Hint:     "set allowPrivilegeEscalation: false"}.on(w))
		}
	}
	return out
}

func aig006(w target.WorkloadTarget) []Finding {
	var out []Finding
	pod := w.PodSpec.SecurityContext
	for _, c := range w.AllContainers() {
		p := effectiveSeccomp(pod, c.SecurityContext)
		switch {
		case p == nil:
			out = append(out, Finding{ID: "AIG-006", Title: "no seccomp profile", Severity: "Medium",
				Evidence: fmt.Sprintf("container %s: seccompProfile unset (container and pod level)", c.Name),
				Hint:     "set seccompProfile.type: RuntimeDefault"}.on(w))
		case p.Type == corev1.SeccompProfileTypeUnconfined:
			out = append(out, Finding{ID: "AIG-006", Title: "seccomp profile Unconfined", Severity: "Medium",
				Evidence: fmt.Sprintf("container %s: effective seccompProfile.type: Unconfined", c.Name),
				Hint:     "set seccompProfile.type: RuntimeDefault"}.on(w))
		}
	}
	return out
}

func aig007(w target.WorkloadTarget) []Finding {
	var out []Finding
	for _, c := range w.AllContainers() {
		var missing []string
		if !hasResource(c.Resources.Requests, corev1.ResourceMemory) {
			missing = append(missing, "requests.memory")
		}
		if !hasResource(c.Resources.Requests, corev1.ResourceCPU) {
			missing = append(missing, "requests.cpu")
		}
		if !hasResource(c.Resources.Limits, corev1.ResourceMemory) {
			missing = append(missing, "limits.memory")
		}
		if len(missing) > 0 {
			out = append(out, Finding{ID: "AIG-007", Title: "missing resource requests/limits", Severity: "Low",
				Evidence: fmt.Sprintf("container %s lacks %s", c.Name, strings.Join(missing, ", ")),
				Hint:     "set requests.memory, requests.cpu and limits.memory (GPU workloads starve nodes)"}.on(w))
		}
	}
	return out
}

func hasResource(l corev1.ResourceList, name corev1.ResourceName) bool {
	_, ok := l[name]
	return ok
}

func aig008(w target.WorkloadTarget) []Finding {
	var out []Finding
	for _, c := range detect.EngineContainers(w) {
		if hasArg(c, "--trust-remote-code") {
			out = append(out, Finding{ID: "AIG-008", Title: "--trust-remote-code enabled", Severity: "High",
				Evidence: fmt.Sprintf("container %s: args include --trust-remote-code (arbitrary Python exec from model repo)", c.Name),
				Hint:     "remove --trust-remote-code; vet model code, prefer SafeTensors"}.on(w))
		}
		for _, v := range modelValues(c) {
			if ext := unsafeExt(v.value); ext != "" {
				out = append(out, Finding{ID: "AIG-008", Title: "non-SafeTensors model reference", Severity: "High",
					Evidence: fmt.Sprintf("container %s: %s %q references %s (pickle-deserialization risk)", c.Name, v.kind, v.raw, ext),
					Hint:     "prefer .safetensors formats"}.on(w))
				continue
			}
			lv := strings.ToLower(v.value)
			if strings.HasPrefix(lv, "s3://") || strings.HasPrefix(lv, "gs://") {
				out = append(out, Finding{ID: "AIG-008", Title: "unverified object-storage model source", Severity: "Medium",
					Evidence: fmt.Sprintf("container %s: %s %q loads model from unverified object storage", c.Name, v.kind, v.raw),
					Hint:     "pin model provenance: digest-verified registry or signed artifacts"}.on(w))
			}
		}
	}
	return out
}

type modelValue struct {
	kind, raw, value string
}

func modelValues(c corev1.Container) []modelValue {
	var out []modelValue
	for _, a := range target.CommandLine(c) {
		out = append(out, modelValue{kind: "arg", raw: a, value: argValue(a)})
	}
	for _, e := range c.Env {
		if e.Value != "" {
			out = append(out, modelValue{kind: "env " + e.Name, raw: e.Value, value: e.Value})
		}
	}
	return out
}

func argValue(a string) string {
	if strings.HasPrefix(a, "-") {
		if i := strings.Index(a, "="); i >= 0 {
			return a[i+1:]
		}
		return ""
	}
	return a
}

func unsafeExt(v string) string {
	if i := strings.IndexAny(v, "?#"); i >= 0 {
		v = v[:i]
	}
	v = strings.ToLower(v)
	for _, ext := range unsafeModelExts {
		if strings.HasSuffix(v, ext) {
			return ext
		}
	}
	return ""
}

func effectiveRunAsUser(pod *corev1.PodSecurityContext, c *corev1.SecurityContext) *int64 {
	if c != nil && c.RunAsUser != nil {
		return c.RunAsUser
	}
	if pod != nil {
		return pod.RunAsUser
	}
	return nil
}

func effectiveRunAsNonRoot(pod *corev1.PodSecurityContext, c *corev1.SecurityContext) *bool {
	if c != nil && c.RunAsNonRoot != nil {
		return c.RunAsNonRoot
	}
	if pod != nil {
		return pod.RunAsNonRoot
	}
	return nil
}

func effectiveSeccomp(pod *corev1.PodSecurityContext, c *corev1.SecurityContext) *corev1.SeccompProfile {
	if c != nil && c.SeccompProfile != nil && c.SeccompProfile.Type != "" {
		return c.SeccompProfile
	}
	if pod != nil && pod.SeccompProfile != nil && pod.SeccompProfile.Type != "" {
		return pod.SeccompProfile
	}
	return nil
}

func hasArg(c corev1.Container, arg string) bool {
	for _, a := range target.CommandLine(c) {
		if a == arg || strings.HasPrefix(a, arg+"=") {
			return true
		}
	}
	return false
}

func hasEnv(c corev1.Container, names ...string) bool {
	for _, e := range c.Env {
		for _, n := range names {
			if e.Name == n && (e.Value != "" || e.ValueFrom != nil) {
				return true
			}
		}
	}
	return false
}

func authEnvNames(c corev1.Container) []string {
	if e := detect.Engine(c); e != "" {
		return engineAuthEnv[e]
	}
	return unknownEngineAuthEnv
}

func hasAuthEvidence(c corev1.Container) bool {
	return hasArg(c, "--api-key") || hasEnv(c, authEnvNames(c)...) || hasAuthEnvFrom(c)
}

func hasAuthEnvFrom(c corev1.Container) bool {
	for _, ef := range c.EnvFrom {
		if ef.SecretRef == nil {
			continue
		}
		name := strings.ToLower(ef.SecretRef.Name)
		if hasNonAuthWord(name) {
			continue
		}
		for _, hint := range authSecretHints {
			if strings.Contains(name, hint) {
				return true
			}
		}
	}
	return false
}

func hasNonAuthWord(name string) bool {
	words := strings.FieldsFunc(name, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
	})
	for _, w := range words {
		if nonAuthSecretWords[w] {
			return true
		}
	}
	return false
}

func envValue(c corev1.Container, name string) string {
	for _, e := range c.Env {
		if e.Name == name {
			return e.Value
		}
	}
	return ""
}
