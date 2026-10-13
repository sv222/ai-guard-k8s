package checks

import (
	"fmt"
	"strings"

	"github.com/aiguard/ai-guard-k8s/pkg/detect"
	"github.com/aiguard/ai-guard-k8s/pkg/target"
	corev1 "k8s.io/api/core/v1"
)

var Registry = []CheckFunc{aig001, aig002, aig003, aig004, aig005, aig006, aig007, aig008}

func RunPodSpecChecks(w target.WorkloadTarget) []Finding {
	var out []Finding
	for _, c := range Registry {
		out = append(out, c(w)...)
	}
	return out
}

func (f Finding) on(w target.WorkloadTarget) Finding {
	f.Kind, f.Namespace, f.Name = w.Kind, w.Namespace, w.Name
	return f
}

// AIG-001: missing auth on inference engines (static heuristics).
func aig001(w target.WorkloadTarget) []Finding {
	var out []Finding
	for _, c := range w.Containers() {
		if !detect.IsAIContainer(c) {
			continue
		}
		img := strings.ToLower(c.Image)
		switch {
		case strings.Contains(img, "vllm"):
			if !hasArg(c, "--api-key") && !hasEnv(c, "VLLM_API_KEY", "API_KEY") {
				out = append(out, Finding{
					ID: "AIG-001", Title: "vLLM without API key auth", Severity: "High",
					Evidence: "no --api-key arg and no VLLM_API_KEY/API_KEY env",
					Hint:     "start vllm with --api-key or front it with an authenticating gateway",
				}.on(w))
			}
		default:
			if !hasEnv(c, "API_KEY", "OPENAI_API_KEY", "VLLM_API_KEY") {
				out = append(out, Finding{
					ID: "AIG-001", Title: "Inference engine without engine/gateway auth evidence", Severity: "Medium",
					Evidence: fmt.Sprintf("%s has no auth env (API_KEY/OPENAI_API_KEY) and engine has no native auth", c.Image),
					Hint:     "front with an authenticating gateway (Envoy/Ingress + OAuth2) — engine lacks native auth",
				}.on(w))
			}
		}
	}
	return out
}

// AIG-002: debug endpoints enabled.
func aig002(w target.WorkloadTarget) []Finding {
	var out []Finding
	for _, c := range w.Containers() {
		if !detect.IsAIContainer(c) {
			continue
		}
		if hasArg(c, "--debug") || hasArg(c, "--allow-http") {
			out = append(out, Finding{
				ID: "AIG-002", Title: "Debug/insecure endpoint enabled", Severity: "Medium",
				Evidence: "args contain --debug or --allow-http",
				Hint:     "remove debug flags in production",
			}.on(w))
		}
		if strings.EqualFold(envValue(c, "OLLAMA_DEBUG"), "true") {
			out = append(out, Finding{
				ID: "AIG-002", Title: "OLLAMA_DEBUG=1", Severity: "Medium",
				Evidence: "env OLLAMA_DEBUG=true",
				Hint:     "unset OLLAMA_DEBUG in production",
			}.on(w))
		}
	}
	return out
}

// AIG-003: hostNetwork / hostPID.
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

// AIG-004: hostPath volumes.
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

// AIG-005: root / privilege escalation.
func aig005(w target.WorkloadTarget) []Finding {
	var out []Finding
	sc := w.PodSpec.SecurityContext
	if sc == nil || sc.RunAsNonRoot == nil || !*sc.RunAsNonRoot {
		out = append(out, Finding{ID: "AIG-005", Title: "runAsNonRoot not enforced", Severity: "High",
			Evidence: "pod securityContext.runAsNonRoot != true",
			Hint:     "set runAsNonRoot: true (PSS Restricted)"}.on(w))
	}
	for _, c := range w.Containers() {
		if c.SecurityContext != nil && c.SecurityContext.AllowPrivilegeEscalation != nil &&
			*c.SecurityContext.AllowPrivilegeEscalation {
			out = append(out, Finding{ID: "AIG-005", Title: "allowPrivilegeEscalation", Severity: "High",
				Evidence: fmt.Sprintf("container %s allows privilege escalation", c.Name),
				Hint:     "set allowPrivilegeEscalation: false"}.on(w))
		}
	}
	return out
}

// AIG-006: missing seccomp.
func aig006(w target.WorkloadTarget) []Finding {
	sc := w.PodSpec.SecurityContext
	if sc == nil || sc.SeccompProfile == nil || sc.SeccompProfile.Type == "" {
		return []Finding{Finding{ID: "AIG-006", Title: "no seccomp profile", Severity: "Medium",
			Evidence: "pod securityContext.seccompProfile unset",
			Hint:     "set seccompProfile.type: RuntimeDefault"}.on(w)}
	}
	return nil
}

// AIG-007: missing resources.
func aig007(w target.WorkloadTarget) []Finding {
	var out []Finding
	for _, c := range w.Containers() {
		r := c.Resources
		if r.Limits == nil || r.Requests == nil {
			out = append(out, Finding{ID: "AIG-007", Title: "missing resource requests/limits", Severity: "Low",
				Evidence: fmt.Sprintf("container %s lacks requests or limits", c.Name),
				Hint:     "set both requests and limits (GPU workloads starve nodes)"}.on(w))
		}
	}
	return out
}

// AIG-008: unsafe model execution (static only).
func aig008(w target.WorkloadTarget) []Finding {
	var out []Finding
	unsafeExts := []string{".bin", ".pt", ".pth", ".pkl", ".ckpt"}
	for _, c := range w.Containers() {
		if !detect.IsAIContainer(c) {
			continue
		}
		if hasArg(c, "--trust-remote-code") {
			out = append(out, Finding{ID: "AIG-008", Title: "--trust-remote-code enabled", Severity: "High",
				Evidence: "args include --trust-remote-code (arbitrary Python exec from model repo)",
				Hint:     "remove --trust-remote-code; vet model code, prefer SafeTensors"}.on(w))
		}
	ModelLoop:
		for _, a := range c.Args {
			la := strings.ToLower(a)
			for _, ext := range unsafeExts {
				if strings.Contains(la, ext) {
					out = append(out, Finding{ID: "AIG-008", Title: "non-SafeTensors model reference", Severity: "High",
						Evidence: fmt.Sprintf("arg %q references %s (pickle-deserialization risk)", a, ext),
						Hint:     "prefer .safetensors formats"}.on(w))
					continue ModelLoop
				}
			}
			if strings.HasPrefix(la, "s3://") || strings.HasPrefix(la, "gs://") {
				out = append(out, Finding{ID: "AIG-008", Title: "unverified object-storage model source", Severity: "Medium",
					Evidence: fmt.Sprintf("arg %q loads model from unverified object storage", a),
					Hint:     "pin model provenance: digest-verified registry or signed artifacts"}.on(w))
			}
		}
	}
	return out
}

func hasArg(c corev1.Container, arg string) bool {
	for _, a := range c.Args {
		if a == arg || strings.HasPrefix(a, arg+"=") {
			return true
		}
	}
	return false
}

func hasEnv(c corev1.Container, names ...string) bool {
	for _, e := range c.Env {
		for _, n := range names {
			if e.Name == n && e.Value != "" {
				return true
			}
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
