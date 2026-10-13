package checks

import (
	"strings"
	"testing"

	"github.com/aiguard/ai-guard-k8s/pkg/target"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

func ptr[T any](v T) *T { return &v }

func resources() corev1.ResourceRequirements {
	rl := corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("1"), corev1.ResourceMemory: resource.MustParse("1Gi")}
	return corev1.ResourceRequirements{Requests: rl, Limits: rl}
}

func clean() target.WorkloadTarget {
	return target.WorkloadTarget{
		Kind: "Deployment", Namespace: "llm", Name: "vllm",
		PodSpec: corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot:   ptr(true),
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			Containers: []corev1.Container{{
				Name: "server", Image: "vllm/vllm-openai:v0.6.0",
				Args:            []string{"--model", "m", "--api-key", "k"},
				SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: ptr(false)},
				Resources:       resources(),
			}},
		},
	}
}

func vllm(args []string, env []corev1.EnvVar, sec *corev1.SecurityContext) target.WorkloadTarget {
	w := clean()
	c := &w.PodSpec.Containers[0]
	c.Args, c.Env, c.SecurityContext = args, env, sec
	return w
}

func ids(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.ID)
	}
	return out
}

func count(fs []Finding, id string) int {
	n := 0
	for _, f := range fs {
		if f.ID == id {
			n++
		}
	}
	return n
}

func has(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func TestCleanWorkloadHasNoFindings(t *testing.T) {
	if fs := RunPodSpecChecks(clean()); len(fs) != 0 {
		t.Fatalf("clean workload produced findings: %+v", fs)
	}
}

func TestPodSpecChecks(t *testing.T) {
	ollama := func(env ...corev1.EnvVar) func(*target.WorkloadTarget) {
		return func(w *target.WorkloadTarget) {
			c := &w.PodSpec.Containers[0]
			c.Image, c.Args, c.Env = "ollama/ollama:latest", nil, env
		}
	}
	container := func(f func(c *corev1.Container)) func(*target.WorkloadTarget) {
		return func(w *target.WorkloadTarget) { f(&w.PodSpec.Containers[0]) }
	}
	pod := func(f func(p *corev1.PodSpec)) func(*target.WorkloadTarget) {
		return func(w *target.WorkloadTarget) { f(&w.PodSpec) }
	}
	tests := []struct {
		name   string
		mutate func(*target.WorkloadTarget)
		id     string
		want   int
	}{
		{"001 vllm no key", container(func(c *corev1.Container) { c.Args = []string{"--model", "m"} }), "AIG-001", 1},
		{"001 vllm key arg", container(func(c *corev1.Container) { c.Args = []string{"--api-key=abc"} }), "AIG-001", 0},
		{"001 vllm key env", container(func(c *corev1.Container) {
			c.Args = nil
			c.Env = []corev1.EnvVar{{Name: "VLLM_API_KEY", Value: "x"}}
		}), "AIG-001", 0},
		{"001 vllm key from secret", container(func(c *corev1.Container) {
			c.Args = nil
			c.Env = []corev1.EnvVar{{Name: "VLLM_API_KEY", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{}}}}
		}), "AIG-001", 0},
		{"001 ollama no auth", ollama(), "AIG-001", 1},
		{"001 ollama api key env", ollama(corev1.EnvVar{Name: "API_KEY", Value: "x"}), "AIG-001", 0},
		{"001 gateway annotation", func(w *target.WorkloadTarget) {
			w.Annotations = map[string]string{GatewayAuthKey: "true"}
			w.PodSpec.Containers[0].Args = nil
		}, "AIG-001", 0},
		{"001 non-ai container", container(func(c *corev1.Container) { c.Image, c.Args = "nginx", nil }), "AIG-001", 0},

		{"002 debug flag", container(func(c *corev1.Container) { c.Args = append(c.Args, "--debug") }), "AIG-002", 1},
		{"002 allow-http", container(func(c *corev1.Container) { c.Args = append(c.Args, "--allow-http=true") }), "AIG-002", 1},
		{"002 ollama debug", ollama(corev1.EnvVar{Name: "OLLAMA_DEBUG", Value: "true"}), "AIG-002", 1},
		{"002 ollama debug 1", ollama(corev1.EnvVar{Name: "OLLAMA_DEBUG", Value: "1"}), "AIG-002", 1},
		{"002 ollama debug off", ollama(corev1.EnvVar{Name: "OLLAMA_DEBUG", Value: "false"}), "AIG-002", 0},
		{"002 clean", func(*target.WorkloadTarget) {}, "AIG-002", 0},

		{"003 hostNetwork", pod(func(p *corev1.PodSpec) { p.HostNetwork = true }), "AIG-003", 1},
		{"003 hostPID", pod(func(p *corev1.PodSpec) { p.HostPID = true }), "AIG-003", 1},
		{"003 both", pod(func(p *corev1.PodSpec) { p.HostNetwork, p.HostPID = true, true }), "AIG-003", 2},
		{"003 clean", func(*target.WorkloadTarget) {}, "AIG-003", 0},

		{"004 hostPath", pod(func(p *corev1.PodSpec) {
			p.Volumes = []corev1.Volume{{Name: "m", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/m"}}}}
		}), "AIG-004", 1},
		{"004 emptyDir", pod(func(p *corev1.PodSpec) {
			p.Volumes = []corev1.Volume{{Name: "m", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}}
		}), "AIG-004", 0},

		{"005 container runAsUser 0 overrides pod nonroot", container(func(c *corev1.Container) {
			c.SecurityContext.RunAsUser = ptr(int64(0))
		}), "AIG-005", 1},
		{"005 container nonzero user overrides pod root", func(w *target.WorkloadTarget) {
			w.PodSpec.SecurityContext = &corev1.PodSecurityContext{RunAsUser: ptr(int64(0))}
			w.PodSpec.Containers[0].SecurityContext.RunAsUser = ptr(int64(1000))
		}, "AIG-005", 0},
		{"005 pod runAsUser 0", func(w *target.WorkloadTarget) {
			w.PodSpec.SecurityContext = &corev1.PodSecurityContext{RunAsUser: ptr(int64(0))}
		}, "AIG-005", 1},
		{"005 container-only runAsNonRoot", func(w *target.WorkloadTarget) {
			w.PodSpec.SecurityContext = nil
			w.PodSpec.Containers[0].SecurityContext.RunAsNonRoot = ptr(true)
		}, "AIG-005", 0},
		{"005 container runAsNonRoot false overrides pod true", container(func(c *corev1.Container) {
			c.SecurityContext.RunAsNonRoot = ptr(false)
		}), "AIG-005", 1},
		{"005 nothing set", func(w *target.WorkloadTarget) {
			w.PodSpec.SecurityContext = nil
			w.PodSpec.Containers[0].SecurityContext = nil
		}, "AIG-005", 2},
		{"005 privileged", container(func(c *corev1.Container) { c.SecurityContext.Privileged = ptr(true) }), "AIG-005", 1},
		{"005 privileged false", container(func(c *corev1.Container) { c.SecurityContext.Privileged = ptr(false) }), "AIG-005", 0},
		{"005 ape true", container(func(c *corev1.Container) { c.SecurityContext.AllowPrivilegeEscalation = ptr(true) }), "AIG-005", 1},
		{"005 ape unset", container(func(c *corev1.Container) { c.SecurityContext.AllowPrivilegeEscalation = nil }), "AIG-005", 1},
		{"005 init container root", pod(func(p *corev1.PodSpec) {
			p.InitContainers = []corev1.Container{{Name: "i", Image: "busybox", SecurityContext: &corev1.SecurityContext{
				RunAsUser: ptr(int64(0)), AllowPrivilegeEscalation: ptr(false)}, Resources: resources()}}
		}), "AIG-005", 1},

		{"006 container-level profile counts", func(w *target.WorkloadTarget) {
			w.PodSpec.SecurityContext = &corev1.PodSecurityContext{RunAsNonRoot: ptr(true)}
			w.PodSpec.Containers[0].SecurityContext.SeccompProfile = &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}
		}, "AIG-006", 0},
		{"006 unset", func(w *target.WorkloadTarget) {
			w.PodSpec.SecurityContext = &corev1.PodSecurityContext{RunAsNonRoot: ptr(true)}
		}, "AIG-006", 1},
		{"006 container unconfined", container(func(c *corev1.Container) {
			c.SecurityContext.SeccompProfile = &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined}
		}), "AIG-006", 1},
		{"006 pod unconfined", func(w *target.WorkloadTarget) {
			w.PodSpec.SecurityContext.SeccompProfile = &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined}
		}, "AIG-006", 1},
		{"006 pod unconfined container overrides", func(w *target.WorkloadTarget) {
			w.PodSpec.SecurityContext.SeccompProfile = &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined}
			w.PodSpec.Containers[0].SecurityContext.SeccompProfile = &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}
		}, "AIG-006", 0},
		{"006 init container", pod(func(p *corev1.PodSpec) {
			p.InitContainers = []corev1.Container{{Name: "i", Image: "busybox", SecurityContext: &corev1.SecurityContext{
				AllowPrivilegeEscalation: ptr(false), SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined}}, Resources: resources()}}
		}), "AIG-006", 1},

		{"007 missing limits", container(func(c *corev1.Container) { c.Resources.Limits = nil }), "AIG-007", 1},
		{"007 missing requests", container(func(c *corev1.Container) { c.Resources.Requests = nil }), "AIG-007", 1},
		{"007 init missing", pod(func(p *corev1.PodSpec) {
			p.InitContainers = []corev1.Container{{Name: "i", Image: "busybox", SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: ptr(false)}}}
		}), "AIG-007", 1},
		{"007 clean", func(*target.WorkloadTarget) {}, "AIG-007", 0},

		{"008 trust-remote-code", container(func(c *corev1.Container) { c.Args = append(c.Args, "--trust-remote-code") }), "AIG-008", 1},
		{"008 bin file", container(func(c *corev1.Container) { c.Args = append(c.Args, "--model", "/data/model.bin") }), "AIG-008", 1},
		{"008 pt eq form", container(func(c *corev1.Container) { c.Args = append(c.Args, "--model=/data/model.PT") }), "AIG-008", 1},
		{"008 pth url with query", container(func(c *corev1.Container) { c.Args = append(c.Args, "https://h/x/model.pth?download=1") }), "AIG-008", 1},
		{"008 ckpt", container(func(c *corev1.Container) { c.Args = append(c.Args, "--ckpt=/m/a.ckpt") }), "AIG-008", 1},
		{"008 pickle", container(func(c *corev1.Container) { c.Args = append(c.Args, "/m/a.pickle") }), "AIG-008", 1},
		{"008 pkl in env", container(func(c *corev1.Container) {
			c.Env = []corev1.EnvVar{{Name: "MODEL_PATH", Value: "/m/a.pkl"}}
		}), "AIG-008", 1},
		{"008 safetensors ok", container(func(c *corev1.Container) { c.Args = append(c.Args, "--model", "/m/model.safetensors") }), "AIG-008", 0},
		{"008 port not an extension", container(func(c *corev1.Container) { c.Args = append(c.Args, "--port=8000") }), "AIG-008", 0},
		{"008 bin directory", container(func(c *corev1.Container) { c.Args = append(c.Args, "/usr/bin/x", "--path=/usr/bin") }), "AIG-008", 0},
		{"008 bin in query only", container(func(c *corev1.Container) { c.Args = append(c.Args, "https://h/x/model.safetensors?name=a.bin") }), "AIG-008", 0},
		{"008 ptx not pt", container(func(c *corev1.Container) { c.Args = append(c.Args, "--file=/m/kernel.ptx") }), "AIG-008", 0},
		{"008 s3 source", container(func(c *corev1.Container) { c.Args = append(c.Args, "--model", "s3://b/m") }), "AIG-008", 1},
		{"008 gs source", container(func(c *corev1.Container) { c.Args = append(c.Args, "--model=gs://b/m") }), "AIG-008", 1},
		{"008 non-ai image ignored", container(func(c *corev1.Container) {
			c.Image = "nginx"
			c.Args = []string{"--trust-remote-code", "/m/a.bin"}
		}), "AIG-008", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := clean()
			tt.mutate(&w)
			fs := RunPodSpecChecks(w)
			if got := count(fs, tt.id); got != tt.want {
				t.Errorf("%s count = %d, want %d; findings: %+v", tt.id, got, tt.want, fs)
			}
		})
	}
}

func TestFindingIdentityAndEvidence(t *testing.T) {
	w := vllm([]string{"--model", "m"}, nil, nil)
	fs := RunPodSpecChecks(w)
	for _, f := range fs {
		if f.Kind != "Deployment" || f.Namespace != "llm" || f.Name != "vllm" {
			t.Errorf("identity missing: %+v", f)
		}
		if f.Evidence == "" || f.Hint == "" || f.Severity == "" || f.Title == "" {
			t.Errorf("incomplete finding: %+v", f)
		}
		if strings.ContainsRune(f.Evidence+f.Hint+f.Title, rune(0x2014)) {
			t.Errorf("em-dash in finding: %+v", f)
		}
	}
	if !has(ids(fs), "AIG-001") || !has(ids(fs), "AIG-005") {
		t.Errorf("unexpected ids %v", ids(fs))
	}
}

func TestSeverity(t *testing.T) {
	if s, err := ParseSeverity(" HIGH "); err != nil || s != "High" {
		t.Errorf("ParseSeverity = %q, %v", s, err)
	}
	if _, err := ParseSeverity("critical"); err == nil {
		t.Error("expected error")
	}
	fs := []Finding{{Severity: "Low"}, {Severity: "Medium"}}
	if !AtLeast(fs, "low") || !AtLeast(fs, "Medium") || AtLeast(fs, "high") {
		t.Error("AtLeast wrong")
	}
	if AtLeast(nil, "low") {
		t.Error("no findings must not meet threshold")
	}
	if SeverityRank("bogus") != 0 {
		t.Error("unknown severity rank must be 0")
	}
}
