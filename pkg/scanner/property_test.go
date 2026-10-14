package scanner

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/sv222/ai-guard-k8s/pkg/target"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	propImages = []string{"vllm/vllm-openai:v0.6", "ollama/ollama", "nginx", "ghcr.io/huggingface/text-embeddings-inference:1", "rayproject/ray:2.9", "localai/localai", "", "postgis/postgis", "ghcr.io/ggml-org/llama.cpp:server"}
	propArgs   = []string{"--api-key", "--api-key=x", "--debug", "--trust-remote-code", "serve", "model.bin", "s3://bucket/m", "gs://b/m.safetensors", "--allow-http", "-m", "vllm"}
	propEnvs   = []string{"API_KEY", "VLLM_API_KEY", "OPENAI_API_KEY", "OLLAMA_DEBUG", "LLAMA_API_KEY", "HF_TOKEN"}
	propLabels = []string{"app", "tier", "ai.infra.guard/enabled", "ai.infra.guard/gateway-auth"}
	propNS     = []string{"llm", "default", "x"}
)

func pick[T any](r *rand.Rand, in []T) T { return in[r.Intn(len(in))] }

func randBool(r *rand.Rand) *bool {
	if r.Intn(3) == 0 {
		return nil
	}
	b := r.Intn(2) == 0
	return &b
}

func randLabels(r *rand.Rand) map[string]string {
	if r.Intn(4) == 0 {
		return nil
	}
	m := map[string]string{}
	for i := r.Intn(3); i >= 0; i-- {
		m[pick(r, propLabels)] = pick(r, []string{"true", "false", "vllm", "x"})
	}
	return m
}

func randContainer(r *rand.Rand, i int) corev1.Container {
	c := corev1.Container{Name: fmt.Sprintf("c%d", i), Image: pick(r, propImages)}
	for n := r.Intn(4); n > 0; n-- {
		c.Args = append(c.Args, pick(r, propArgs))
	}
	if r.Intn(3) == 0 {
		c.Command = []string{"sh", "-c", "exec " + pick(r, propArgs) + " " + pick(r, propArgs)}
	}
	for n := r.Intn(3); n > 0; n-- {
		e := corev1.EnvVar{Name: pick(r, propEnvs), Value: pick(r, []string{"", "1", "true", "x.bin"})}
		if r.Intn(3) == 0 {
			e.ValueFrom = &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{}}
		}
		c.Env = append(c.Env, e)
	}
	if r.Intn(3) == 0 {
		name := pick(r, []string{"hf-token", "api-key", "x-auth", ""})
		c.EnvFrom = []corev1.EnvFromSource{{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: name}}}}
	}
	if r.Intn(2) == 0 {
		uid := int64(r.Intn(3)) * 1000
		c.SecurityContext = &corev1.SecurityContext{
			RunAsUser: &uid, RunAsNonRoot: randBool(r), Privileged: randBool(r), AllowPrivilegeEscalation: randBool(r),
		}
		if r.Intn(2) == 0 {
			profile := pick(r, []corev1.SeccompProfileType{"", corev1.SeccompProfileTypeUnconfined, corev1.SeccompProfileTypeRuntimeDefault})
			c.SecurityContext.SeccompProfile = &corev1.SeccompProfile{Type: profile}
		}
	}
	return c
}

func randTarget(r *rand.Rand) target.WorkloadTarget {
	w := target.WorkloadTarget{
		Kind:       pick(r, []string{"Deployment", "Pod", "StatefulSet", "ReplicaSet"}),
		Namespace:  pick(r, propNS),
		Name:       fmt.Sprintf("w%d", r.Intn(5)),
		Labels:     randLabels(r),
		MetaLabels: randLabels(r),
		Source:     "gen.yaml",
	}
	if r.Intn(5) == 0 {
		w.Annotations = map[string]string{"helm.sh/hook": pick(r, []string{"test", "pre-install", "test,post-install"})}
	}
	for n := r.Intn(3); n >= 0; n-- {
		w.PodSpec.Containers = append(w.PodSpec.Containers, randContainer(r, n))
	}
	for n := r.Intn(2); n > 0; n-- {
		w.PodSpec.InitContainers = append(w.PodSpec.InitContainers, randContainer(r, 10+n))
	}
	w.PodSpec.HostNetwork, w.PodSpec.HostPID, w.PodSpec.HostIPC = r.Intn(4) == 0, r.Intn(4) == 0, r.Intn(4) == 0
	if r.Intn(4) == 0 {
		w.PodSpec.Volumes = []corev1.Volume{{Name: "h", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/m"}}}}
	}
	if r.Intn(2) == 0 {
		w.PodSpec.SecurityContext = &corev1.PodSecurityContext{RunAsNonRoot: randBool(r)}
	}
	return w
}

func randPeers(r *rand.Rand) []netv1.NetworkPolicyPeer {
	var peers []netv1.NetworkPolicyPeer
	for n := r.Intn(3); n > 0; n-- {
		switch r.Intn(4) {
		case 0:
			peers = append(peers, netv1.NetworkPolicyPeer{})
		case 1:
			peers = append(peers, netv1.NetworkPolicyPeer{NamespaceSelector: &metav1.LabelSelector{}})
		case 2:
			peers = append(peers, netv1.NetworkPolicyPeer{IPBlock: &netv1.IPBlock{CIDR: pick(r, []string{"0.0.0.0/0", "::/0", "10.0.0.0/8"})}})
		default:
			peers = append(peers, netv1.NetworkPolicyPeer{PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "gw"}}})
		}
	}
	return peers
}

func randDirScan(r *rand.Rand) target.DirScan {
	var ds target.DirScan
	for i := r.Intn(6); i >= 0; i-- {
		ds.Targets = append(ds.Targets, randTarget(r))
	}
	for i := r.Intn(3); i > 0; i-- {
		spec := netv1.NetworkPolicySpec{PodSelector: metav1.LabelSelector{MatchLabels: randLabels(r)}}
		for _, pt := range []netv1.PolicyType{netv1.PolicyTypeIngress, netv1.PolicyTypeEgress} {
			if r.Intn(2) == 0 {
				spec.PolicyTypes = append(spec.PolicyTypes, pt)
			}
		}
		for n := r.Intn(3); n > 0; n-- {
			spec.Ingress = append(spec.Ingress, netv1.NetworkPolicyIngressRule{From: randPeers(r)})
			spec.Egress = append(spec.Egress, netv1.NetworkPolicyEgressRule{To: randPeers(r)})
		}
		ds.NetPols = append(ds.NetPols, target.NetworkPolicyEntry{Namespace: pick(r, propNS), Name: fmt.Sprintf("p%d", i), Spec: spec})
	}
	for i := r.Intn(3); i > 0; i-- {
		ds.Services = append(ds.Services, target.ServiceEntry{
			Namespace: pick(r, propNS), Name: fmt.Sprintf("s%d", i),
			Type: pick(r, []string{"ClusterIP", "LoadBalancer", "NodePort"}), Selector: randLabels(r),
		})
	}
	for i := r.Intn(2); i > 0; i-- {
		ds.Ingresses = append(ds.Ingresses, target.IngressEntry{
			Namespace:   pick(r, propNS),
			Name:        "ing",
			Annotations: map[string]string{pick(r, []string{"nginx.ingress.kubernetes.io/auth-url", "x"}): "y"},
			Services:    []string{fmt.Sprintf("s%d", r.Intn(3))},
		})
	}
	return ds
}

func TestPropertyAnalyzeIsDeterministicAndNeverPanics(t *testing.T) {
	for seed := int64(0); seed < 400; seed++ {
		ds := randDirScan(rand.New(rand.NewSource(seed)))
		func() {
			defer func() {
				if p := recover(); p != nil {
					t.Fatalf("seed %d panicked: %v", seed, p)
				}
			}()
			checkAnalyze(t, ds)
		}()
	}
}

func FuzzAnalyzeGenerated(f *testing.F) {
	for _, s := range []int64{0, 1, 2, 42, 1 << 40, -7, -152} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, seed int64) {
		checkAnalyze(t, randDirScan(rand.New(rand.NewSource(seed))))
	})
}
