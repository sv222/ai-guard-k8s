package scanner

import (
	"context"
	"strings"
	"testing"

	"github.com/sv222/ai-guard-k8s/pkg/target"
	corev1 "k8s.io/api/core/v1"
)

const regress = "../../testdata/regress"

func scanRegress(t *testing.T, file string) map[string]int {
	t.Helper()
	res, err := Scan(context.Background(), Options{Path: regress + "/" + file})
	if err != nil {
		t.Fatal(err)
	}
	return idSet(res.Findings)
}

func wantIDs(t *testing.T, got map[string]int, want map[string]int) {
	t.Helper()
	for id, n := range want {
		if got[id] != n {
			t.Errorf("%s = %d, want %d; got %v", id, got[id], n, got)
		}
	}
	for id, n := range got {
		if _, ok := want[id]; !ok {
			t.Errorf("unexpected %s x%d; got %v", id, n, got)
		}
	}
}

func TestRegressHelmTestHookPodIsSkipped(t *testing.T) {
	wantIDs(t, scanRegress(t, "helm-test-hook.yaml"), map[string]int{})
}

func TestRegressTgiSubstringIsNotAnEngine(t *testing.T) {
	wantIDs(t, scanRegress(t, "postgis.yaml"), map[string]int{})
}

func TestRegressEnginesBeyondTheFirstList(t *testing.T) {
	res, err := Scan(context.Background(), Options{Path: regress + "/engines.yaml"})
	if err != nil {
		t.Fatal(err)
	}
	perWorkload := map[string]int{}
	for _, f := range res.Findings {
		if f.ID == "AIG-001" {
			perWorkload[f.Name]++
		}
	}
	for _, name := range []string{"embed", "assistant"} {
		if perWorkload[name] != 1 {
			t.Errorf("AIG-001 on %s = %d, want 1; got %v", name, perWorkload[name], perWorkload)
		}
	}
	if perWorkload["chat"] != 2 {
		t.Errorf("AIG-001 on chat = %d, want 2; got %v", perWorkload["chat"], perWorkload)
	}
	if got := idSet(res.Findings)["AIG-010"]; got != 1 {
		t.Errorf("AIG-010 = %d, want 1 (embed behind a LoadBalancer)", got)
	}
}

func TestRegressEngineStartedByCommand(t *testing.T) {
	res, err := Scan(context.Background(), Options{Path: regress + "/args-engine.yaml"})
	if err != nil {
		t.Fatal(err)
	}
	high := map[string]bool{}
	other := map[string]int{}
	for _, f := range res.Findings {
		if f.ID == "AIG-001" && f.Severity == "High" {
			high[f.Name] = true
		}
		if f.Name == "web" {
			other[f.ID]++
		}
	}
	if !high["llm-gateway"] || !high["qa"] {
		t.Errorf("vLLM started by command not detected: %v", high)
	}
	if len(other) != 0 {
		t.Errorf("web service with vllm only as an argument value was scanned: %v", other)
	}
	if got := idSet(res.Findings)["AIG-008"]; got != 1 {
		t.Errorf("AIG-008 = %d, want 1 for --trust-remote-code in the shell string", got)
	}
}

func TestRegressOptInWorkloadWithCustomImage(t *testing.T) {
	res, err := Scan(context.Background(), Options{Path: regress + "/optin-custom-image.yaml"})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]map[string]int{}
	for _, f := range res.Findings {
		if got[f.Name] == nil {
			got[f.Name] = map[string]int{}
		}
		got[f.Name][f.ID]++
	}
	if got["genai"]["AIG-001"] != 1 || got["genai"]["AIG-008"] != 1 {
		t.Errorf("opted-in single container workload not checked: %v", got["genai"])
	}
	if got["genai-mesh"]["AIG-001"] != 0 || got["genai-mesh"]["AIG-008"] != 0 {
		t.Errorf("engine checks ran on a multi-container pod with no recognized engine: %v", got["genai-mesh"])
	}
}

func TestRegressSelectorOptInWithCustomImage(t *testing.T) {
	ds := target.DirScan{Targets: []target.WorkloadTarget{{
		Kind: "Deployment", Namespace: "x", Name: "svc", Labels: map[string]string{"tier": "inference"},
		PodSpec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "registry.example.com/platform/svc:1"}}},
	}}}
	if got := idSet(Analyze(ds, "tier=inference")); got["AIG-001"] != 1 {
		t.Errorf("AIG-001 = %d, want 1 for a selected single-container workload", got["AIG-001"])
	}
}

func TestRegressEnvFromTokenSecretIsNotEngineAuth(t *testing.T) {
	res, err := Scan(context.Background(), Options{Path: regress + "/envfrom-secrets.yaml"})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, f := range res.Findings {
		if f.ID == "AIG-001" {
			got[f.Name]++
		}
	}
	if got["vllm-hf"] != 1 || got["vllm-keyed"] != 0 {
		t.Errorf("AIG-001 by workload = %v, want vllm-hf 1 and vllm-keyed 0", got)
	}
}

func TestRegressIngressExposure(t *testing.T) {
	res, err := Scan(context.Background(), Options{Path: regress + "/ingress-exposure.yaml"})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, f := range res.Findings {
		if f.ID == "AIG-010" {
			got[f.Name]++
		}
	}
	if got["ollama-open"] != 1 || got["ollama-authed"] != 0 || got["ollama-internal"] != 0 {
		t.Errorf("AIG-010 by workload = %v, want only ollama-open", got)
	}
}

func TestRegressHelmTestHookIsReportedAsWarning(t *testing.T) {
	res, err := Scan(context.Background(), Options{Path: regress + "/helm-test-hook.yaml"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 || len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "helm.sh/hook") {
		t.Errorf("findings=%v warnings=%v", res.Findings, res.Warnings)
	}
}
