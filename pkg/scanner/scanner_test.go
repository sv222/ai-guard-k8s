package scanner

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sv222/ai-guard-k8s/pkg/checks"
	"github.com/sv222/ai-guard-k8s/pkg/target"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

const fixtures = "../../testdata/manifests"

func idSet(fs []checks.Finding) map[string]int {
	out := map[string]int{}
	for _, f := range fs {
		out[f.ID]++
	}
	return out
}

func TestScanCleanDirHasNoFindings(t *testing.T) {
	res, err := Scan(context.Background(), Options{Path: fixtures + "/clean"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("clean fixtures produced findings: %+v", res.Findings)
	}
}

func TestScanOffendingDirCoversEveryCheck(t *testing.T) {
	res, err := Scan(context.Background(), Options{Path: fixtures + "/offending"})
	if err != nil {
		t.Fatal(err)
	}
	got := idSet(res.Findings)
	for _, id := range []string{"AIG-001", "AIG-002", "AIG-003", "AIG-004", "AIG-005", "AIG-006", "AIG-007", "AIG-008", "AIG-009", "AIG-010"} {
		if got[id] == 0 {
			t.Errorf("fixture did not trigger %s; got %v", id, got)
		}
	}
}

func TestScanPathOnlyDoesNotTouchCluster(t *testing.T) {
	old := loadCluster
	defer func() { loadCluster = old }()
	loadCluster = func(context.Context, string, string) (target.DirScan, error) {
		t.Fatal("cluster must not be queried when only a path is given")
		return target.DirScan{}, nil
	}
	if _, err := Scan(context.Background(), Options{Path: fixtures + "/clean"}); err != nil {
		t.Fatal(err)
	}
}

func TestScanClusterOptIn(t *testing.T) {
	old := loadCluster
	defer func() { loadCluster = old }()
	called := false
	loadCluster = func(context.Context, string, string) (target.DirScan, error) {
		called = true
		return target.DirScan{}, nil
	}
	if _, err := Scan(context.Background(), Options{Path: fixtures + "/clean", Cluster: true}); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Error("cluster loader not called with Cluster: true")
	}
}

func TestScanClusterError(t *testing.T) {
	old := loadCluster
	defer func() { loadCluster = old }()
	loadCluster = func(context.Context, string, string) (target.DirScan, error) {
		return target.DirScan{}, errors.New("no kubeconfig")
	}
	_, err := Scan(context.Background(), Options{Cluster: true})
	if err == nil || !strings.Contains(err.Error(), "no kubeconfig") {
		t.Errorf("err = %v", err)
	}
}

func TestScanValidation(t *testing.T) {
	if _, err := Scan(context.Background(), Options{}); err == nil {
		t.Error("expected error when nothing to scan")
	}
	if _, err := Scan(context.Background(), Options{Path: fixtures, Selector: "a in ("}); err == nil {
		t.Error("expected error for invalid selector")
	}
	if _, err := Scan(context.Background(), Options{Path: fixtures + "/missing"}); err == nil {
		t.Error("expected error for missing path")
	}
}

func TestScanSelectorOverride(t *testing.T) {
	ds := target.DirScan{Targets: []target.WorkloadTarget{{
		Kind: "Deployment", Namespace: "x", Name: "svc", Labels: map[string]string{"tier": "inference"},
		PodSpec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "nginx"}}},
	}}}
	if got := Analyze(ds, ""); len(got) != 0 {
		t.Errorf("non-AI workload scanned without selector: %+v", got)
	}
	if got := Analyze(ds, "tier=inference"); len(got) == 0 {
		t.Error("selector override did not select workload")
	}
}

func TestAnalyzeDedupesAndSorts(t *testing.T) {
	w := target.WorkloadTarget{
		Kind: "Deployment", Namespace: "x", Name: "vllm",
		MetaLabels: map[string]string{"ai.infra.guard/enabled": "true"},
		PodSpec:    corev1.PodSpec{HostNetwork: true, Containers: []corev1.Container{{Name: "c", Image: "app"}}},
	}
	ds := target.DirScan{Targets: []target.WorkloadTarget{w, w}}
	got := Analyze(ds, "")
	seen := map[string]bool{}
	for _, f := range got {
		key := f.ID + f.Evidence
		if seen[key] {
			t.Errorf("duplicate finding %s", key)
		}
		seen[key] = true
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].ID > got[i].ID {
			t.Errorf("not sorted: %s before %s", got[i-1].ID, got[i].ID)
		}
	}
}

func TestClusterPodOwnedByDeploymentNotDuplicated(t *testing.T) {
	yes := true
	spec := corev1.PodSpec{HostNetwork: true, Containers: []corev1.Container{{Name: "c", Image: "vllm/vllm-openai"}}}
	cs := fake.NewSimpleClientset(
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "vllm", Namespace: "x"},
			Spec:       appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: spec}},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "vllm-abc-1", Namespace: "x",
				OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "vllm-abc", Controller: &yes}}},
			Spec: spec,
		},
	)
	old := loadCluster
	defer func() { loadCluster = old }()
	loadCluster = func(ctx context.Context, _, ns string) (target.DirScan, error) {
		return target.FromClientset(ctx, cs, ns)
	}
	res, err := Scan(context.Background(), Options{Cluster: true})
	if err != nil {
		t.Fatal(err)
	}
	if n := idSet(res.Findings)["AIG-003"]; n != 1 {
		t.Errorf("AIG-003 findings = %d, want 1: %+v", n, res.Findings)
	}
	for _, f := range res.Findings {
		if f.Kind == "Pod" {
			t.Errorf("owned pod scanned separately: %+v", f)
		}
	}
}

func TestAnalyzeWarnsWhenPodTemplateLacksEnforceLabel(t *testing.T) {
	pod := func(name string, tplLabels, metaLabels map[string]string) target.WorkloadTarget {
		return target.WorkloadTarget{
			Kind: "Deployment", Namespace: "llm", Name: name, Labels: tplLabels, MetaLabels: metaLabels,
			PodSpec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "vllm/vllm-openai"}}},
		}
	}
	ds := target.DirScan{Targets: []target.WorkloadTarget{
		pod("labeled", map[string]string{"ai.infra.guard/enabled": "true"}, nil),
		pod("only-on-deployment", nil, map[string]string{"ai.infra.guard/enabled": "true"}),
		pod("unlabeled", map[string]string{"app": "x"}, nil),
	}}
	_, warnings := AnalyzeWith(ds, "", "ai.infra.guard/enabled=true")
	if len(warnings) != 2 {
		t.Fatalf("warnings = %v", warnings)
	}
	for _, w := range warnings {
		if strings.Contains(w, "llm/labeled") || !strings.Contains(w, "ai.infra.guard/enabled=true") {
			t.Errorf("unexpected warning %q", w)
		}
	}
	if _, warnings := AnalyzeWith(ds, "", ""); len(warnings) != 0 {
		t.Errorf("empty enforce selector must not warn: %v", warnings)
	}
	_, warnings = AnalyzeWith(ds, "", "team=llm")
	if len(warnings) != 3 {
		t.Errorf("custom enforce selector warnings = %v", warnings)
	}
}

func TestScanInvalidEnforceSelector(t *testing.T) {
	if _, err := Scan(context.Background(), Options{Path: fixtures + "/clean", EnforceSelector: "nokey"}); err == nil {
		t.Error("expected error")
	}
}

func TestScanWarningsAreUnique(t *testing.T) {
	res, err := Scan(context.Background(), Options{Path: fixtures + "/offending", EnforceSelector: "ai.infra.guard/enabled=true"})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, w := range res.Warnings {
		if seen[w] {
			t.Errorf("duplicate warning %q", w)
		}
		seen[w] = true
	}
	if len(res.Warnings) == 0 {
		t.Error("offending sample should lack the enforce label")
	}
}
