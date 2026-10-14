package enforce

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	clienttesting "k8s.io/client-go/testing"
)

func testMapper(withCilium bool) meta.RESTMapper {
	m := meta.NewDefaultRESTMapper(nil)
	m.Add(schema.GroupVersionKind{Group: "kyverno.io", Version: "v1", Kind: "ClusterPolicy"}, meta.RESTScopeRoot)
	if withCilium {
		m.Add(schema.GroupVersionKind{Group: "cilium.io", Version: "v2", Kind: "CiliumNetworkPolicy"}, meta.RESTScopeNamespace)
		m.Add(schema.GroupVersionKind{Group: "cilium.io", Version: "v2", Kind: "CiliumClusterwideNetworkPolicy"}, meta.RESTScopeRoot)
	}
	return m
}

func fakeClient() (*dynamicfake.FakeDynamicClient, *[]clienttesting.PatchAction) {
	client := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	var patches []clienttesting.PatchAction
	client.PrependReactor("patch", "*", func(a clienttesting.Action) (bool, runtime.Object, error) {
		pa := a.(clienttesting.PatchAction)
		patches = append(patches, pa)
		return true, &unstructured.Unstructured{Object: map[string]interface{}{}}, nil
	})
	return client, &patches
}

func TestApplyUsesRESTMapping(t *testing.T) {
	client, patches := fakeClient()
	var out bytes.Buffer
	files := defaultPolicies(t)
	if err := Apply(context.Background(), client, testMapper(true), files, "", &out); err != nil {
		t.Fatal(err)
	}
	if len(*patches) != 4 {
		t.Fatalf("patches = %d, want 4", len(*patches))
	}
	byName := map[string]clienttesting.PatchAction{}
	for _, p := range *patches {
		byName[p.GetName()] = p
	}
	kyverno := byName["aig-require-nonroot"]
	if kyverno.GetResource().Resource != "clusterpolicies" || kyverno.GetNamespace() != "" {
		t.Errorf("clusterpolicy action = %v ns=%q", kyverno.GetResource(), kyverno.GetNamespace())
	}
	cilium := byName["aig-inference-egress"]
	if cilium.GetResource().Resource != "ciliumclusterwidenetworkpolicies" || cilium.GetNamespace() != "" {
		t.Errorf("cilium action = %v ns=%q", cilium.GetResource(), cilium.GetNamespace())
	}
	if !strings.Contains(out.String(), "applied ClusterPolicy aig-require-nonroot") {
		t.Errorf("output = %q", out.String())
	}
}

func TestApplyNamespaceFlag(t *testing.T) {
	client, patches := fakeClient()
	files, err := Policies(Options{Namespace: "llm"})
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(context.Background(), client, testMapper(true), files, "other", &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	for _, p := range *patches {
		if p.GetName() == "aig-inference-egress" && p.GetNamespace() != "llm" {
			t.Errorf("namespace = %q, want llm", p.GetNamespace())
		}
	}
}

func TestApplyClusterwideIgnoresNamespaceFlag(t *testing.T) {
	client, patches := fakeClient()
	if err := Apply(context.Background(), client, testMapper(true), defaultPolicies(t), "gpu", &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	for _, p := range *patches {
		if p.GetNamespace() != "" {
			t.Errorf("%s was applied in namespace %q", p.GetName(), p.GetNamespace())
		}
	}
}

func TestApplyNamespacedPolicyWithoutNamespaceUsesFlag(t *testing.T) {
	client, patches := fakeClient()
	file := PolicyFile{Name: "p.yaml", Content: "apiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy\nmetadata:\n  name: p\n"}
	if err := Apply(context.Background(), client, testMapper(true), []PolicyFile{file}, "gpu", &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if len(*patches) != 1 || (*patches)[0].GetNamespace() != "gpu" {
		t.Errorf("patches = %v", *patches)
	}
}

func TestApplyMissingCRD(t *testing.T) {
	client, _ := fakeClient()
	err := Apply(context.Background(), client, testMapper(false), defaultPolicies(t), "", &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "CRD") {
		t.Errorf("err = %v, want CRD hint", err)
	}
}

func TestApplyPatchError(t *testing.T) {
	client := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	client.PrependReactor("patch", "*", func(clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("forbidden")
	})
	err := Apply(context.Background(), client, testMapper(true), defaultPolicies(t), "", &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "forbidden") {
		t.Errorf("err = %v", err)
	}
}

func TestApplyInvalidContent(t *testing.T) {
	client, _ := fakeClient()
	err := Apply(context.Background(), client, testMapper(true), []PolicyFile{{Name: "bad.yaml", Content: "a: [unterminated"}}, "", &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "bad.yaml") {
		t.Errorf("err = %v", err)
	}
}

func TestPlan(t *testing.T) {
	var out bytes.Buffer
	if err := Plan(defaultPolicies(t), "", &out); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if strings.Count(got, "would apply") != 4 {
		t.Errorf("plan output:\n%s", got)
	}
	if !strings.Contains(got, "would apply CiliumClusterwideNetworkPolicy aig-inference-egress (aig-cilium-egress-fqdn.yaml)") {
		t.Errorf("plan output:\n%s", got)
	}
	namespaced, err := Policies(Options{Namespace: "llm"})
	if err != nil {
		t.Fatal(err)
	}
	var nsOut bytes.Buffer
	if err := Plan(namespaced, "", &nsOut); err != nil || !strings.Contains(nsOut.String(), "would apply CiliumNetworkPolicy aig-inference-egress in namespace llm") {
		t.Errorf("err=%v plan output:\n%s", err, nsOut.String())
	}
	if err := Plan([]PolicyFile{{Name: "bad.yaml", Content: "a: [x"}}, "", &out); err == nil {
		t.Error("expected error for invalid content")
	}
}

func TestClientsWithoutKubeconfig(t *testing.T) {
	t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "missing"))
	if _, _, err := Clients(""); err == nil {
		t.Error("expected error without a usable kubeconfig")
	}
	if _, _, err := Clients(filepath.Join(t.TempDir(), "explicit-missing")); err == nil {
		t.Error("expected error for missing explicit kubeconfig")
	}
}
