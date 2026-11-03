package target

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	helmChart   = "../../testdata/helm/vllm"
	kustOverlay = "../../testdata/kustomize/overlay"
)

func byName(ds DirScan) map[string]WorkloadTarget {
	out := map[string]WorkloadTarget{}
	for _, w := range ds.Targets {
		out[w.Name] = w
	}
	return out
}

func TestFromHelmMapsTemplates(t *testing.T) {
	ds, err := FromHelm(helmChart, "llm", nil, []string{"apiKey=k", "hostPort=8000"})
	if err != nil {
		t.Fatal(err)
	}
	if ds.Failed != 0 || ds.Objects != 4 {
		t.Fatalf("failed=%d objects=%d warnings=%v", ds.Failed, ds.Objects, ds.Warnings)
	}
	ws := byName(ds)
	dep, test := ws["release-name-vllm"], ws["release-name-vllm-test"]
	if dep.Namespace != "llm" || dep.Source != filepath.Join(helmChart, "templates", "deployment.yaml") || dep.Line != 0 {
		t.Errorf("deployment = %s/%s from %s line %d", dep.Namespace, dep.Name, dep.Source, dep.Line)
	}
	c := dep.Containers()[0]
	if c.Image != "vllm/vllm-openai:v0.6.0" || strings.Join(c.Args, " ") != "--model m --api-key k" || c.Ports[0].HostPort != 8000 {
		t.Errorf("container = %+v", c)
	}
	if test.Source != filepath.Join(helmChart, "templates", "tests", "test-connection.yaml") || !test.IsHelmTestHook() {
		t.Errorf("test hook = %+v", test)
	}
	if len(ds.Services) != 1 || ds.Services[0].Type != "ClusterIP" || len(ds.NetPols) != 1 {
		t.Errorf("services=%+v netpols=%+v", ds.Services, ds.NetPols)
	}
}

func TestFromHelmValuesFile(t *testing.T) {
	vals := filepath.Join(t.TempDir(), "v.yaml")
	if err := os.WriteFile(vals, []byte("service:\n  type: LoadBalancer\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ds, err := FromHelm(helmChart, "", []string{vals}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(ds.Services) != 1 || ds.Services[0].Type != "LoadBalancer" || ds.Services[0].Namespace != "default" {
		t.Errorf("services = %+v", ds.Services)
	}
}

func TestFromHelmErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := FromHelm(dir, "", nil, nil); err == nil || !strings.Contains(err.Error(), "load Helm chart") {
		t.Errorf("missing chart: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Chart.yaml"), []byte("apiVersion: v2\nname: x\nversion: 0.1.0\ndependencies:\n  - name: redis\n    version: 1.0.0\n    repository: https://example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := FromHelm(dir, "", nil, nil); err == nil || !strings.Contains(err.Error(), "helm dependency build") {
		t.Errorf("missing dependency: %v", err)
	}
	if _, err := FromHelm(helmChart, "", []string{filepath.Join(dir, "missing.yaml")}, nil); err == nil {
		t.Error("missing values file must fail")
	}
	bad := t.TempDir()
	if err := os.MkdirAll(filepath.Join(bad, "templates"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bad, "Chart.yaml"), []byte("apiVersion: v2\nname: bad\nversion: 0.1.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bad, "templates", "x.yaml"), []byte("{{ fail \"boom\" }}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := FromHelm(bad, "", nil, nil); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("template error: %v", err)
	}
}

func TestFromKustomizeMapsOrigins(t *testing.T) {
	ds, err := FromKustomize(kustOverlay, false)
	if err != nil {
		t.Fatal(err)
	}
	if ds.Failed != 0 || ds.Objects != 3 || len(ds.Targets) != 1 {
		t.Fatalf("failed=%d objects=%d targets=%d warnings=%v", ds.Failed, ds.Objects, len(ds.Targets), ds.Warnings)
	}
	w := ds.Targets[0]
	if w.Namespace != "llm" || w.Source != filepath.Join(kustOverlay, "..", "base", "deployment.yaml") || w.Line != 0 {
		t.Errorf("deployment = %s/%s from %s line %d", w.Namespace, w.Name, w.Source, w.Line)
	}
	if _, ok := w.MetaAnnotations["config.kubernetes.io/origin"]; ok {
		t.Error("origin annotation leaked into the scanned object")
	}
	c := w.Containers()[0]
	if strings.Join(c.Args, " ") != "--model m" || c.SecurityContext.Capabilities == nil || c.SecurityContext.Capabilities.Add[0] != "NET_ADMIN" {
		t.Errorf("patch not applied: %+v", c)
	}
	if len(ds.NetPols) != 1 || ds.NetPols[0].Namespace != "llm" {
		t.Errorf("netpols = %+v", ds.NetPols)
	}
}

func TestFromKustomizeKeepsBuildMetadata(t *testing.T) {
	dir := t.TempDir()
	write := func(name, data string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("kustomization.yml", "buildMetadata: [originAnnotations]\nresources: [pod.yaml]\n")
	write("pod.yaml", "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  containers:\n    - name: c\n      image: ollama/ollama\n")
	ds, err := FromKustomize(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(ds.Targets) != 1 || ds.Targets[0].Source != filepath.Join(dir, "pod.yaml") {
		t.Errorf("targets = %+v", ds.Targets)
	}
	if _, err := FromKustomize(filepath.Join(dir, "missing"), false); err == nil {
		t.Error("missing dir must fail")
	}
	write("kustomization.yml", "resources: [missing.yaml]\n")
	if _, err := FromKustomize(dir, false); err == nil || !strings.Contains(err.Error(), "build kustomization") {
		t.Errorf("bad kustomization: %v", err)
	}
}

func TestFromKustomizeRefusesRemoteByDefault(t *testing.T) {
	cases := map[string]string{
		"https resource":  "resources:\n  - https://127.0.0.1:1/pod.yaml\n",
		"git resource":    "resources:\n  - github.com/org/repo//deploy?ref=v1\n",
		"ssh base":        "resources:\n  - git@github.com:org/repo.git//deploy\n",
		"https patch":     "resources:\n  - pod.yaml\npatches:\n  - path: https://127.0.0.1:1/p.yaml\n",
		"component":       "components:\n  - https://github.com/org/repo/comp\n",
		"generator files": "resources:\n  - pod.yaml\nconfigMapGenerator:\n  - name: c\n    files:\n      - k=https://127.0.0.1:1/f\n",
	}
	for name, kust := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "kustomization.yaml"), []byte(kust), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "pod.yaml"), []byte("apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  containers:\n    - name: c\n      image: ollama/ollama\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := FromKustomize(dir, false)
			if err == nil || !strings.Contains(err.Error(), "remote resource") || !strings.Contains(err.Error(), "--allow-remote") {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestFromKustomizeRefusesRemoteInLocalBase(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "base"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "kustomization.yaml"), []byte("resources: [base]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "base", "kustomization.yaml"), []byte("resources:\n  - https://127.0.0.1:1/pod.yaml\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := FromKustomize(dir, false)
	if err == nil || !strings.Contains(err.Error(), "remote resource") {
		t.Fatalf("error = %v", err)
	}
	_, err = FromKustomize(dir, true)
	if err == nil || strings.Contains(err.Error(), "remote resource") {
		t.Fatalf("with allowRemote the fetch must be attempted: %v", err)
	}
}

func TestFromKustomizeKeepsLocalDottedPaths(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "app.example.com", "org", "base"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "kustomization.yaml"), []byte("resources: [app.example.com/org/base]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "app.example.com", "org", "base", "kustomization.yaml"), []byte("resources: [pod.yaml]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "app.example.com", "org", "base", "pod.yaml"), []byte("apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  containers:\n    - name: c\n      image: ollama/ollama\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ds, err := FromKustomize(dir, false); err != nil || len(ds.Targets) != 1 {
		t.Fatalf("targets=%d err=%v", len(ds.Targets), err)
	}
}
