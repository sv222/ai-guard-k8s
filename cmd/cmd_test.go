package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/sv222/ai-guard-k8s/pkg/checks"
	"github.com/sv222/ai-guard-k8s/pkg/enforce"
)

const (
	cleanDir     = "../testdata/manifests/clean"
	offendingDir = "../testdata/manifests/offending"
)

func run(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	var o, e bytes.Buffer
	code = Run(args, &o, &e)
	return o.String(), e.String(), code
}

func brokenKubeconfig(t *testing.T) {
	t.Helper()
	t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "missing-kubeconfig"))
}

const lowOnly = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: vllm
  namespace: llm
spec:
  selector:
    matchLabels:
      app: vllm
  template:
    metadata:
      labels:
        app: vllm
    spec:
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: server
          image: vllm/vllm-openai:v0.6.0
          args: ["--api-key", "k"]
          securityContext:
            allowPrivilegeEscalation: false
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny
  namespace: llm
spec:
  podSelector: {}
  policyTypes: [Ingress]
`

func TestVersion(t *testing.T) {
	stdout, _, code := run(t, "--version")
	if code != 0 || strings.TrimSpace(stdout) != "ai-guard "+Version {
		t.Errorf("version output = %q code=%d", stdout, code)
	}
}

func TestScanCleanPath(t *testing.T) {
	brokenKubeconfig(t)
	stdout, stderr, code := run(t, "scan", "--path", cleanDir)
	if code != 0 {
		t.Fatalf("code = %d stderr=%s stdout=%s", code, stderr, stdout)
	}
	if !strings.Contains(stdout, "No findings") {
		t.Errorf("stdout = %q", stdout)
	}
}

func TestScanPathDoesNotNeedCluster(t *testing.T) {
	brokenKubeconfig(t)
	_, stderr, code := run(t, "scan", "--path", offendingDir)
	if code != 1 {
		t.Errorf("code = %d, want 1 (findings, not a cluster error); stderr=%s", code, stderr)
	}
	if strings.Contains(stderr, "Error:") {
		t.Errorf("unexpected error: %s", stderr)
	}
}

func TestScanOffendingTable(t *testing.T) {
	stdout, _, code := run(t, "scan", "--path", offendingDir)
	if code != 1 {
		t.Fatalf("code = %d", code)
	}
	for _, id := range []string{"AIG-001", "AIG-003", "AIG-010"} {
		if !strings.Contains(stdout, id) {
			t.Errorf("table lacks %s:\n%s", id, stdout)
		}
	}
}

func TestScanJSON(t *testing.T) {
	stdout, _, code := run(t, "scan", "--path", offendingDir, "--json")
	if code != 1 {
		t.Fatalf("code = %d", code)
	}
	var fs []checks.Finding
	if err := json.Unmarshal([]byte(stdout), &fs); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout)
	}
	if len(fs) == 0 || fs[0].ID == "" || fs[0].Evidence == "" {
		t.Errorf("findings = %+v", fs)
	}
}

func TestScanJSONCleanIsEmptyArray(t *testing.T) {
	stdout, _, code := run(t, "scan", "--path", cleanDir, "--json")
	if code != 0 || strings.TrimSpace(stdout) != "[]" {
		t.Errorf("code=%d stdout=%q", code, stdout)
	}
}

func TestScanFailOn(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "m.yaml"), []byte(lowOnly), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, code := run(t, "scan", "--path", dir); code != 1 {
		t.Errorf("default fail-on code = %d, want 1", code)
	}
	if _, _, code := run(t, "scan", "--path", dir, "--fail-on", "low"); code != 1 {
		t.Errorf("fail-on low code = %d, want 1", code)
	}
	if _, _, code := run(t, "scan", "--path", dir, "--fail-on", "medium"); code != 0 {
		t.Errorf("fail-on medium code = %d, want 0", code)
	}
	if _, _, code := run(t, "scan", "--path", offendingDir, "--fail-on", "high"); code != 1 {
		t.Errorf("fail-on high on offending code = %d, want 1", code)
	}
	if _, stderr, code := run(t, "scan", "--path", dir, "--fail-on", "critical"); code != 2 || !strings.Contains(stderr, "invalid severity") {
		t.Errorf("bad fail-on code=%d stderr=%s", code, stderr)
	}
}

func TestScanMissingPathIsError(t *testing.T) {
	_, stderr, code := run(t, "scan", "--path", filepath.Join(t.TempDir(), "nope"))
	if code != 2 {
		t.Errorf("code = %d, want 2", code)
	}
	if !strings.Contains(stderr, "Error:") || strings.Contains(stderr, "Usage:") {
		t.Errorf("stderr = %q (want error without usage dump)", stderr)
	}
}

func TestScanWithoutPathUsesCluster(t *testing.T) {
	brokenKubeconfig(t)
	_, stderr, code := run(t, "scan")
	if code != 2 || !strings.Contains(stderr, "cluster scan") {
		t.Errorf("code=%d stderr=%q", code, stderr)
	}
}

func TestScanClusterFlagAddsCluster(t *testing.T) {
	brokenKubeconfig(t)
	_, stderr, code := run(t, "scan", "--path", cleanDir, "--cluster")
	if code != 2 || !strings.Contains(stderr, "cluster scan") {
		t.Errorf("code=%d stderr=%q", code, stderr)
	}
}

func TestScanOfflineIsDeprecatedNoop(t *testing.T) {
	brokenKubeconfig(t)
	_, stderr, code := run(t, "scan", "--path", cleanDir, "--offline")
	if code != 0 {
		t.Errorf("code = %d stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr, "deprecated") {
		t.Errorf("no deprecation notice: %q", stderr)
	}
}

func writeDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestScanInvalidYAMLFails(t *testing.T) {
	dir := writeDir(t, map[string]string{"broken.yaml": "key: [unterminated\nother: : :\n"})
	_, stderr, code := run(t, "scan", "--path", dir)
	if code != 2 {
		t.Errorf("code = %d, want 2", code)
	}
	if !strings.Contains(stderr, "warning:") || !strings.Contains(stderr, "broken.yaml") || !strings.Contains(stderr, "Error:") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestScanPartialFailureIsError(t *testing.T) {
	dir := writeDir(t, map[string]string{
		"good.yaml":   lowOnly,
		"broken.yaml": "kind: Deployment\nmetadata: [x\n",
	})
	stdout, stderr, code := run(t, "scan", "--path", dir)
	if code != 2 {
		t.Errorf("code = %d, want 2; stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, "AIG-") && !strings.Contains(stdout, "No findings") {
		t.Errorf("report should still be printed: %q", stdout)
	}
	if !strings.Contains(stderr, "incomplete") {
		t.Errorf("stderr = %q", stderr)
	}
	if _, stderr, code = run(t, "scan", "--path", dir, "--lenient", "--fail-on", "high"); code != 0 || !strings.Contains(stderr, "warning:") {
		t.Errorf("lenient: code=%d stderr=%q", code, stderr)
	}
}

func TestScanBadTypesInDeploymentFail(t *testing.T) {
	bad := "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: vllm\nspec:\n  replicas: three\n  template:\n    spec:\n      containers: []\n"
	_, stderr, code := run(t, "scan", "--path", writeDir(t, map[string]string{"d.yaml": bad}))
	if code != 2 || !strings.Contains(stderr, "decode") {
		t.Errorf("code=%d stderr=%q", code, stderr)
	}
}

func TestScanRawHelmTemplateFails(t *testing.T) {
	tpl := "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: {{ include \"x.fullname\" . }}\nspec:\n  replicas: {{ .Values.replicas }}\n"
	_, stderr, code := run(t, "scan", "--path", writeDir(t, map[string]string{"deployment.yaml": tpl}))
	if code != 2 {
		t.Errorf("code = %d, want 2; stderr=%q", code, stderr)
	}
}

func TestScanNoManifestsFails(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"empty dir":       {},
		"only text":       {"notes.txt": "hello"},
		"not kubernetes":  {"values.yaml": "replicas: 2\nimage: x\n"},
		"empty yaml file": {"empty.yaml": ""},
	} {
		_, stderr, code := run(t, "scan", "--path", writeDir(t, files), "--lenient")
		if code != 2 || !strings.Contains(stderr, "no Kubernetes") {
			t.Errorf("%s: code=%d stderr=%q", name, code, stderr)
		}
	}
}

func TestScanWorkloadSelector(t *testing.T) {
	dir := t.TempDir()
	manifest := strings.NewReplacer("vllm/vllm-openai:v0.6.0", "nginx", "name: vllm", "name: web").Replace(lowOnly)
	manifest = strings.Replace(manifest, "app: vllm\n    spec", "app: vllm\n        tier: inference\n    spec", 1)
	if err := os.WriteFile(filepath.Join(dir, "m.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, code := run(t, "scan", "--path", dir); code != 0 {
		t.Errorf("non-AI workload flagged, code = %d", code)
	}
	if _, _, code := run(t, "scan", "--path", dir, "--workload-selector", "tier=inference"); code != 1 {
		t.Errorf("selected workload not scanned, code = %d", code)
	}
	if _, stderr, code := run(t, "scan", "--path", dir, "--workload-selector", "tier in (("); code != 2 || !strings.Contains(stderr, "selector") {
		t.Errorf("invalid selector code=%d stderr=%s", code, stderr)
	}
}

func TestEnforceWritesPolicies(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	stdout, stderr, code := run(t, "enforce", "--out", out, "--selector", "team=llm,tier=gpu",
		"--mode", "enforce", "--allow-fqdn", "models.example.com", "--allow-fqdn", "*.cdn.example.org")
	if code != 0 {
		t.Fatalf("code = %d stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, "wrote 4 policies") {
		t.Errorf("stdout = %q", stdout)
	}
	cilium, err := os.ReadFile(filepath.Join(out, "aig-cilium-egress-fqdn.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"team: llm", "tier: gpu", "models.example.com", "cdn.example.org", "cdn-lfs.hf.co"} {
		if !strings.Contains(string(cilium), want) {
			t.Errorf("cilium policy lacks %q", want)
		}
	}
	kyverno, err := os.ReadFile(filepath.Join(out, "aig-require-nonroot.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(kyverno), "validationFailureAction: Enforce") || !strings.Contains(string(kyverno), "team: llm") {
		t.Errorf("kyverno policy wrong:\n%s", kyverno)
	}
}

func TestEnforceDefaultsToAudit(t *testing.T) {
	out := t.TempDir()
	if _, stderr, code := run(t, "enforce", "--out", out); code != 0 {
		t.Fatalf("code = %d stderr=%s", code, stderr)
	}
	b, err := os.ReadFile(filepath.Join(out, "aig-block-host-access.yaml"))
	if err != nil || !strings.Contains(string(b), "validationFailureAction: Audit") {
		t.Errorf("default mode is not Audit: %v\n%s", err, b)
	}
}

func TestEnforceDryRun(t *testing.T) {
	brokenKubeconfig(t)
	out := filepath.Join(t.TempDir(), "should-not-exist")
	stdout, _, code := run(t, "enforce", "--apply", "--dry-run", "--out", out)
	if code != 0 {
		t.Fatalf("code = %d", code)
	}
	if strings.Count(stdout, "would apply") != 4 {
		t.Errorf("stdout = %q", stdout)
	}
	if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
		t.Error("dry-run must not write files")
	}
}

func TestEnforceInvalidOptions(t *testing.T) {
	for _, args := range [][]string{
		{"enforce", "--mode", "block"},
		{"enforce", "--selector", "nokey"},
		{"enforce", "--allow-fqdn", "*"},
	} {
		_, stderr, code := run(t, args...)
		if code != 2 || !strings.Contains(stderr, "Error:") {
			t.Errorf("%v: code=%d stderr=%q", args, code, stderr)
		}
	}
}

func TestEnforceApplyWithoutCluster(t *testing.T) {
	brokenKubeconfig(t)
	_, stderr, code := run(t, "enforce", "--apply")
	if code != 2 || !strings.Contains(stderr, "Error:") {
		t.Errorf("code=%d stderr=%q", code, stderr)
	}
}

func TestExitErrorHelpers(t *testing.T) {
	inner := errors.New("boom")
	e := &ExitError{Code: 2, Err: inner}
	if e.Error() != "boom" || !errors.Is(e, inner) {
		t.Error("ExitError does not wrap")
	}
	if (&ExitError{Code: 1}).Error() == "" {
		t.Error("empty ExitError message")
	}
	if runtimeError(nil) != nil {
		t.Error("runtimeError(nil) must be nil")
	}
}

func TestEnforceSkipCilium(t *testing.T) {
	brokenKubeconfig(t)
	stdout, _, code := run(t, "enforce", "--apply", "--dry-run", "--skip-cilium")
	if code != 0 {
		t.Fatalf("code = %d", code)
	}
	if strings.Count(stdout, "would apply") != 3 || strings.Contains(stdout, "Cilium") {
		t.Errorf("stdout = %q", stdout)
	}
	out := filepath.Join(t.TempDir(), "out")
	stdout, _, code = run(t, "enforce", "--out", out, "--skip-cilium")
	if code != 0 || !strings.Contains(stdout, "wrote 3 policies") {
		t.Errorf("code=%d stdout=%q", code, stdout)
	}
	if _, err := os.Stat(filepath.Join(out, "aig-cilium-egress-fqdn.yaml")); !errors.Is(err, os.ErrNotExist) {
		t.Error("cilium file written")
	}
}

func TestHardenedExamplesHaveNoFindings(t *testing.T) {
	brokenKubeconfig(t)
	stdout, stderr, code := run(t, "scan", "--path", "../examples/hardened", "--fail-on", "low")
	if code != 0 || !strings.Contains(stdout, "No findings") {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	files, err := filepath.Glob("../examples/hardened/*.yaml")
	if err != nil || len(files) < 2 {
		t.Fatalf("examples missing: %v %v", files, err)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), "ai.infra.guard/enabled") {
			t.Errorf("%s is not opted in to ai-guard policies", f)
		}
	}
}

func fakeCluster(withCilium bool) (enforce.Cluster, *int) {
	patches := 0
	client := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	client.PrependReactor("patch", "*", func(clienttesting.Action) (bool, runtime.Object, error) {
		patches++
		return true, &unstructured.Unstructured{Object: map[string]interface{}{}}, nil
	})
	m := meta.NewDefaultRESTMapper(nil)
	m.Add(schema.GroupVersionKind{Group: "kyverno.io", Version: "v1", Kind: "ClusterPolicy"}, meta.RESTScopeRoot)
	if withCilium {
		m.Add(schema.GroupVersionKind{Group: "cilium.io", Version: "v2", Kind: "CiliumClusterwideNetworkPolicy"}, meta.RESTScopeRoot)
		m.Add(schema.GroupVersionKind{Group: "cilium.io", Version: "v2", Kind: "CiliumNetworkPolicy"}, meta.RESTScopeNamespace)
	}
	return enforce.Cluster{Context: "kind-test", Server: "https://127.0.0.1:6443", Client: client, Mapper: m}, &patches
}

func useFakeCluster(t *testing.T, withCilium, terminal bool) (*int, *string) {
	t.Helper()
	cluster, patches := fakeCluster(withCilium)
	var gotContext string
	oldConnect, oldTerm := connectCluster, isTerminal
	connectCluster = func(kubeconfig, kubeContext string) (enforce.Cluster, error) {
		gotContext = kubeContext
		return cluster, nil
	}
	isTerminal = func(io.Reader) bool { return terminal }
	t.Cleanup(func() { connectCluster, isTerminal = oldConnect, oldTerm })
	return patches, &gotContext
}

func runWithStdin(t *testing.T, stdin string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	var o, e bytes.Buffer
	root := NewRootCmd(&o, &e)
	root.SetIn(strings.NewReader(stdin))
	root.SetArgs(args)
	err := root.Execute()
	code = 0
	var ee *ExitError
	if errors.As(err, &ee) {
		code = ee.Code
		if ee.Err != nil {
			e.WriteString("Error: " + ee.Err.Error() + "\n")
		}
	} else if err != nil {
		code = 2
	}
	return o.String(), e.String(), code
}

func TestEnforceApplyNeedsYesWithoutTerminal(t *testing.T) {
	patches, _ := useFakeCluster(t, true, false)
	stdout, stderr, code := runWithStdin(t, "y\n", "enforce", "--apply")
	if code != 2 || !strings.Contains(stderr, "--yes") {
		t.Errorf("code=%d stderr=%q", code, stderr)
	}
	if *patches != 0 {
		t.Errorf("%d policies applied without confirmation", *patches)
	}
	if !strings.Contains(stdout, `context "kind-test"`) || !strings.Contains(stdout, "https://127.0.0.1:6443") {
		t.Errorf("cluster not printed: %q", stdout)
	}
}

func TestEnforceApplyWithYes(t *testing.T) {
	patches, gotContext := useFakeCluster(t, true, false)
	stdout, stderr, code := runWithStdin(t, "", "enforce", "--apply", "--yes", "--context", "staging")
	if code != 0 || *patches != 4 {
		t.Fatalf("code=%d patches=%d stderr=%q", code, *patches, stderr)
	}
	if *gotContext != "staging" {
		t.Errorf("context passed = %q", *gotContext)
	}
	if !strings.Contains(stdout, "applied CiliumClusterwideNetworkPolicy aig-inference-egress") {
		t.Errorf("stdout = %q", stdout)
	}
}

func TestEnforceApplyInteractive(t *testing.T) {
	patches, _ := useFakeCluster(t, true, true)
	_, stderr, code := runWithStdin(t, "n\n", "enforce", "--apply")
	if code != 2 || !strings.Contains(stderr, "aborted") || *patches != 0 {
		t.Errorf("decline: code=%d patches=%d stderr=%q", code, *patches, stderr)
	}
	_, _, code = runWithStdin(t, "", "enforce", "--apply")
	if code != 2 || *patches != 0 {
		t.Errorf("EOF must not confirm: code=%d patches=%d", code, *patches)
	}
	stdout, stderr, code := runWithStdin(t, "yes\n", "enforce", "--apply")
	if code != 0 || *patches != 4 || !strings.Contains(stdout, "[y/N]") {
		t.Errorf("accept: code=%d patches=%d stdout=%q stderr=%q", code, *patches, stdout, stderr)
	}
}

func TestEnforceApplyMissingCiliumChangesNothing(t *testing.T) {
	patches, _ := useFakeCluster(t, false, false)
	_, stderr, code := runWithStdin(t, "", "enforce", "--apply", "--yes")
	if code != 2 || *patches != 0 || !strings.Contains(stderr, "--skip-cilium") {
		t.Errorf("code=%d patches=%d stderr=%q", code, *patches, stderr)
	}
	_, stderr, code = runWithStdin(t, "", "enforce", "--apply", "--yes", "--skip-cilium")
	if code != 0 || *patches != 3 {
		t.Errorf("skip-cilium: code=%d patches=%d stderr=%q", code, *patches, stderr)
	}
}

func TestScanWarnsAboutMissingEnforceLabel(t *testing.T) {
	_, stderr, code := run(t, "scan", "--path", offendingDir)
	if code != 1 || !strings.Contains(stderr, "pod template lacks the label ai.infra.guard/enabled=true") {
		t.Errorf("code=%d stderr=%q", code, stderr)
	}
	_, stderr, _ = run(t, "scan", "--path", offendingDir, "--enforce-selector", "")
	if strings.Contains(stderr, "pod template lacks") {
		t.Errorf("warning not disabled: %q", stderr)
	}
	if _, stderr, code := run(t, "scan", "--path", offendingDir, "--enforce-selector", "nokey"); code != 2 || !strings.Contains(stderr, "enforce selector") {
		t.Errorf("invalid selector: code=%d stderr=%q", code, stderr)
	}
}
