package enforce

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

var update = flag.Bool("update", false, "rewrite golden files and the policies mirror")

const mirrorDir = "../../policies"

func defaultPolicies(t *testing.T) []PolicyFile {
	t.Helper()
	files, err := Policies(Options{})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func TestPoliciesGolden(t *testing.T) {
	files := defaultPolicies(t)
	if len(files) != 4 {
		t.Fatalf("policies = %d, want 4", len(files))
	}
	if *update {
		if err := Write("testdata/golden", files); err != nil {
			t.Fatal(err)
		}
		if err := Write(mirrorDir, files); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range files {
		golden := filepath.Join("testdata/golden", f.Name)
		want, err := os.ReadFile(golden)
		if err != nil {
			t.Fatalf("missing golden %s: %v", golden, err)
		}
		if f.Content != string(want) {
			t.Errorf("%s differs from golden:\n%s", f.Name, f.Content)
		}
	}
}

func TestPoliciesMirrorMatchesDefaultOutput(t *testing.T) {
	for _, f := range defaultPolicies(t) {
		got, err := os.ReadFile(filepath.Join(mirrorDir, f.Name))
		if err != nil {
			t.Fatalf("policies/ mirror missing %s: %v", f.Name, err)
		}
		if string(got) != f.Content {
			t.Errorf("policies/%s is out of date; run go test ./pkg/enforce -update", f.Name)
		}
	}
	entries, err := os.ReadDir(mirrorDir)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"README.md": true}
	for _, f := range defaultPolicies(t) {
		want[f.Name] = true
	}
	for _, e := range entries {
		if !want[e.Name()] {
			t.Errorf("unexpected file in policies/: %s", e.Name())
		}
	}
}

func TestPoliciesAreValidYAMLWithRuleLists(t *testing.T) {
	files, err := Policies(Options{Mode: "enforce", Selector: "team=llm,tier=gpu", AllowFQDNs: []string{"models.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		var doc map[string]interface{}
		if err := yaml.Unmarshal([]byte(f.Content), &doc); err != nil {
			t.Fatalf("%s: %v", f.Name, err)
		}
		if doc["kind"] == nil || doc["apiVersion"] == nil {
			t.Errorf("%s lacks kind/apiVersion", f.Name)
		}
		if doc["kind"] != "ClusterPolicy" {
			continue
		}
		spec := doc["spec"].(map[string]interface{})
		if spec["validationFailureAction"] != "Enforce" {
			t.Errorf("%s action = %v", f.Name, spec["validationFailureAction"])
		}
		rules, ok := spec["rules"].([]interface{})
		if !ok || len(rules) == 0 {
			t.Fatalf("%s: rules is not a list: %v", f.Name, spec["rules"])
		}
		for _, r := range rules {
			rm := r.(map[string]interface{})
			if rm["name"] == nil || rm["match"] == nil || rm["exclude"] == nil || rm["validate"] == nil {
				t.Errorf("%s: incomplete rule %v", f.Name, rm)
			}
		}
	}
}

func TestSelectorAppliesToKyvernoAndCilium(t *testing.T) {
	files, err := Policies(Options{Selector: "team=llm, tier=gpu"})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if !strings.Contains(f.Content, "team: llm") || !strings.Contains(f.Content, "tier: gpu") {
			t.Errorf("%s does not carry the custom selector:\n%s", f.Name, f.Content)
		}
		if strings.Contains(f.Content, "ai.infra.guard/enabled") {
			t.Errorf("%s still uses the default selector", f.Name)
		}
	}
}

func TestDefaultSelector(t *testing.T) {
	for _, f := range defaultPolicies(t) {
		if !strings.Contains(f.Content, `ai.infra.guard/enabled: "true"`) {
			t.Errorf("%s lacks default selector", f.Name)
		}
	}
}

func TestModeAndExclusions(t *testing.T) {
	audit := defaultPolicies(t)
	for _, f := range audit[:3] {
		if !strings.Contains(f.Content, "validationFailureAction: Audit") {
			t.Errorf("%s is not Audit by default", f.Name)
		}
		for _, ns := range []string{"kube-system", "kube-public", "kube-node-lease"} {
			if !strings.Contains(f.Content, ns) {
				t.Errorf("%s does not exclude %s", f.Name, ns)
			}
		}
	}
	enforced, err := Policies(Options{Mode: "ENFORCE"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(enforced[0].Content, "validationFailureAction: Enforce") {
		t.Error("enforce mode not applied")
	}
	if _, err := Policies(Options{Mode: "block"}); err == nil {
		t.Error("expected error for invalid mode")
	}
}

func TestInvalidSelector(t *testing.T) {
	for _, s := range []string{"nokey", "a=", "bad key=v", ",,"} {
		if _, err := Policies(Options{Selector: s}); err == nil {
			t.Errorf("selector %q should be rejected", s)
		}
	}
}

func TestFQDNs(t *testing.T) {
	cilium := func(extra ...string) string {
		files, err := Policies(Options{AllowFQDNs: extra})
		if err != nil {
			t.Fatal(err)
		}
		return files[3].Content
	}
	base := cilium()
	for _, h := range []string{"huggingface.co", "cdn-lfs.hf.co", "cas-bridge.xethub.hf.co", "transfer.xethub.hf.co", "cas-server.xethub.hf.co"} {
		if !strings.Contains(base, "matchName: "+h) {
			t.Errorf("default policy lacks %s", h)
		}
	}
	for _, p := range []string{"*.huggingface.co", "*.hf.co"} {
		if !strings.Contains(base, "matchPattern: '"+p+"'") {
			t.Errorf("default policy lacks pattern %s", p)
		}
	}
	extra := cilium("Models.Example.com.", "*.cdn.example.org", "huggingface.co")
	if !strings.Contains(extra, "matchName: models.example.com") || !strings.Contains(extra, "matchPattern: '*.cdn.example.org'") {
		t.Errorf("extra hosts missing:\n%s", extra)
	}
	if strings.Count(extra, "huggingface.co") != strings.Count(base, "huggingface.co") {
		t.Error("duplicate default host was added twice")
	}
	for _, bad := range []string{"", "*", "localhost", "bad host.com", "a..b/c"} {
		if _, err := Policies(Options{AllowFQDNs: []string{bad}}); err == nil {
			t.Errorf("allow-fqdn %q should be rejected", bad)
		}
	}
	if len(DefaultFQDNs()) < 5 {
		t.Error("DefaultFQDNs too short")
	}
}

func TestCiliumNamespace(t *testing.T) {
	files, err := Policies(Options{Namespace: "llm"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(files[3].Content, "namespace: llm") {
		t.Errorf("namespace missing:\n%s", files[3].Content)
	}
}

func TestWrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "out")
	files := defaultPolicies(t)
	if err := Write(dir, files); err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		got, err := os.ReadFile(filepath.Join(dir, f.Name))
		if err != nil || string(got) != f.Content {
			t.Errorf("%s not written correctly: %v", f.Name, err)
		}
	}
}
