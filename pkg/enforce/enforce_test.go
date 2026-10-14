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
	for _, h := range []string{"huggingface.co", "cdn-lfs.hf.co", "cas-bridge.xethub.hf.co", "transfer.xethub.hf.co", "cas-server.xethub.hf.co", "us.aws.cdn.hf.co", "us.gcp.cdn.hf.co", "cas-server.xethub-eu.hf.co", "transfer.xethub-eu.hf.co"} {
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
	for _, bad := range []string{"", "*", "*.", "localhost", "bad host.com", "a..b/c", "*.com", "*.*", "*.*.example.com", "a*.example.com", "foo.*.example.com", "**.example.com", "*example.com", "-a.example.com", "a-.example.com", ".example.com", "a..example.com", "ex_ample.com", strings.Repeat("a", 64) + ".com", strings.Repeat("a.", 130) + "com"} {
		if _, err := Policies(Options{AllowFQDNs: []string{bad}}); err == nil {
			t.Errorf("allow-fqdn %q should be rejected", bad)
		}
	}
	if len(DefaultFQDNs()) < 5 {
		t.Error("DefaultFQDNs too short")
	}
}

func TestCiliumScope(t *testing.T) {
	files, err := Policies(Options{Namespace: "llm"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(files[3].Content, "namespace: llm") || !strings.Contains(files[3].Content, "kind: CiliumNetworkPolicy") {
		t.Errorf("namespaced policy expected:\n%s", files[3].Content)
	}
	def := defaultPolicies(t)
	if !strings.Contains(def[3].Content, "kind: CiliumClusterwideNetworkPolicy") || strings.Contains(def[3].Content, "\n  namespace: ") {
		t.Errorf("cluster-wide policy expected:\n%s", def[3].Content)
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

func TestSkipCilium(t *testing.T) {
	files, err := Policies(Options{SkipCilium: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 3 {
		t.Fatalf("got %d files, want 3", len(files))
	}
	for _, f := range files {
		if strings.Contains(f.Content, "CiliumNetworkPolicy") {
			t.Errorf("%s contains a Cilium policy", f.Name)
		}
	}
}

func TestValidateFQDN(t *testing.T) {
	for in, want := range map[string]string{
		"models.example.com":    "models.example.com",
		" Models.Example.COM.":  "models.example.com",
		"*.example.com":         "*.example.com",
		"*.cdn.example.co.uk":   "*.cdn.example.co.uk",
		"xn--bcher-kva.example": "xn--bcher-kva.example",
		"a.b":                   "a.b",
	} {
		got, err := ValidateFQDN(in)
		if err != nil || got != want {
			t.Errorf("ValidateFQDN(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"*.com", "*.*", "*", "com", "a.*.com", "*.example.*"} {
		if got, err := ValidateFQDN(in); err == nil {
			t.Errorf("ValidateFQDN(%q) = %q, want error", in, got)
		}
	}
}

func TestRestrictDNS(t *testing.T) {
	open, err := Policies(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(open[3].Content, "dns:\n        - matchPattern: '*'") {
		t.Errorf("default DNS rule should allow every name:\n%s", open[3].Content)
	}
	files, err := Policies(Options{RestrictDNS: true, AllowFQDNs: []string{"models.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]interface{}
	if err := yaml.Unmarshal([]byte(files[3].Content), &doc); err != nil {
		t.Fatal(err)
	}
	egress := doc["spec"].(map[string]interface{})["egress"].([]interface{})
	dns := egress[0].(map[string]interface{})["toPorts"].([]interface{})[0].(map[string]interface{})["rules"].(map[string]interface{})["dns"].([]interface{})
	fqdns := egress[1].(map[string]interface{})["toFQDNs"].([]interface{})
	if len(dns) != len(fqdns) {
		t.Fatalf("dns rules %d, fqdn rules %d", len(dns), len(fqdns))
	}
	for i := range dns {
		d, f := dns[i].(map[string]interface{}), fqdns[i].(map[string]interface{})
		for k, v := range d {
			if f[k] != v {
				t.Errorf("dns rule %v differs from fqdn rule %v", d, f)
			}
		}
		if d["matchPattern"] == "*" {
			t.Error("restricted DNS rule still allows every name")
		}
	}
}

func TestWriteRefusesSymlinksAndSpecialFiles(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	files := defaultPolicies(t)
	if err := os.Symlink(victim, filepath.Join(dir, files[1].Name)); err != nil {
		t.Skip("symlinks not available:", err)
	}
	err := Write(dir, files)
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("err = %v", err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Errorf("symlink target was overwritten: %q", b)
	}
	if _, err := os.Stat(filepath.Join(dir, files[0].Name)); err == nil {
		t.Error("files were written although one target was refused")
	}
}

func TestWriteOverwritesRegularFiles(t *testing.T) {
	dir := t.TempDir()
	files := defaultPolicies(t)
	if err := os.WriteFile(filepath.Join(dir, files[0].Name), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Write(dir, files); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, files[0].Name)); string(b) != files[0].Content {
		t.Error("regular file not replaced")
	}
}

func TestHostAndResourceRulesCoverNewFields(t *testing.T) {
	files := defaultPolicies(t)
	byName := map[string]string{}
	for _, f := range files {
		byName[f.Name] = f.Content
	}
	host := byName["aig-block-host-access.yaml"]
	for _, want := range []string{"=(hostIPC)", "=(hostPort)", "=(initContainers)"} {
		if !strings.Contains(host, want) {
			t.Errorf("host access policy lacks %s", want)
		}
	}
	if !strings.Contains(byName["aig-require-resources.yaml"], "=(initContainers)") {
		t.Error("resources policy ignores init containers")
	}
}
