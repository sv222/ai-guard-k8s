package enforce

import (
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

func FuzzValidateFQDN(f *testing.F) {
	for _, s := range []string{
		"models.example.com", "*.example.com", "*.com", "*.*", "*", "", "a.b", "Models.Example.COM.", "a*.example.com",
		"xn--bcher-kva.example", "-a.example.com", "a..b", "*.a.b", strings.Repeat("a", 64) + ".com", "a_b.example.com", " x.y ",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		h, err := ValidateFQDN(raw)
		if err != nil {
			if h != "" {
				t.Fatalf("error with non-empty result %q", h)
			}
			return
		}
		if h != strings.ToLower(h) || strings.HasSuffix(h, ".") || len(h) > 253 {
			t.Fatalf("badly normalized result %q from %q", h, raw)
		}
		labels := strings.Split(h, ".")
		if len(labels) < 2 {
			t.Fatalf("single label accepted: %q", h)
		}
		for i, l := range labels {
			if strings.Contains(l, "*") && (i != 0 || l != "*" || len(labels) < 3) {
				t.Fatalf("bad wildcard accepted: %q", h)
			}
			if l == "" || strings.ContainsAny(l, " _/\\\t\n") {
				t.Fatalf("bad label accepted: %q", h)
			}
		}
		again, err := ValidateFQDN(h)
		if err != nil || again != h {
			t.Fatalf("not idempotent: %q -> %q (%v)", h, again, err)
		}
	})
}

func FuzzPolicies(f *testing.F) {
	f.Add("", "", "", "", false, false)
	f.Add("team=llm,tier=gpu", "enforce", "llm", "models.example.com", true, false)
	f.Add("a=b", "AUDIT", "ns", "*.example.com", false, true)
	f.Add("a: b", "audit", "x: y", "a\nb.example.com", false, false)
	f.Add("k=\"v\"", "enforce", "-bad-", "*.com", true, false)
	f.Fuzz(func(t *testing.T, sel, mode, ns, fqdn string, restrict, skip bool) {
		var extra []string
		if fqdn != "" {
			extra = []string{fqdn}
		}
		files, err := Policies(Options{Selector: sel, Mode: mode, Namespace: ns, AllowFQDNs: extra, RestrictDNS: restrict, SkipCilium: skip})
		if err != nil {
			return
		}
		wantFiles := 4
		if skip {
			wantFiles = 3
		}
		if len(files) != wantFiles {
			t.Fatalf("got %d files, want %d", len(files), wantFiles)
		}
		for _, file := range files {
			var doc map[string]interface{}
			if err := yaml.Unmarshal([]byte(file.Content), &doc); err != nil {
				t.Fatalf("%s is not valid YAML: %v\n%s", file.Name, err, file.Content)
			}
			if doc["kind"] == nil || doc["apiVersion"] == nil {
				t.Fatalf("%s lacks kind or apiVersion", file.Name)
			}
			if err := Check(testMapper(true), []PolicyFile{file}, ""); err != nil {
				t.Fatalf("%s does not resolve: %v", file.Name, err)
			}
			checkNoBareWildcards(t, file.Name, doc)
		}
	})
}

func checkNoBareWildcards(t *testing.T, name string, doc map[string]interface{}) {
	t.Helper()
	spec, _ := doc["spec"].(map[string]interface{})
	egress, _ := spec["egress"].([]interface{})
	for _, e := range egress {
		rule, _ := e.(map[string]interface{})
		names, _ := rule["toFQDNs"].([]interface{})
		for _, n := range names {
			entry, _ := n.(map[string]interface{})
			for _, key := range []string{"matchName", "matchPattern"} {
				v, ok := entry[key].(string)
				if !ok {
					continue
				}
				if _, err := ValidateFQDN(v); err != nil {
					t.Fatalf("%s: toFQDNs %s %q is not an acceptable host: %v", name, key, v, err)
				}
			}
		}
	}
}
