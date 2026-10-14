package report

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"unicode/utf8"

	"github.com/sv222/ai-guard-k8s/pkg/checks"
)

func FuzzPrintJSON(f *testing.F) {
	f.Add("AIG-001", "High", "Deployment", "llm", "vllm", "evidence", "hint", "a.yaml", 1)
	f.Add("", "", "", "", "", "", "", "", 0)
	f.Add("AIG-009\t", "Medium", "Pod", "ns\n", "na\"me", "<script>&", "\\", "c:\\x.yaml", 3)
	f.Add("\u2028", "Low", "k", "n", "a", "\x00", "h", "s", 2)
	f.Fuzz(func(t *testing.T, id, sev, kind, ns, name, evidence, hint, source string, n int) {
		for _, s := range []string{id, sev, kind, ns, name, evidence, hint, source} {
			if !utf8.ValidString(s) {
				t.Skip()
			}
		}
		if n < 0 || n > 5 {
			n = 2
		}
		in := make([]checks.Finding, 0, n)
		for i := 0; i < n; i++ {
			in = append(in, checks.Finding{ID: id, Title: name, Severity: sev, Kind: kind, Namespace: ns, Name: name, Evidence: evidence, Hint: hint, Source: source})
		}
		var buf bytes.Buffer
		if err := PrintJSON(&buf, in); err != nil {
			t.Fatal(err)
		}
		if !json.Valid(buf.Bytes()) {
			t.Fatalf("invalid JSON: %q", buf.String())
		}
		var back []checks.Finding
		if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
			t.Fatal(err)
		}
		if len(in) == 0 {
			if back == nil || len(back) != 0 {
				t.Fatalf("empty input must give []: %q", buf.String())
			}
			return
		}
		if !reflect.DeepEqual(in, back) {
			t.Fatalf("round trip changed the findings:\n%+v\n%+v", in, back)
		}
		var table bytes.Buffer
		if err := PrintTable(&table, in); err != nil {
			t.Fatal(err)
		}
	})
}
