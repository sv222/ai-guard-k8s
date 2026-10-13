package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aiguard/ai-guard-k8s/pkg/checks"
)

func TestPrintJSONRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	fs := []checks.Finding{{ID: "AIG-001", Severity: "High", Namespace: "llm", Name: "vllm"}}
	if err := PrintJSON(&buf, fs); err != nil {
		t.Fatal(err)
	}
	var back []checks.Finding
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatal(err)
	}
	if len(back) != 1 || back[0].ID != "AIG-001" {
		t.Errorf("round trip lost data: %+v", back)
	}
}

func TestPrintJSONEmptyIsArray(t *testing.T) {
	var buf bytes.Buffer
	if err := PrintJSON(&buf, nil); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(buf.String()) != "[]" {
		t.Errorf("empty JSON = %q, want []", buf.String())
	}
}

func TestPrintTable(t *testing.T) {
	var buf bytes.Buffer
	if err := PrintTable(&buf, []checks.Finding{{ID: "AIG-003", Severity: "High", Namespace: "llm",
		Name: "ollama", Evidence: "hostNetwork", Hint: "x", Title: "t", Kind: "Deployment"}}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "AIG-003") || !strings.Contains(out, "Deployment/llm/ollama") {
		t.Errorf("table output wrong: %q", out)
	}
}

func TestPrintTableEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := PrintTable(&buf, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No findings") {
		t.Errorf("empty table = %q", buf.String())
	}
}
