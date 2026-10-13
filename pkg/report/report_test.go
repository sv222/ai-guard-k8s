package report

import (
	"bytes"
	"encoding/json"
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

func TestPrintTableNonEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := PrintTable(&buf, []checks.Finding{{ID: "AIG-003", Severity: "High", Namespace: "llm",
		Name: "ollama", Evidence: "hostNetwork", Hint: "x", Title: "t", Kind: "Deployment"}}); err != nil {
		t.Fatal(err)
	}
	if buf.Len() == 0 {
		t.Error("table output empty")
	}
}
