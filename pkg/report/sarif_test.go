package report

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/sv222/ai-guard-k8s/pkg/checks"
)

var update = flag.Bool("update", false, "rewrite golden files")

type sarifDoc struct {
	Version string `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name  string `json:"name"`
				Rules []struct {
					ID string `json:"id"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID    string `json:"ruleId"`
			RuleIndex int    `json:"ruleIndex"`
			Level     string `json:"level"`
			Message   struct {
				Text string `json:"text"`
			} `json:"message"`
			Locations []struct {
				PhysicalLocation *struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine int `json:"startLine"`
					} `json:"region"`
				} `json:"physicalLocation"`
				LogicalLocations []struct {
					FullyQualifiedName string `json:"fullyQualifiedName"`
				} `json:"logicalLocations"`
			} `json:"locations"`
			PartialFingerprints map[string]string `json:"partialFingerprints"`
		} `json:"results"`
	} `json:"runs"`
}

func parseSARIF(t *testing.T, fs []checks.Finding) sarifDoc {
	t.Helper()
	var buf bytes.Buffer
	if err := PrintSARIF(&buf, fs, "1.2.3"); err != nil {
		t.Fatal(err)
	}
	var d sarifDoc
	if err := json.Unmarshal(buf.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	if d.Version != "2.1.0" || len(d.Runs) != 1 || d.Runs[0].Tool.Driver.Name != "ai-guard" {
		t.Fatalf("bad SARIF header: %+v", d)
	}
	return d
}

var sample = []checks.Finding{
	{ID: "AIG-003", Title: "hostNetwork enabled", Severity: "High", Kind: "Deployment", Namespace: "llm", Name: "vllm", Evidence: "hostNetwork: true", Hint: "set hostNetwork: false", Source: "manifests/vllm.yaml"},
	{ID: "AIG-001", Title: "no auth", Severity: "Medium", Kind: "Deployment", Namespace: "llm", Name: "ollama", Evidence: "no key", Source: "cluster"},
	{ID: "AIG-007", Title: "missing resource requests/limits", Severity: "Low", Kind: "Pod", Namespace: "llm", Name: "p", Evidence: "c", Source: "./a/../b.yaml"},
	{ID: "AIG-003", Title: "hostPID enabled", Severity: "High", Kind: "Deployment", Namespace: "llm", Name: "vllm", Evidence: "hostPID: true", Source: "manifests/vllm.yaml"},
}

func TestSARIFEmpty(t *testing.T) {
	d := parseSARIF(t, nil)
	if d.Runs[0].Results == nil || len(d.Runs[0].Results) != 0 || len(d.Runs[0].Tool.Driver.Rules) != 0 {
		t.Errorf("empty input must give empty results and rules: %+v", d.Runs[0])
	}
}

func TestSARIFRulesAndLevels(t *testing.T) {
	d := parseSARIF(t, sample)
	rules := d.Runs[0].Tool.Driver.Rules
	if len(rules) != 3 || rules[0].ID != "AIG-001" || rules[1].ID != "AIG-003" || rules[2].ID != "AIG-007" {
		t.Fatalf("rules = %+v, want AIG-001, AIG-003, AIG-007", rules)
	}
	want := []struct {
		id, level string
		index     int
	}{{"AIG-003", "error", 1}, {"AIG-001", "warning", 0}, {"AIG-007", "note", 2}, {"AIG-003", "error", 1}}
	res := d.Runs[0].Results
	if len(res) != len(want) {
		t.Fatalf("got %d results, want %d", len(res), len(want))
	}
	for i, w := range want {
		if res[i].RuleID != w.id || res[i].Level != w.level || res[i].RuleIndex != w.index {
			t.Errorf("result %d = %s/%s/%d, want %s/%s/%d", i, res[i].RuleID, res[i].Level, res[i].RuleIndex, w.id, w.level, w.index)
		}
	}
	if res[0].PartialFingerprints["aiGuardFinding/v1"] == res[3].PartialFingerprints["aiGuardFinding/v1"] {
		t.Error("different findings on the same object share a fingerprint")
	}
	if got := res[0].Message.Text; got != "hostNetwork enabled in Deployment/llm/vllm: hostNetwork: true. Fix: set hostNetwork: false" {
		t.Errorf("message = %q", got)
	}
}

func TestSARIFLocations(t *testing.T) {
	res := parseSARIF(t, sample).Runs[0].Results
	file := res[0].Locations[0]
	if file.PhysicalLocation == nil || file.PhysicalLocation.ArtifactLocation.URI != "manifests/vllm.yaml" || file.PhysicalLocation.Region.StartLine != 1 {
		t.Errorf("file location = %+v", file.PhysicalLocation)
	}
	if file.LogicalLocations[0].FullyQualifiedName != "Deployment/llm/vllm" {
		t.Errorf("logical location = %+v", file.LogicalLocations)
	}
	if res[1].Locations[0].PhysicalLocation != nil {
		t.Error("cluster finding must have no file location")
	}
	if got := res[2].Locations[0].PhysicalLocation.ArtifactLocation.URI; got != "b.yaml" {
		t.Errorf("uri = %q, want b.yaml", got)
	}
}

func TestSARIFAbsoluteURI(t *testing.T) {
	abs, err := filepath.Abs("x.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if got := sarifURI(abs); got != "file://"+filepath.ToSlash(abs) && got != "file:///"+filepath.ToSlash(abs) {
		t.Errorf("sarifURI(%q) = %q", abs, got)
	}
}

func TestSARIFURIEscapesSegments(t *testing.T) {
	tests := map[string]string{
		"manifests/my app/dep.yaml": "manifests/my%20app/dep.yaml",
		"a#b/c%d.yaml":              "a%23b/c%25d.yaml",
		"plain/dep.yaml":            "plain/dep.yaml",
	}
	for in, want := range tests {
		if got := sarifURI(in); got != want {
			t.Errorf("sarifURI(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSARIFGolden(t *testing.T) {
	var buf bytes.Buffer
	if err := PrintSARIF(&buf, sample, "1.2.3"); err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "golden", "sample.sarif")
	if *update {
		if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("missing golden %s: %v (run go test ./pkg/report -update)", golden, err)
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("SARIF differs from %s; run go test ./pkg/report -update and review the diff:\n%s", golden, buf.String())
	}
}
