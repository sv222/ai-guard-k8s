package enforce

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPoliciesGolden(t *testing.T) {
	files := Policies("ai.infra.guard/enabled=true")
	if len(files) != 4 {
		t.Fatalf("policies = %d, want 4", len(files))
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
