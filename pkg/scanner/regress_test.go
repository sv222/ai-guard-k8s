package scanner

import (
	"context"
	"testing"
)

const regress = "../../testdata/regress"

func scanRegress(t *testing.T, file string) map[string]int {
	t.Helper()
	res, err := Scan(context.Background(), Options{Path: regress + "/" + file})
	if err != nil {
		t.Fatal(err)
	}
	return idSet(res.Findings)
}

func wantIDs(t *testing.T, got map[string]int, want map[string]int) {
	t.Helper()
	for id, n := range want {
		if got[id] != n {
			t.Errorf("%s = %d, want %d; got %v", id, got[id], n, got)
		}
	}
	for id, n := range got {
		if _, ok := want[id]; !ok {
			t.Errorf("unexpected %s x%d; got %v", id, n, got)
		}
	}
}

func TestRegressHelmTestHookPodIsSkipped(t *testing.T) {
	wantIDs(t, scanRegress(t, "helm-test-hook.yaml"), map[string]int{})
}
