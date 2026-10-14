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

func TestRegressTgiSubstringIsNotAnEngine(t *testing.T) {
	wantIDs(t, scanRegress(t, "postgis.yaml"), map[string]int{})
}

func TestRegressEnginesBeyondTheFirstList(t *testing.T) {
	res, err := Scan(context.Background(), Options{Path: regress + "/engines.yaml"})
	if err != nil {
		t.Fatal(err)
	}
	perWorkload := map[string]int{}
	for _, f := range res.Findings {
		if f.ID == "AIG-001" {
			perWorkload[f.Name]++
		}
	}
	for _, name := range []string{"embed", "assistant"} {
		if perWorkload[name] != 1 {
			t.Errorf("AIG-001 on %s = %d, want 1; got %v", name, perWorkload[name], perWorkload)
		}
	}
	if perWorkload["chat"] != 2 {
		t.Errorf("AIG-001 on chat = %d, want 2; got %v", perWorkload["chat"], perWorkload)
	}
	if got := idSet(res.Findings)["AIG-010"]; got != 1 {
		t.Errorf("AIG-010 = %d, want 1 (embed behind a LoadBalancer)", got)
	}
}
