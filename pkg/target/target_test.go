package target

import (
	"testing"
)

func TestFromDirExtractsWorkload(t *testing.T) {
	ds, err := FromDir("testdata")
	if err != nil {
		t.Fatal(err)
	}
	if len(ds.Targets) != 1 {
		t.Fatalf("targets = %d, want 1", len(ds.Targets))
	}
	w := ds.Targets[0]
	if w.Kind != "Deployment" || w.Namespace != "llm" || w.Name != "vllm-openai" {
		t.Errorf("workload identity = %s/%s/%s", w.Kind, w.Namespace, w.Name)
	}
	if w.Containers()[0].Image != "vllm/vllm-openai:v0.6.0" {
		t.Errorf("image = %s", w.Containers()[0].Image)
	}
	if len(ds.NetPols) != 1 {
		t.Errorf("netpols = %d, want 1", len(ds.NetPols))
	}
	if len(ds.Services) != 1 || ds.Services[0].Type != "LoadBalancer" {
		t.Errorf("services = %+v", ds.Services)
	}
}

func TestFromDirEmptySelectorNetPolCoversAll(t *testing.T) {
	ds, err := FromDir("testdata")
	if err != nil {
		t.Fatal(err)
	}
	if len(ds.NetPols) != 1 || ds.NetPols[0].PodSelector.MatchLabels != nil &&
		len(ds.NetPols[0].PodSelector.MatchLabels) != 0 {
		t.Errorf("expected empty podSelector")
	}
}
