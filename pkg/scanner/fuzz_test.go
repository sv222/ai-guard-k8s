package scanner

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/sv222/ai-guard-k8s/pkg/checks"
	"github.com/sv222/ai-guard-k8s/pkg/target"
)

const fuzzTimeout = 20 * time.Second

func seedFiles(f *testing.F, globs ...string) {
	f.Helper()
	for _, g := range globs {
		matches, err := filepath.Glob(g)
		if err != nil {
			f.Fatal(err)
		}
		for _, m := range matches {
			data, err := os.ReadFile(m)
			if err != nil {
				f.Fatal(err)
			}
			f.Add(data)
		}
	}
}

func findingsSorted(fs []checks.Finding) bool {
	return sort.SliceIsSorted(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		if a.Title != b.Title {
			return a.Title < b.Title
		}
		return a.Evidence < b.Evidence
	})
}

func reversed(ds target.DirScan) target.DirScan {
	out := ds
	out.Targets = append([]target.WorkloadTarget(nil), ds.Targets...)
	for i, j := 0, len(out.Targets)-1; i < j; i, j = i+1, j-1 {
		out.Targets[i], out.Targets[j] = out.Targets[j], out.Targets[i]
	}
	out.NetPols = append([]target.NetworkPolicyEntry(nil), ds.NetPols...)
	for i, j := 0, len(out.NetPols)-1; i < j; i, j = i+1, j-1 {
		out.NetPols[i], out.NetPols[j] = out.NetPols[j], out.NetPols[i]
	}
	return out
}

const enforceSel = "ai.infra.guard/enabled=true"

func analyzeProblem(ds target.DirScan) error {
	first, w1 := AnalyzeWith(ds, "", enforceSel)
	second, w2 := AnalyzeWith(ds, "", enforceSel)
	if !reflect.DeepEqual(first, second) || !reflect.DeepEqual(w1, w2) {
		return errors.New("analysis is not deterministic")
	}
	if !findingsSorted(first) {
		return fmt.Errorf("findings are not sorted: %+v", first)
	}
	again, _ := AnalyzeWith(reversed(ds), "", enforceSel)
	if len(first) != len(again) {
		return fmt.Errorf("input order changes the number of findings: %d vs %d", len(first), len(again))
	}
	for i := range first {
		if first[i].ID != again[i].ID || first[i].Name != again[i].Name || first[i].Evidence != again[i].Evidence {
			return fmt.Errorf("input order changes the findings:\n%+v\n%+v", first[i], again[i])
		}
	}
	seen := map[string]bool{}
	for _, f := range first {
		if f.ID == "" || checks.SeverityRank(f.Severity) == 0 || f.Kind == "" || f.Evidence == "" {
			return fmt.Errorf("incomplete finding: %+v", f)
		}
		key := f.ID + "|" + f.Kind + "|" + f.Namespace + "|" + f.Name + "|" + f.Title + "|" + f.Evidence
		if seen[key] {
			return fmt.Errorf("duplicate finding: %+v", f)
		}
		seen[key] = true
	}
	return nil
}

func within[T any](t *testing.T, what string, fn func() T) T {
	t.Helper()
	done := make(chan T, 1)
	go func() { done <- fn() }()
	select {
	case v := <-done:
		return v
	case <-time.After(fuzzTimeout):
		t.Fatalf("%s took more than %s", what, fuzzTimeout)
		var zero T
		return zero
	}
}

func checkAnalyze(t *testing.T, ds target.DirScan) {
	t.Helper()
	if err := within(t, "analysis", func() error { return analyzeProblem(ds) }); err != nil {
		t.Fatal(err)
	}
}

func FuzzScanManifest(f *testing.F) {
	seedFiles(f,
		"../../testdata/manifests/*/*.yaml",
		"../../testdata/regress/*.yaml",
		"../../examples/hardened/*.yaml",
		"../target/testdata/*",
	)
	f.Add([]byte("kind: Pod\nmetadata: {name: vllm, labels: {ai.infra.guard/enabled: 'true'}}\nspec: {containers: [{name: c, image: vllm/vllm}]}"))
	f.Add([]byte("kind: NetworkPolicy\nmetadata: {name: p}\nspec: {podSelector: {matchExpressions: [{key: a, operator: Bogus}]}, ingress: [{}]}"))
	f.Fuzz(func(t *testing.T, data []byte) {
		ds := within(t, "decoding", func() target.DirScan { return target.FromBytes(data, "fuzz.yaml") })
		checkAnalyze(t, ds)
	})
}
