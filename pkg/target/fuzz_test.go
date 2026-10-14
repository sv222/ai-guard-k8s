package target

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

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

func FuzzFromBytes(f *testing.F) {
	seedFiles(f,
		"testdata/*",
		"../../testdata/manifests/*/*.yaml",
		"../../testdata/regress/*.yaml",
		"../../examples/hardened/*.yaml",
		"../../testdata/kyverno/*.yaml",
	)
	f.Add([]byte(""))
	f.Add([]byte("---\n---\n"))
	f.Add([]byte("null"))
	f.Add([]byte("[]"))
	f.Add([]byte("{\"kind\":\"List\",\"items\":[{\"kind\":\"Pod\"},null,1]}"))
	f.Add([]byte("kind: Deployment\nspec: {template: {spec: {containers: [{name: 1}]}}}"))
	f.Add([]byte("kind: Service\nspec: {ports: [{port: 99999999999}]}"))
	f.Add([]byte("a: &a [*a]"))
	f.Fuzz(func(t *testing.T, data []byte) {
		first := FromBytes(data, "f.yaml")
		second := FromBytes(data, "f.yaml")
		if !reflect.DeepEqual(first, second) {
			t.Fatal("decoding is not deterministic")
		}
		if first.Failed < 0 || first.Objects < 0 {
			t.Fatalf("negative counters: %+v", first)
		}
		if first.Failed > len(first.Warnings) {
			t.Fatalf("failed=%d but only %d warnings", first.Failed, len(first.Warnings))
		}
		for _, w := range first.Targets {
			if w.Kind == "" || w.Namespace == "" || w.Source != "f.yaml" {
				t.Fatalf("incomplete target: %+v", w)
			}
		}
		for _, p := range first.NetPols {
			if p.Namespace == "" {
				t.Fatalf("network policy without namespace: %+v", p)
			}
		}
		for _, s := range first.Services {
			if s.Namespace == "" {
				t.Fatalf("service without namespace: %+v", s)
			}
		}
	})
}
