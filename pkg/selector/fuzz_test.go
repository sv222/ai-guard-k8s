package selector

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/util/validation"
)

func FuzzParse(f *testing.F) {
	for _, s := range []string{
		DefaultEnforce, "a=b", "a=b,c=d", " a = b , c=d ", "", ",,", "nokey", "a=", "=b", "a=b=c", "ai.infra.guard/enabled=true",
		"team=llm, tier=gpu", "a=b,a=c", "bad key=v", "k=v\n", "a/b/c=d", strings.Repeat("a", 300) + "=b",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, err := Parse(s)
		if err != nil {
			if got != nil {
				t.Fatalf("error with non-nil result: %v", got)
			}
			return
		}
		keys := make([]string, 0, len(got))
		for k, v := range got {
			if len(validation.IsQualifiedName(k)) > 0 || len(validation.IsValidLabelValue(v)) > 0 || v == "" {
				t.Fatalf("accepted invalid pair %q=%q from %q", k, v, s)
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, k+"="+got[k])
		}
		again, err := Parse(strings.Join(parts, ","))
		if err != nil || !reflect.DeepEqual(got, again) {
			t.Fatalf("round trip failed for %q: %v %v", s, again, err)
		}
	})
}
