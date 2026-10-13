package selector

import (
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
)

const DefaultEnforce = "ai.infra.guard/enabled=true"

func Parse(s string) (map[string]string, error) {
	out := map[string]string{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("invalid selector term %q: want key=value", part)
		}
		k, v := strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1])
		if k == "" || v == "" {
			return nil, fmt.Errorf("invalid selector term %q: key and value must not be empty", part)
		}
		if errs := validation.IsQualifiedName(k); len(errs) > 0 {
			return nil, fmt.Errorf("invalid label key %q: %s", k, strings.Join(errs, "; "))
		}
		if errs := validation.IsValidLabelValue(v); len(errs) > 0 {
			return nil, fmt.Errorf("invalid label value %q: %s", v, strings.Join(errs, "; "))
		}
		out[k] = v
	}
	return out, nil
}
