package target

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"sigs.k8s.io/kustomize/kyaml/filesys"
	"sigs.k8s.io/yaml"
)

var (
	scpLike  = regexp.MustCompile(`^[\w.-]+@[\w.-]+:`)
	hostLike = regexp.MustCompile(`^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$`)
)

func isRemoteRef(fsys filesys.FileSystem, dir, ref string) bool {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return false
	}
	lower := strings.ToLower(ref)
	if strings.Contains(ref, "://") || strings.HasPrefix(lower, "git::") || strings.HasPrefix(lower, "git@") || scpLike.MatchString(ref) {
		return true
	}
	segs := strings.Split(filepath.ToSlash(ref), "/")
	if len(segs) < 3 || !hostLike.MatchString(segs[0]) {
		return false
	}
	return !fsys.Exists(filepath.Join(dir, filepath.FromSlash(ref)))
}

func stringsOf(v any) []string {
	list, _ := v.([]any)
	var out []string
	for _, e := range list {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func fieldOf(v any, key string) []string {
	list, _ := v.([]any)
	var out []string
	for _, e := range list {
		m, _ := e.(map[string]any)
		if s, ok := m[key].(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func kustomizationRefs(kust map[string]any) []string {
	var refs []string
	for _, k := range []string{"resources", "components", "bases", "crds", "configurations", "generators", "transformers"} {
		refs = append(refs, stringsOf(kust[k])...)
	}
	for _, k := range []string{"patches", "patchesJson6902", "replacements"} {
		refs = append(refs, fieldOf(kust[k], "path")...)
	}
	for _, p := range stringsOf(kust["patchesStrategicMerge"]) {
		if !strings.Contains(p, "\n") {
			refs = append(refs, p)
		}
	}
	if oa, ok := kust["openapi"].(map[string]any); ok {
		if p, ok := oa["path"].(string); ok {
			refs = append(refs, p)
		}
	}
	for _, k := range []string{"configMapGenerator", "secretGenerator"} {
		gens, _ := kust[k].([]any)
		for _, g := range gens {
			m, _ := g.(map[string]any)
			for _, f := range stringsOf(m["files"]) {
				_, p, ok := strings.Cut(f, "=")
				if !ok {
					p = f
				}
				refs = append(refs, p)
			}
			refs = append(refs, stringsOf(m["envs"])...)
			if e, ok := m["env"].(string); ok {
				refs = append(refs, e)
			}
		}
	}
	return refs
}

func findRemoteRef(fsys filesys.FileSystem, dir string, data []byte) (string, bool) {
	var kust map[string]any
	if err := yaml.Unmarshal(data, &kust); err != nil || kust == nil {
		return "", false
	}
	for _, r := range kustomizationRefs(kust) {
		if isRemoteRef(fsys, dir, r) {
			return r, true
		}
	}
	return "", false
}

func errRemoteRef(file, ref string) error {
	return fmt.Errorf("remote resource %q in %s is refused: the build would fetch it over the network (pass --allow-remote to allow this)", ref, file)
}
