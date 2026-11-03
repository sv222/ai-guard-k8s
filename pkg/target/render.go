package target

import (
	"bytes"
	"cmp"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"helm.sh/helm/v4/pkg/action"
	"helm.sh/helm/v4/pkg/chart"
	"helm.sh/helm/v4/pkg/chart/loader"
	"helm.sh/helm/v4/pkg/cli/values"
	"helm.sh/helm/v4/pkg/release"
	"sigs.k8s.io/kustomize/api/konfig"
	"sigs.k8s.io/kustomize/api/krusty"
	"sigs.k8s.io/kustomize/api/types"
	"sigs.k8s.io/kustomize/kyaml/filesys"
	"sigs.k8s.io/yaml"
)

const sourcePrefix = "# Source: "

func FromHelm(chartPath, namespace string, valueFiles, set []string) (DirScan, error) {
	ch, err := loader.Load(chartPath)
	if err != nil {
		return DirScan{}, fmt.Errorf("load Helm chart %s: %w", chartPath, err)
	}
	ac, err := chart.NewAccessor(ch)
	if err != nil {
		return DirScan{}, err
	}
	if t := ac.MetadataAsMap()["Type"]; t != nil && t != "" && t != "application" {
		return DirScan{}, fmt.Errorf("chart %s: %s charts are not installable", chartPath, t)
	}
	if req := ac.MetaDependencies(); len(req) > 0 {
		if err := action.CheckDependencies(ch, req); err != nil {
			return DirScan{}, fmt.Errorf("chart %s: %w (run helm dependency build)", chartPath, err)
		}
	}
	vals, err := (&values.Options{ValueFiles: valueFiles, Values: set}).MergeValues(nil)
	if err != nil {
		return DirScan{}, err
	}
	inst := action.NewInstall(action.NewConfiguration(action.ConfigurationSetLogger(slog.DiscardHandler)))
	inst.DryRunStrategy = action.DryRunClient
	inst.ReleaseName = "release-name"
	inst.Namespace = orDefault(namespace, "default")
	inst.Replace = true
	rel, err := inst.Run(ch, vals)
	if err != nil {
		return DirScan{}, fmt.Errorf("render Helm chart %s: %w", chartPath, err)
	}
	acc, err := release.NewAccessor(rel)
	if err != nil {
		return DirScan{}, err
	}
	files := map[string]*bytes.Buffer{}
	var order []string
	add := func(src, doc string) {
		if files[src] == nil {
			files[src] = &bytes.Buffer{}
			order = append(order, src)
		}
		files[src].WriteString("---\n" + doc + "\n")
	}
	docs, err := splitDocuments([]byte(acc.Manifest()))
	if err != nil {
		return DirScan{}, fmt.Errorf("render Helm chart %s: %w", chartPath, err)
	}
	for _, d := range docs {
		first, _, _ := strings.Cut(string(d.data), "\n")
		src, ok := strings.CutPrefix(first, sourcePrefix)
		if !ok {
			src = ""
		}
		add(src, string(d.data))
	}
	for _, h := range acc.Hooks() {
		ha, err := release.NewHookAccessor(h)
		if err != nil {
			return DirScan{}, err
		}
		add(ha.Path(), ha.Manifest())
	}
	var out DirScan
	for _, src := range order {
		consumeRendered(&out, files[src].Bytes(), helmSource(chartPath, src))
	}
	return out, nil
}

func helmSource(chartPath, src string) string {
	if fi, err := os.Stat(chartPath); err != nil || !fi.IsDir() {
		return chartPath
	}
	_, rest, ok := strings.Cut(filepath.ToSlash(src), "/")
	if !ok {
		return chartPath
	}
	return filepath.Join(chartPath, filepath.FromSlash(rest))
}

func FromKustomize(dir string, allowRemote bool) (DirScan, error) {
	abs, err := filepath.Abs(dir)
	if err == nil {
		abs, err = filepath.EvalSymlinks(abs)
	}
	if err != nil {
		return DirScan{}, err
	}
	k := krusty.MakeKustomizer(krusty.MakeDefaultOptions())
	fs := &originFS{FileSystem: filesys.MakeFsOnDisk(), root: abs, allowRemote: allowRemote}
	m, err := k.Run(fs, abs)
	if fs.refused != nil {
		return DirScan{}, fmt.Errorf("build kustomization %s: %w", dir, fs.refused)
	}
	if err != nil {
		return DirScan{}, fmt.Errorf("build kustomization %s: %w", dir, err)
	}
	res := m.Resources()
	srcs := make([]string, len(res))
	for i, r := range res {
		srcs[i] = dir
		if o, err := r.GetOrigin(); err == nil && o != nil && o.Repo == "" {
			if p := cmp.Or(o.Path, o.ConfiguredIn); p != "" {
				srcs[i] = filepath.Join(dir, filepath.FromSlash(p))
			}
		}
	}
	if err := m.RemoveOriginAnnotations(); err != nil {
		return DirScan{}, err
	}
	var out DirScan
	for i, r := range res {
		data, err := r.AsYAML()
		if err != nil {
			return out, err
		}
		consumeRendered(&out, data, srcs[i])
	}
	return out, nil
}

func consumeRendered(out *DirScan, data []byte, source string) {
	n := len(out.Targets)
	consumeFile(out, data, source)
	for i := n; i < len(out.Targets); i++ {
		out.Targets[i].Line = 0
	}
}

type originFS struct {
	filesys.FileSystem
	root        string
	allowRemote bool
	refused     error
}

func (f *originFS) ReadFile(path string) ([]byte, error) {
	data, err := f.FileSystem.ReadFile(path)
	if err != nil || !slices.Contains(konfig.RecognizedKustomizationFileNames(), filepath.Base(path)) {
		return data, err
	}
	if !f.allowRemote {
		if ref, ok := findRemoteRef(f.FileSystem, filepath.Dir(path), data); ok {
			f.refused = cmp.Or(f.refused, errRemoteRef(path, ref))
			return nil, f.refused
		}
	}
	if filepath.Dir(path) != f.root {
		return data, nil
	}
	var kust map[string]any
	if err := yaml.Unmarshal(data, &kust); err != nil || kust == nil {
		return data, nil
	}
	meta, _ := kust["buildMetadata"].([]any)
	if slices.Contains(meta, any(types.OriginAnnotations)) {
		return data, nil
	}
	kust["buildMetadata"] = append(meta, types.OriginAnnotations)
	return yaml.Marshal(kust)
}
