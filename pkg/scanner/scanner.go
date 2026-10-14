package scanner

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/sv222/ai-guard-k8s/pkg/checks"
	"github.com/sv222/ai-guard-k8s/pkg/detect"
	"github.com/sv222/ai-guard-k8s/pkg/selector"
	"github.com/sv222/ai-guard-k8s/pkg/target"
)

const clusterTimeout = 2 * time.Minute

var loadCluster = target.FromCluster

type Options struct {
	Path            string
	Cluster         bool
	Kubeconfig      string
	Namespace       string
	Selector        string
	EnforceSelector string
}

type Result struct {
	Findings []checks.Finding
	Warnings []string
	Failed   int
}

func Scan(ctx context.Context, o Options) (Result, error) {
	if o.Path == "" && !o.Cluster {
		return Result{}, fmt.Errorf("nothing to scan: set a path or enable the cluster scan")
	}
	if err := detect.ValidateSelector(o.Selector); err != nil {
		return Result{}, fmt.Errorf("invalid workload selector: %w", err)
	}
	if o.EnforceSelector != "" {
		if _, err := selector.Parse(o.EnforceSelector); err != nil {
			return Result{}, fmt.Errorf("invalid enforce selector: %w", err)
		}
	}
	var res Result
	var all []checks.Finding
	if o.Path != "" {
		ds, err := target.FromDir(o.Path)
		if err != nil {
			return res, err
		}
		res.Warnings = append(res.Warnings, ds.Warnings...)
		res.Failed += ds.Failed
		if ds.Objects == 0 {
			if ds.Failed > 0 {
				return res, fmt.Errorf("no Kubernetes object under %s could be decoded (%d documents failed)", o.Path, ds.Failed)
			}
			return res, fmt.Errorf("no Kubernetes manifests found under %s (looked for .yaml, .yml and .json files)", o.Path)
		}
		findings, warnings := AnalyzeWith(ds, o.Selector, o.EnforceSelector)
		all = append(all, findings...)
		res.Warnings = append(res.Warnings, warnings...)
	}
	if o.Cluster {
		cctx, cancel := context.WithTimeout(ctx, clusterTimeout)
		defer cancel()
		ds, err := loadCluster(cctx, o.Kubeconfig, o.Namespace)
		if err != nil {
			return res, fmt.Errorf("cluster scan: %w", err)
		}
		res.Warnings = append(res.Warnings, ds.Warnings...)
		findings, warnings := AnalyzeWith(ds, o.Selector, o.EnforceSelector)
		all = append(all, findings...)
		res.Warnings = append(res.Warnings, warnings...)
	}
	res.Findings = dedupe(all)
	res.Warnings = uniqueStrings(res.Warnings)
	return res, nil
}

func Analyze(ds target.DirScan, selector string) []checks.Finding {
	findings, _ := AnalyzeWith(ds, selector, "")
	return findings
}

func AnalyzeWith(ds target.DirScan, extraSelector, enforceSelector string) ([]checks.Finding, []string) {
	ctx := checks.ScanContext{NetPols: ds.NetPols, Services: ds.Services, Ingresses: ds.Ingresses}
	enforceLabels, _ := selector.Parse(enforceSelector)
	var out []checks.Finding
	var warnings []string
	for _, w := range ds.Targets {
		if !detect.IsAIWorkload(w, extraSelector) {
			continue
		}
		if w.IsHelmTestHook() {
			warnings = append(warnings, fmt.Sprintf("%s %s/%s skipped: it has the annotation helm.sh/hook with a test hook", w.Kind, w.Namespace, w.Name))
			continue
		}
		w.OptIn = detect.OptedIn(w, extraSelector)
		out = append(out, checks.RunPodSpecChecks(w)...)
		out = append(out, checks.RunContextChecks(w, ctx)...)
		if len(enforceLabels) > 0 && !labelsMatch(enforceLabels, w.Labels) {
			warnings = append(warnings, fmt.Sprintf("%s %s/%s is an AI workload but its pod template lacks the label %s, so the policies from `ai-guard enforce` do not select its pods",
				w.Kind, w.Namespace, w.Name, formatSelector(enforceLabels)))
		}
	}
	return dedupe(out), warnings
}

func labelsMatch(want, have map[string]string) bool {
	for k, v := range want {
		if have[k] != v {
			return false
		}
	}
	return true
}

func formatSelector(sel map[string]string) string {
	keys := make([]string, 0, len(sel))
	for k := range sel {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	s := ""
	for i, k := range keys {
		if i > 0 {
			s += ","
		}
		s += k + "=" + sel[k]
	}
	return s
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func dedupe(in []checks.Finding) []checks.Finding {
	seen := make(map[string]bool, len(in))
	out := make([]checks.Finding, 0, len(in))
	for _, f := range in {
		key := fmt.Sprintf("%s|%s|%s|%s|%s|%s", f.ID, f.Kind, f.Namespace, f.Name, f.Title, f.Evidence)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
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
	return out
}
