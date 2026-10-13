package scanner

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/aiguard/ai-guard-k8s/pkg/checks"
	"github.com/aiguard/ai-guard-k8s/pkg/detect"
	"github.com/aiguard/ai-guard-k8s/pkg/target"
)

const clusterTimeout = 2 * time.Minute

var loadCluster = target.FromCluster

type Options struct {
	Path       string
	Cluster    bool
	Kubeconfig string
	Namespace  string
	Selector   string
}

type Result struct {
	Findings []checks.Finding
	Warnings []string
}

func Scan(ctx context.Context, o Options) (Result, error) {
	if o.Path == "" && !o.Cluster {
		return Result{}, fmt.Errorf("nothing to scan: set a path or enable the cluster scan")
	}
	if err := detect.ValidateSelector(o.Selector); err != nil {
		return Result{}, fmt.Errorf("invalid workload selector: %w", err)
	}
	var res Result
	var all []checks.Finding
	if o.Path != "" {
		ds, err := target.FromDir(o.Path)
		if err != nil {
			return res, err
		}
		res.Warnings = append(res.Warnings, ds.Warnings...)
		all = append(all, Analyze(ds, o.Selector)...)
	}
	if o.Cluster {
		cctx, cancel := context.WithTimeout(ctx, clusterTimeout)
		defer cancel()
		ds, err := loadCluster(cctx, o.Kubeconfig, o.Namespace)
		if err != nil {
			return res, fmt.Errorf("cluster scan: %w", err)
		}
		all = append(all, Analyze(ds, o.Selector)...)
	}
	res.Findings = dedupe(all)
	return res, nil
}

func Analyze(ds target.DirScan, selector string) []checks.Finding {
	ctx := checks.ScanContext{NetPols: ds.NetPols, Services: ds.Services}
	var out []checks.Finding
	for _, w := range ds.Targets {
		if !detect.IsAIWorkload(w, selector) {
			continue
		}
		out = append(out, checks.RunPodSpecChecks(w)...)
		out = append(out, checks.RunContextChecks(w, ctx)...)
	}
	return dedupe(out)
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
		return a.ID < b.ID
	})
	return out
}
