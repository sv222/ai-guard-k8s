package scanner

import (
	"github.com/aiguard/ai-guard-k8s/pkg/checks"
	"github.com/aiguard/ai-guard-k8s/pkg/detect"
	"github.com/aiguard/ai-guard-k8s/pkg/target"
)

// ScanDir: pass 1 indexes NetPols/Services (FromDir), pass 2 checks AI workloads.
func ScanDir(dir, selector string) ([]checks.Finding, error) {
	ds, err := target.FromDir(dir)
	if err != nil {
		return nil, err
	}
	ctx := checks.ScanContext{NetPols: ds.NetPols, Services: ds.Services}
	var out []checks.Finding
	for _, w := range ds.Targets {
		if !detect.IsAIWorkload(w, selector) {
			continue
		}
		out = append(out, checks.RunPodSpecChecks(w)...)
		out = append(out, checks.RunContextChecks(w, ctx)...)
	}
	return out, nil
}
