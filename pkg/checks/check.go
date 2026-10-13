package checks

import "github.com/aiguard/ai-guard-k8s/pkg/target"

type Finding struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Severity  string `json:"severity"`
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Evidence  string `json:"evidence"`
	Hint      string `json:"hint"`
}

type CheckFunc func(w target.WorkloadTarget) []Finding
