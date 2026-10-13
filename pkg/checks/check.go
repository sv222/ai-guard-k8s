package checks

import (
	"fmt"
	"strings"

	"github.com/aiguard/ai-guard-k8s/pkg/target"
)

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

func (f Finding) on(w target.WorkloadTarget) Finding {
	f.Kind, f.Namespace, f.Name = w.Kind, w.Namespace, w.Name
	return f
}

func SeverityRank(s string) int {
	switch strings.ToLower(s) {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	}
	return 0
}

func ParseSeverity(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "low":
		return "Low", nil
	case "medium":
		return "Medium", nil
	case "high":
		return "High", nil
	}
	return "", fmt.Errorf("invalid severity %q: want low, medium or high", s)
}

func AtLeast(findings []Finding, threshold string) bool {
	need := SeverityRank(threshold)
	for _, f := range findings {
		if SeverityRank(f.Severity) >= need {
			return true
		}
	}
	return false
}
