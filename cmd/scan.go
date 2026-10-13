package cmd

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/aiguard/ai-guard-k8s/pkg/checks"
	"github.com/aiguard/ai-guard-k8s/pkg/detect"
	"github.com/aiguard/ai-guard-k8s/pkg/report"
	"github.com/aiguard/ai-guard-k8s/pkg/target"
)

var (
	scanPath     string
	scanJSON     bool
	scanSelector string
	kubeconfig   string
	namespace    string
	offline      bool
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Audit AI inference workloads (manifests and/or live cluster)",
	RunE: func(c *cobra.Command, args []string) error {
		var findings []checks.Finding
		var dss []target.DirScan
		if scanPath != "" {
			ds, err := target.FromDir(scanPath)
			if err != nil {
				return err
			}
			dss = append(dss, ds)
		}
		if !offline {
			ds, err := target.FromCluster(kubeconfig, namespace)
			if err != nil {
				return err
			}
			dss = append(dss, ds)
		}
		for _, ds := range dss {
			ctx := checks.ScanContext{NetPols: ds.NetPols, Services: ds.Services}
			for _, w := range ds.Targets {
				if !detect.IsAIWorkload(w, scanSelector) {
					continue
				}
				findings = append(findings, checks.RunPodSpecChecks(w)...)
				findings = append(findings, checks.RunContextChecks(w, ctx)...)
			}
		}
		if scanJSON {
			if err := report.PrintJSON(os.Stdout, findings); err != nil {
				return err
			}
		} else {
			if err := report.PrintTable(os.Stdout, findings); err != nil {
				return err
			}
		}
		if len(findings) > 0 {
			os.Exit(1)
		}
		return nil
	},
}

func init() {
	scanCmd.Flags().StringVar(&scanPath, "path", "", "manifest directory to scan")
	scanCmd.Flags().BoolVar(&scanJSON, "json", false, "JSON output")
	scanCmd.Flags().StringVar(&scanSelector, "workload-selector", "", "extra k=v,k=v selector for AI workloads")
	scanCmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "kubeconfig path (defaults to KUBECONFIG)")
	scanCmd.Flags().StringVarP(&namespace, "namespace", "n", "", "cluster namespace (empty = all)")
	scanCmd.Flags().BoolVar(&offline, "offline", false, "skip live cluster scan")
	rootCmd.AddCommand(scanCmd)
}
