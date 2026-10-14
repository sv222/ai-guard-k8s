package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sv222/ai-guard-k8s/pkg/checks"
	"github.com/sv222/ai-guard-k8s/pkg/report"
	"github.com/sv222/ai-guard-k8s/pkg/scanner"
	selpkg "github.com/sv222/ai-guard-k8s/pkg/selector"
)

func newScanCmd(kubeconfig *string) *cobra.Command {
	var (
		path      string
		asJSON    bool
		selector  string
		namespace string
		cluster   bool
		failOn    string
		offline   bool
		lenient   bool

		enforceSel string
	)
	c := &cobra.Command{
		Use:   "scan",
		Short: "Audit AI inference workloads (manifests and/or live cluster)",
		Long: "Audit AI inference workloads.\n\n" +
			"With --path, only the manifests under that path are scanned. Add --cluster to scan the live cluster as well.\n" +
			"Without --path, the live cluster from the kubeconfig is scanned.\n\n" +
			"Files that cannot be decoded make the scan fail with exit 2 unless --lenient is set. A path with no Kubernetes object at all is also an error.\n\n" +
			"Exit codes: 0 no findings at or above --fail-on, 1 findings, 2 error.",
		RunE: func(c *cobra.Command, args []string) error {
			threshold, err := checks.ParseSeverity(failOn)
			if err != nil {
				return runtimeError(err)
			}
			c.SilenceUsage = true
			if offline {
				fmt.Fprintln(c.ErrOrStderr(), "warning: --offline is deprecated and has no effect; --path already skips the cluster")
			}
			res, err := scanner.Scan(c.Context(), scanner.Options{
				Path:       path,
				Cluster:    cluster || path == "",
				Kubeconfig: *kubeconfig,
				Namespace:  namespace,
				Selector:   selector,

				EnforceSelector: enforceSel,
			})
			if err != nil {
				for _, w := range res.Warnings {
					fmt.Fprintln(c.ErrOrStderr(), "warning:", w)
				}
				return runtimeError(err)
			}
			for _, w := range res.Warnings {
				fmt.Fprintln(c.ErrOrStderr(), "warning:", w)
			}
			if asJSON {
				err = report.PrintJSON(c.OutOrStdout(), res.Findings)
			} else {
				err = report.PrintTable(c.OutOrStdout(), res.Findings)
			}
			if err != nil {
				return runtimeError(err)
			}
			if res.Failed > 0 && !lenient {
				return runtimeError(fmt.Errorf("%d documents could not be decoded, so the scan is incomplete (fix them, or use --lenient to scan the rest)", res.Failed))
			}
			if checks.AtLeast(res.Findings, threshold) {
				return &ExitError{Code: ExitFindings}
			}
			return nil
		},
	}
	c.Flags().StringVar(&path, "path", "", "manifest directory or file to scan (skips the cluster unless --cluster is set)")
	c.Flags().BoolVar(&cluster, "cluster", false, "also scan the live cluster when --path is set")
	c.Flags().BoolVar(&asJSON, "json", false, "JSON output")
	c.Flags().StringVar(&selector, "workload-selector", "", "extra label selector marking AI workloads, for example tier=inference")
	c.Flags().StringVarP(&namespace, "namespace", "n", "", "cluster namespace (empty = all)")
	c.Flags().StringVar(&failOn, "fail-on", "low", "lowest severity that makes the exit code 1: low, medium or high")
	c.Flags().StringVar(&enforceSel, "enforce-selector", selpkg.DefaultEnforce, "label selector that ai-guard enforce uses; AI workloads whose pod template lacks it get a warning (empty = no warning)")
	c.Flags().BoolVar(&lenient, "lenient", false, "with --path, do not fail when some files cannot be decoded (they are still listed as warnings)")
	c.Flags().BoolVar(&offline, "offline", false, "deprecated no-op: --path already skips the cluster")
	_ = c.Flags().MarkHidden("offline")
	return c
}
