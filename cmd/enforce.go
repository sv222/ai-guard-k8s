package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/sv222/ai-guard-k8s/pkg/enforce"
	"github.com/sv222/ai-guard-k8s/pkg/selector"
)

const applyTimeout = 60 * time.Second

func newEnforceCmd(kubeconfig *string) *cobra.Command {
	var (
		out        string
		apply      bool
		dryRun     bool
		sel        string
		mode       string
		fqdns      []string
		namespace  string
		skipCilium bool
	)
	c := &cobra.Command{
		Use:   "enforce",
		Short: "Generate (and optionally apply) Kyverno + Cilium hardening policies",
		RunE: func(c *cobra.Command, args []string) error {
			files, err := enforce.Policies(enforce.Options{
				Selector:   sel,
				Mode:       mode,
				AllowFQDNs: fqdns,
				Namespace:  namespace,
				SkipCilium: skipCilium,
			})
			if err != nil {
				return runtimeError(err)
			}
			c.SilenceUsage = true
			switch {
			case dryRun:
				return runtimeError(enforce.Plan(files, namespace, c.OutOrStdout()))
			case apply:
				client, mapper, err := enforce.Clients(*kubeconfig)
				if err != nil {
					return runtimeError(err)
				}
				ctx, cancel := context.WithTimeout(c.Context(), applyTimeout)
				defer cancel()
				return runtimeError(enforce.Apply(ctx, client, mapper, files, namespace, c.OutOrStdout()))
			}
			if err := enforce.Write(out, files); err != nil {
				return runtimeError(err)
			}
			fmt.Fprintf(c.OutOrStdout(), "wrote %d policies to %s\n", len(files), out)
			return nil
		},
	}
	c.Flags().StringVar(&out, "out", "./policies-out", "output directory")
	c.Flags().BoolVar(&apply, "apply", false, "server-side apply to the live cluster instead of writing files")
	c.Flags().BoolVar(&dryRun, "dry-run", false, "print what --apply would apply and change nothing")
	c.Flags().StringVar(&sel, "selector", selector.DefaultEnforce, "k=v[,k=v] label selector scoping the Kyverno and Cilium policies")
	c.Flags().StringVar(&mode, "mode", enforce.ModeAudit, "Kyverno validationFailureAction: audit or enforce")
	c.Flags().StringSliceVar(&fqdns, "allow-fqdn", nil, "extra host allowed for egress by the Cilium policy (repeatable)")
	c.Flags().BoolVar(&skipCilium, "skip-cilium", false, "do not generate or apply the CiliumNetworkPolicy (for clusters without Cilium)")
	c.Flags().StringVarP(&namespace, "namespace", "n", "", "namespace: make the Cilium policy a namespaced CiliumNetworkPolicy there (default: a cluster-wide CiliumClusterwideNetworkPolicy)")
	return c
}
