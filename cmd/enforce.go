package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sv222/ai-guard-k8s/pkg/enforce"
	"github.com/sv222/ai-guard-k8s/pkg/selector"
)

const applyTimeout = 60 * time.Second

var (
	connectCluster = enforce.Connect
	isTerminal     = func(r io.Reader) bool {
		f, ok := r.(*os.File)
		if !ok {
			return false
		}
		info, err := f.Stat()
		return err == nil && info.Mode()&os.ModeCharDevice != 0
	}
)

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
		kubeCtx    string
		yes        bool
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
				return runtimeError(runApply(c, *kubeconfig, kubeCtx, files, namespace, yes))
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
	c.Flags().StringVar(&kubeCtx, "context", "", "kubeconfig context to apply to (default: the current context)")
	c.Flags().BoolVar(&yes, "yes", false, "with --apply, do not ask for confirmation (required when stdin is not a terminal)")
	c.Flags().StringVar(&sel, "selector", selector.DefaultEnforce, "k=v[,k=v] label selector scoping the Kyverno and Cilium policies")
	c.Flags().StringVar(&mode, "mode", enforce.ModeAudit, "Kyverno validationFailureAction: audit or enforce")
	c.Flags().StringSliceVar(&fqdns, "allow-fqdn", nil, "extra host allowed for egress by the Cilium policy (repeatable)")
	c.Flags().BoolVar(&skipCilium, "skip-cilium", false, "do not generate or apply the Cilium policy (for clusters without Cilium)")
	c.Flags().StringVarP(&namespace, "namespace", "n", "", "namespace: make the Cilium policy a namespaced CiliumNetworkPolicy there (default: a cluster-wide CiliumClusterwideNetworkPolicy)")
	return c
}

func runApply(c *cobra.Command, kubeconfig, kubeCtx string, files []enforce.PolicyFile, namespace string, yes bool) error {
	cluster, err := connectCluster(kubeconfig, kubeCtx)
	if err != nil {
		return err
	}
	stdout := c.OutOrStdout()
	fmt.Fprintf(stdout, "cluster: context %q, server %s\n", cluster.Context, cluster.Server)
	if err := enforce.Check(cluster.Mapper, files, namespace); err != nil {
		return err
	}
	if err := enforce.Plan(files, namespace, stdout); err != nil {
		return err
	}
	if !yes {
		if !isTerminal(c.InOrStdin()) {
			return errors.New("refusing to apply without confirmation: stdin is not a terminal, pass --yes to apply")
		}
		fmt.Fprintf(stdout, "Apply %d policies to context %q? [y/N] ", len(files), cluster.Context)
		line, _ := bufio.NewReader(c.InOrStdin()).ReadString('\n')
		if answer := strings.ToLower(strings.TrimSpace(line)); answer != "y" && answer != "yes" {
			return errors.New("aborted, nothing was applied")
		}
	}
	ctx, cancel := context.WithTimeout(c.Context(), applyTimeout)
	defer cancel()
	return enforce.Apply(ctx, cluster.Client, cluster.Mapper, files, namespace, stdout)
}
