package cmd

import (
	"context"
	"strings"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/yaml"

	"github.com/aiguard/ai-guard-k8s/pkg/enforce"
)

var (
	enforceOut      string
	enforceApply    bool
	enforceSelector string
)

var enforceCmd = &cobra.Command{
	Use:   "enforce",
	Short: "Generate (and optionally apply) Kyverno + Cilium hardening policies",
	RunE: func(c *cobra.Command, args []string) error {
		files := enforce.Policies(enforceSelector)
		if !enforceApply {
			return enforce.Write(enforceOut, files)
		}
		rules := clientcmd.NewDefaultClientConfigLoadingRules()
		if kubeconfig != "" {
			rules.ExplicitPath = kubeconfig
		}
		config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			rules, &clientcmd.ConfigOverrides{}).ClientConfig()
		if err != nil {
			return err
		}
		dc, err := dynamic.NewForConfig(config)
		if err != nil {
			return err
		}
		ctx := context.TODO()
		for _, f := range files {
			var obj unstructured.Unstructured
			if err := yaml.Unmarshal([]byte(f.Content), &obj.Object); err != nil {
				return err
			}
			gvr := schema.GroupVersionResource{
				Group:    obj.GroupVersionKind().Group,
				Version:  obj.GroupVersionKind().Version,
				Resource: plural(obj.GetKind()),
			}
			_, err := dc.Resource(gvr).Apply(ctx, obj.GetName(), obj.DeepCopy(),
				metav1.ApplyOptions{FieldManager: "ai-guard", Force: true})
			if err != nil {
				return err
			}
		}
		return nil
	},
}

func plural(kind string) string {
	switch kind {
	case "ClusterPolicy":
		return "clusterpolicies"
	case "CiliumNetworkPolicy":
		return "ciliumnetworkpolicies"
	}
	return strings.ToLower(kind) + "s"
}

func init() {
	enforceCmd.Flags().StringVar(&enforceOut, "out", "./policies-out", "output directory")
	enforceCmd.Flags().BoolVar(&enforceApply, "apply", false, "server-side apply to live cluster")
	enforceCmd.Flags().StringVar(&enforceSelector, "selector", "", "label selector scoping the policies (default ai.infra.guard/enabled=true)")
	rootCmd.AddCommand(enforceCmd)
}
