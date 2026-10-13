package enforce

import (
	"context"
	"fmt"
	"io"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/restmapper"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/yaml"
)

const FieldManager = "ai-guard"

func Clients(kubeconfig string) (dynamic.Interface, meta.RESTMapper, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		rules.ExplicitPath = kubeconfig
	}
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		rules, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return nil, nil, err
	}
	dc, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, nil, err
	}
	disc, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		return nil, nil, err
	}
	return dc, restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(disc)), nil
}

func decode(f PolicyFile) (*unstructured.Unstructured, error) {
	obj := &unstructured.Unstructured{}
	if err := yaml.Unmarshal([]byte(f.Content), &obj.Object); err != nil {
		return nil, fmt.Errorf("%s: %w", f.Name, err)
	}
	return obj, nil
}

func Plan(files []PolicyFile, defaultNamespace string, out io.Writer) error {
	for _, f := range files {
		obj, err := decode(f)
		if err != nil {
			return err
		}
		ns := obj.GetNamespace()
		if obj.GetKind() == "CiliumNetworkPolicy" && ns == "" {
			ns = defaultNamespace
			if ns == "" {
				ns = metav1.NamespaceDefault
			}
		}
		if ns != "" {
			fmt.Fprintf(out, "would apply %s %s in namespace %s (%s)\n", obj.GetKind(), obj.GetName(), ns, f.Name)
		} else {
			fmt.Fprintf(out, "would apply %s %s (%s)\n", obj.GetKind(), obj.GetName(), f.Name)
		}
	}
	return nil
}

func Apply(ctx context.Context, client dynamic.Interface, mapper meta.RESTMapper, files []PolicyFile, defaultNamespace string, out io.Writer) error {
	for _, f := range files {
		obj, err := decode(f)
		if err != nil {
			return err
		}
		gvk := obj.GroupVersionKind()
		mapping, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
		if err != nil {
			if meta.IsNoMatchError(err) {
				return fmt.Errorf("%s: kind %s is not served by the cluster (is the Kyverno/Cilium CRD installed?): %w", f.Name, gvk.Kind, err)
			}
			return fmt.Errorf("%s: %w", f.Name, err)
		}
		var ri dynamic.ResourceInterface
		if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
			ns := obj.GetNamespace()
			if ns == "" {
				ns = defaultNamespace
			}
			if ns == "" {
				ns = metav1.NamespaceDefault
			}
			obj.SetNamespace(ns)
			ri = client.Resource(mapping.Resource).Namespace(ns)
		} else {
			ri = client.Resource(mapping.Resource)
		}
		if _, err := ri.Apply(ctx, obj.GetName(), obj.DeepCopy(),
			metav1.ApplyOptions{FieldManager: FieldManager, Force: true}); err != nil {
			return fmt.Errorf("%s: %w", f.Name, err)
		}
		fmt.Fprintf(out, "applied %s %s\n", obj.GetKind(), obj.GetName())
	}
	return nil
}
