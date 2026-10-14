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

type Cluster struct {
	Context string
	Server  string
	Client  dynamic.Interface
	Mapper  meta.RESTMapper
}

func Connect(kubeconfig, kubeContext string) (Cluster, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		rules.ExplicitPath = kubeconfig
	}
	cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		rules, &clientcmd.ConfigOverrides{CurrentContext: kubeContext})
	config, err := cc.ClientConfig()
	if err != nil {
		return Cluster{}, err
	}
	name := kubeContext
	if name == "" {
		if raw, err := cc.RawConfig(); err == nil {
			name = raw.CurrentContext
		}
	}
	dc, err := dynamic.NewForConfig(config)
	if err != nil {
		return Cluster{}, err
	}
	disc, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		return Cluster{}, err
	}
	return Cluster{
		Context: name,
		Server:  config.Host,
		Client:  dc,
		Mapper:  restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(disc)),
	}, nil
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

type resolved struct {
	file      PolicyFile
	obj       *unstructured.Unstructured
	mapping   *meta.RESTMapping
	namespace string
}

func resolve(mapper meta.RESTMapper, files []PolicyFile, defaultNamespace string) ([]resolved, error) {
	out := make([]resolved, 0, len(files))
	for _, f := range files {
		obj, err := decode(f)
		if err != nil {
			return nil, err
		}
		gvk := obj.GroupVersionKind()
		mapping, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
		if err != nil {
			if meta.IsNoMatchError(err) {
				return nil, fmt.Errorf("%s: kind %s is not served by the cluster (is the Kyverno/Cilium CRD installed? use --skip-cilium to leave out the Cilium policy): %w", f.Name, gvk.Kind, err)
			}
			return nil, fmt.Errorf("%s: %w", f.Name, err)
		}
		r := resolved{file: f, obj: obj, mapping: mapping}
		if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
			r.namespace = obj.GetNamespace()
			if r.namespace == "" {
				r.namespace = defaultNamespace
			}
			if r.namespace == "" {
				r.namespace = metav1.NamespaceDefault
			}
			obj.SetNamespace(r.namespace)
		}
		out = append(out, r)
	}
	return out, nil
}

func Check(mapper meta.RESTMapper, files []PolicyFile, defaultNamespace string) error {
	_, err := resolve(mapper, files, defaultNamespace)
	return err
}

func Apply(ctx context.Context, client dynamic.Interface, mapper meta.RESTMapper, files []PolicyFile, defaultNamespace string, out io.Writer) error {
	items, err := resolve(mapper, files, defaultNamespace)
	if err != nil {
		return err
	}
	for _, r := range items {
		var ri dynamic.ResourceInterface
		if r.namespace != "" {
			ri = client.Resource(r.mapping.Resource).Namespace(r.namespace)
		} else {
			ri = client.Resource(r.mapping.Resource)
		}
		if _, err := ri.Apply(ctx, r.obj.GetName(), r.obj.DeepCopy(),
			metav1.ApplyOptions{FieldManager: FieldManager, Force: true}); err != nil {
			return fmt.Errorf("%s: %w", r.file.Name, err)
		}
		fmt.Fprintf(out, "applied %s %s\n", r.obj.GetKind(), r.obj.GetName())
	}
	return nil
}
