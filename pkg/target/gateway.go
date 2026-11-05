package target

import (
	"context"
	"encoding/json"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	gatewayGroup      = "gateway.networking.k8s.io"
	envoyGatewayGroup = "gateway.envoyproxy.io"
)

type HTTPRouteEntry struct {
	Namespace, Name string
	Annotations     map[string]string
	Gateways        []string
	Services        []string
	Plugins         []string
	AuthFilter      bool
}

type AuthPolicyEntry struct {
	Namespace, Name string
	Targets         []string
}

type gwRef struct {
	Group     *string `json:"group"`
	Kind      *string `json:"kind"`
	Name      string  `json:"name"`
	Namespace *string `json:"namespace"`
}

func (r gwRef) is(defGroup, group, kind string) bool {
	g, k := defGroup, kind
	if r.Group != nil {
		g = *r.Group
	}
	if r.Kind != nil {
		k = *r.Kind
	}
	return g == group && k == kind
}

func (r gwRef) key(ns string) string {
	if r.Namespace != nil && *r.Namespace != "" {
		ns = *r.Namespace
	}
	return ns + "/" + r.Name
}

type gwFilter struct {
	Type         string `json:"type"`
	ExtensionRef *gwRef `json:"extensionRef"`
}

type httpRoute struct {
	metav1.ObjectMeta `json:"metadata"`
	Spec              struct {
		ParentRefs []gwRef `json:"parentRefs"`
		Rules      []struct {
			Filters     []gwFilter `json:"filters"`
			BackendRefs []struct {
				gwRef
				Filters []gwFilter `json:"filters"`
			} `json:"backendRefs"`
		} `json:"rules"`
	} `json:"spec"`
}

type securityPolicy struct {
	metav1.ObjectMeta `json:"metadata"`
	Spec              struct {
		TargetRef  *gwRef          `json:"targetRef"`
		TargetRefs []gwRef         `json:"targetRefs"`
		BasicAuth  json.RawMessage `json:"basicAuth"`
		APIKeyAuth json.RawMessage `json:"apiKeyAuth"`
		JWT        json.RawMessage `json:"jwt"`
		OIDC       json.RawMessage `json:"oidc"`
		ExtAuth    json.RawMessage `json:"extAuth"`
	} `json:"spec"`
}

func httpRouteEntry(raw []byte) (HTTPRouteEntry, error) {
	var o httpRoute
	if err := json.Unmarshal(raw, &o); err != nil {
		return HTTPRouteEntry{}, err
	}
	ns := orDefault(o.Namespace, "default")
	e := HTTPRouteEntry{Namespace: ns, Name: o.Name, Annotations: o.Annotations}
	for _, p := range o.Spec.ParentRefs {
		if p.is(gatewayGroup, gatewayGroup, "Gateway") {
			e.Gateways = append(e.Gateways, p.key(ns))
		}
	}
	seen := map[string]bool{}
	for _, r := range o.Spec.Rules {
		e.AuthFilter = e.AuthFilter || authFilter(r.Filters)
		e.Plugins = append(e.Plugins, kongRefs(r.Filters)...)
		for _, b := range r.BackendRefs {
			e.AuthFilter = e.AuthFilter || authFilter(b.Filters)
			e.Plugins = append(e.Plugins, kongRefs(b.Filters)...)
			if k := b.key(ns); b.is("", "", "Service") && !seen[k] {
				seen[k] = true
				e.Services = append(e.Services, k)
			}
		}
	}
	return e, nil
}

func kongRefs(fs []gwFilter) []string {
	var out []string
	for _, f := range fs {
		if f.Type == "ExtensionRef" && f.ExtensionRef != nil && f.ExtensionRef.is("", kongConfigGroup, "KongPlugin") {
			out = append(out, f.ExtensionRef.Name)
		}
	}
	return out
}

func authFilter(fs []gwFilter) bool {
	for _, f := range fs {
		if f.Type != "ExtensionRef" || f.ExtensionRef == nil {
			continue
		}
		k := ""
		if f.ExtensionRef.Kind != nil {
			k = *f.ExtensionRef.Kind
		}
		if s := strings.ToLower(k + "/" + f.ExtensionRef.Name); strings.Contains(s, "auth") || strings.Contains(s, "jwt") || strings.Contains(s, "oidc") {
			return true
		}
	}
	return false
}

func authPolicyEntry(raw []byte) (AuthPolicyEntry, bool, error) {
	var o securityPolicy
	if err := json.Unmarshal(raw, &o); err != nil {
		return AuthPolicyEntry{}, false, err
	}
	s := o.Spec
	if !present(s.BasicAuth) && !present(s.APIKeyAuth) && !present(s.JWT) && !present(s.OIDC) && !present(s.ExtAuth) {
		return AuthPolicyEntry{}, false, nil
	}
	ns := orDefault(o.Namespace, "default")
	e := AuthPolicyEntry{Namespace: ns, Name: o.Name}
	refs := s.TargetRefs
	if s.TargetRef != nil {
		refs = append(refs, *s.TargetRef)
	}
	for _, r := range refs {
		for _, kind := range []string{"Gateway", "HTTPRoute"} {
			if r.is("", gatewayGroup, kind) {
				e.Targets = append(e.Targets, kind+"/"+ns+"/"+r.Name)
			}
		}
	}
	return e, true, nil
}

func present(m json.RawMessage) bool {
	return len(m) > 0 && string(m) != "null"
}

func listGatewayObjects(ctx context.Context, cs kubernetes.Interface, namespace string, out *DirScan) error {
	rc := cs.Discovery().RESTClient()
	if rc == nil {
		return nil
	}
	list := func(namespace, group, version, resource string, each func(json.RawMessage) error) error {
		path := "/apis/" + group + "/" + version
		if namespace != "" {
			path += "/namespaces/" + namespace
		}
		data, err := rc.Get().AbsPath(path, resource).DoRaw(ctx)
		switch {
		case apierrors.IsNotFound(err):
			return nil
		case apierrors.IsForbidden(err):
			out.Warnings = append(out.Warnings, "cannot list "+resource+"."+group+": "+err.Error())
			return nil
		case err != nil:
			return err
		}
		var l struct {
			Items []json.RawMessage `json:"items"`
		}
		if err := json.Unmarshal(data, &l); err != nil {
			return err
		}
		for _, item := range l.Items {
			if err := each(item); err != nil {
				return err
			}
		}
		return nil
	}
	err := list(namespace, gatewayGroup, "v1", "httproutes", func(raw json.RawMessage) error {
		e, err := httpRouteEntry(raw)
		if err == nil {
			out.HTTPRoutes = append(out.HTTPRoutes, e)
		}
		return err
	})
	if err != nil {
		return err
	}
	err = list(namespace, envoyGatewayGroup, "v1alpha1", "securitypolicies", func(raw json.RawMessage) error {
		e, ok, err := authPolicyEntry(raw)
		if ok {
			out.AuthPolicies = append(out.AuthPolicies, e)
		}
		return err
	})
	if err != nil {
		return err
	}
	for _, rk := range [][2]string{{"authorizationpolicies", "AuthorizationPolicy"}, {"requestauthentications", "RequestAuthentication"}} {
		resource, kind := rk[0], rk[1]
		err = list(namespace, istioSecurityGroup, "v1", resource, func(raw json.RawMessage) error {
			e, ok, err := meshPolicyEntry(raw, kind)
			if ok {
				out.MeshPolicies = append(out.MeshPolicies, e)
			}
			return err
		})
		if err != nil {
			return err
		}
	}
	err = list(namespace, kongConfigGroup, "v1", "kongplugins", func(raw json.RawMessage) error {
		e, ok, err := kongPluginEntry(raw, false)
		if ok {
			out.KongPlugins = append(out.KongPlugins, e)
		}
		return err
	})
	if err != nil {
		return err
	}
	return list("", kongConfigGroup, "v1", "kongclusterplugins", func(raw json.RawMessage) error {
		e, ok, err := kongPluginEntry(raw, true)
		if ok {
			out.KongPlugins = append(out.KongPlugins, e)
		}
		return err
	})
}
