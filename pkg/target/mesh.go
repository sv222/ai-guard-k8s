package target

import (
	"encoding/json"
	"slices"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	istioSecurityGroup = "security.istio.io"
	kongConfigGroup    = "configuration.konghq.com"
)

var kongAuthPlugins = []string{
	"basic-auth", "hmac-auth", "jwt", "jwt-signer", "key-auth", "key-auth-enc", "ldap-auth", "ldap-auth-advanced",
	"mtls-auth", "oauth2", "oauth2-introspection", "openid-connect", "saml", "vault-auth",
}

// MeshPolicyEntry is an Istio RequestAuthentication (with jwtRules) or an
// AuthorizationPolicy that refuses unauthenticated requests.
type MeshPolicyEntry struct {
	Namespace, Name, Kind string
	Selector              map[string]string
	Targets               []string
	JWT                   bool
}

// KongPluginEntry is a KongPlugin or KongClusterPlugin that authenticates.
type KongPluginEntry struct {
	Namespace, Name string
	Cluster         bool
}

type istioSource struct {
	Principals           []string `json:"principals"`
	RequestPrincipals    []string `json:"requestPrincipals"`
	NotPrincipals        []string `json:"notPrincipals"`
	NotRequestPrincipals []string `json:"notRequestPrincipals"`
}

type istioPolicy struct {
	metav1.ObjectMeta `json:"metadata"`
	Spec              struct {
		Selector *struct {
			MatchLabels map[string]string `json:"matchLabels"`
		} `json:"selector"`
		TargetRef  *gwRef            `json:"targetRef"`
		TargetRefs []gwRef           `json:"targetRefs"`
		Action     string            `json:"action"`
		Provider   json.RawMessage   `json:"provider"`
		JWTRules   []json.RawMessage `json:"jwtRules"`
		Rules      []struct {
			From []struct {
				Source istioSource `json:"source"`
			} `json:"from"`
			To   []json.RawMessage `json:"to"`
			When []json.RawMessage `json:"when"`
		} `json:"rules"`
	} `json:"spec"`
}

func meshPolicyEntry(raw []byte, kind string) (MeshPolicyEntry, bool, error) {
	var o istioPolicy
	if err := json.Unmarshal(raw, &o); err != nil {
		return MeshPolicyEntry{}, false, err
	}
	s := o.Spec
	e := MeshPolicyEntry{Namespace: orDefault(o.Namespace, "default"), Name: o.Name, Kind: kind}
	if s.Selector != nil {
		e.Selector = s.Selector.MatchLabels
	}
	refs := s.TargetRefs
	if s.TargetRef != nil {
		refs = append(refs, *s.TargetRef)
	}
	for _, r := range refs {
		if r.is("", gatewayGroup, "Gateway") {
			e.Targets = append(e.Targets, "Gateway/"+e.Namespace+"/"+r.Name)
		} else if r.is("", "", "Service") {
			e.Targets = append(e.Targets, "Service/"+e.Namespace+"/"+r.Name)
		}
	}
	if kind == "RequestAuthentication" {
		return e, len(s.JWTRules) > 0, nil
	}
	switch s.Action {
	case "CUSTOM":
		return e, present(s.Provider), nil
	case "DENY":
		for _, r := range s.Rules {
			if len(r.To) > 0 || len(r.When) > 0 {
				continue
			}
			for _, f := range r.From {
				if slices.Contains(f.Source.NotRequestPrincipals, "*") {
					e.JWT = true
				}
				if e.JWT || slices.Contains(f.Source.NotPrincipals, "*") {
					return e, true, nil
				}
			}
		}
		return e, false, nil
	}
	if len(s.Rules) == 0 {
		return e, false, nil
	}
	for _, r := range s.Rules {
		var ident bool
		for _, f := range r.From {
			if len(f.Source.Principals) > 0 {
				ident = true
				break
			}
			if len(f.Source.RequestPrincipals) > 0 {
				ident, e.JWT = true, true
			}
		}
		if !ident {
			return e, false, nil
		}
	}
	return e, true, nil
}

type kongPlugin struct {
	metav1.ObjectMeta `json:"metadata"`
	Plugin            string `json:"plugin"`
	Disabled          bool   `json:"disabled"`
	Config            struct {
		Anonymous string `json:"anonymous"`
	} `json:"config"`
}

func kongPluginEntry(raw []byte, cluster bool) (KongPluginEntry, bool, error) {
	var o kongPlugin
	if err := json.Unmarshal(raw, &o); err != nil {
		return KongPluginEntry{}, false, err
	}
	ok := !o.Disabled && o.Config.Anonymous == "" && slices.Contains(kongAuthPlugins, o.Plugin)
	e := KongPluginEntry{Name: o.Name, Cluster: cluster}
	if !cluster {
		e.Namespace = orDefault(o.Namespace, "default")
	}
	return e, ok, nil
}
