package enforce

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sv222/ai-guard-k8s/pkg/selector"
	"sigs.k8s.io/yaml"
)

const (
	ModeAudit   = "audit"
	ModeEnforce = "enforce"
)

var excludedNamespaces = []string{"kube-system", "kube-public", "kube-node-lease"}

var defaultFQDNs = []string{
	"huggingface.co",
	"*.huggingface.co",
	"cdn-lfs.huggingface.co",
	"cdn-lfs.hf.co",
	"*.hf.co",
	"cas-bridge.xethub.hf.co",
	"cas-server.xethub.hf.co",
	"transfer.xethub.hf.co",
	"us.aws.cdn.hf.co",
	"us.gcp.cdn.hf.co",
	"cas-server.xethub-eu.hf.co",
	"transfer.xethub-eu.hf.co",
}

var fqdnPattern = regexp.MustCompile(`^[a-z0-9*]([a-z0-9*.-]*[a-z0-9*])?$`)

type Options struct {
	Selector   string
	Mode       string
	AllowFQDNs []string
	Namespace  string
	SkipCilium bool
}

type PolicyFile struct {
	Name, Content string
}

type obj = map[string]interface{}

func DefaultFQDNs() []string {
	return append([]string{}, defaultFQDNs...)
}

func Policies(o Options) ([]PolicyFile, error) {
	selStr := o.Selector
	if strings.TrimSpace(selStr) == "" {
		selStr = selector.DefaultEnforce
	}
	sel, err := selector.Parse(selStr)
	if err != nil {
		return nil, fmt.Errorf("invalid --selector: %w", err)
	}
	if len(sel) == 0 {
		return nil, fmt.Errorf("invalid --selector: no label terms")
	}
	action, err := failureAction(o.Mode)
	if err != nil {
		return nil, err
	}
	fqdns, err := mergeFQDNs(o.AllowFQDNs)
	if err != nil {
		return nil, err
	}

	specs := []struct {
		name  string
		rules []obj
	}{
		{"aig-require-nonroot", []obj{
			rule("require-nonroot", sel, nonRootRule()),
			rule("disallow-privilege-escalation", sel, privilegeEscalationRule()),
			rule("disallow-privileged", sel, privilegedRule()),
		}},
		{"aig-block-host-access", []obj{rule("block-host-access", sel, hostAccessRule())}},
		{"aig-require-resources", []obj{rule("require-resources", sel, resourcesRule())}},
	}

	var files []PolicyFile
	for _, s := range specs {
		doc := obj{
			"apiVersion": "kyverno.io/v1",
			"kind":       "ClusterPolicy",
			"metadata":   obj{"name": s.name},
			"spec": obj{
				"validationFailureAction": action,
				"background":              true,
				"rules":                   s.rules,
			},
		}
		content, err := render(doc)
		if err != nil {
			return nil, err
		}
		files = append(files, PolicyFile{Name: s.name + ".yaml", Content: content})
	}

	if o.SkipCilium {
		return files, nil
	}
	cilium, err := render(ciliumPolicy(sel, fqdns, o.Namespace))
	if err != nil {
		return nil, err
	}
	files = append(files, PolicyFile{Name: "aig-cilium-egress-fqdn.yaml", Content: cilium})
	return files, nil
}

func failureAction(mode string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", ModeAudit:
		return "Audit", nil
	case ModeEnforce:
		return "Enforce", nil
	}
	return "", fmt.Errorf("invalid --mode %q: want audit or enforce", mode)
}

func mergeFQDNs(extra []string) ([]string, error) {
	out := DefaultFQDNs()
	seen := map[string]bool{}
	for _, h := range out {
		seen[h] = true
	}
	for _, raw := range extra {
		h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
		if h == "" || h == "*" || !strings.Contains(h, ".") || !fqdnPattern.MatchString(h) {
			return nil, fmt.Errorf("invalid --allow-fqdn %q: want a host name such as models.example.com or *.example.com", raw)
		}
		if seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	return out, nil
}

func rule(name string, sel map[string]string, validate obj) obj {
	return obj{
		"name": name,
		"match": obj{"any": []obj{{"resources": obj{
			"kinds":    []string{"Pod"},
			"selector": obj{"matchLabels": sel},
		}}}},
		"exclude": obj{"any": []obj{{"resources": obj{
			"namespaces": excludedNamespaces,
		}}}},
		"validate": validate,
	}
}

func nonRootRule() obj {
	nonRoot := obj{"runAsNonRoot": true}
	optional := obj{"=(securityContext)": obj{"=(runAsNonRoot)": true}}
	return obj{
		"message": "AI inference pods must run as non-root (runAsNonRoot: true at pod level or on every container)",
		"anyPattern": []obj{
			{"spec": obj{
				"securityContext":   nonRoot,
				"=(initContainers)": []obj{optional},
				"=(containers)":     []obj{optional},
			}},
			{"spec": obj{
				"=(initContainers)": []obj{{"securityContext": nonRoot}},
				"containers":        []obj{{"securityContext": nonRoot}},
			}},
		},
	}
}

func privilegeEscalationRule() obj {
	sc := obj{"securityContext": obj{"allowPrivilegeEscalation": "false"}}
	return obj{
		"message": "AI inference containers must set allowPrivilegeEscalation: false",
		"pattern": obj{"spec": obj{
			"=(initContainers)": []obj{sc},
			"containers":        []obj{sc},
		}},
	}
}

func privilegedRule() obj {
	sc := obj{"=(securityContext)": obj{"=(privileged)": "false"}}
	return obj{
		"message": "AI inference containers must not be privileged",
		"pattern": obj{"spec": obj{
			"=(initContainers)": []obj{sc},
			"=(containers)":     []obj{sc},
		}},
	}
}

func hostAccessRule() obj {
	return obj{
		"message": "AI inference pods must not use hostNetwork, hostPID or hostPath volumes",
		"pattern": obj{"spec": obj{
			"=(hostNetwork)": "false",
			"=(hostPID)":     "false",
			"=(volumes)":     []obj{{"X(hostPath)": "null"}},
		}},
	}
}

func resourcesRule() obj {
	return obj{
		"message": "AI inference containers must set requests and limits",
		"pattern": obj{"spec": obj{
			"containers": []obj{{"resources": obj{
				"requests": obj{"memory": "?*", "cpu": "?*"},
				"limits":   obj{"memory": "?*"},
			}}},
		}},
	}
}

func ciliumPolicy(sel map[string]string, fqdns []string, namespace string) obj {
	var names []obj
	for _, h := range fqdns {
		if strings.Contains(h, "*") {
			names = append(names, obj{"matchPattern": h})
		} else {
			names = append(names, obj{"matchName": h})
		}
	}
	meta := obj{"name": "aig-inference-egress"}
	if namespace != "" {
		meta["namespace"] = namespace
	}
	return obj{
		"apiVersion": "cilium.io/v2",
		"kind":       "CiliumNetworkPolicy",
		"metadata":   meta,
		"spec": obj{
			"endpointSelector": obj{"matchLabels": sel},
			"egress": []obj{
				{
					"toEndpoints": []obj{{"matchLabels": obj{
						"k8s:io.kubernetes.pod.namespace": "kube-system",
						"k8s-app":                         "kube-dns",
					}}},
					"toPorts": []obj{{
						"ports": []obj{{"port": "53", "protocol": "ANY"}},
						"rules": obj{"dns": []obj{{"matchPattern": "*"}}},
					}},
				},
				{"toFQDNs": names},
			},
		},
	}
}

func render(doc obj) (string, error) {
	b, err := yaml.Marshal(doc)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func Write(outDir string, files []PolicyFile) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(outDir, f.Name), []byte(f.Content), 0o644); err != nil {
			return err
		}
	}
	return nil
}
