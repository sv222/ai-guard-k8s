package enforce

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type PolicyFile struct {
	Name, Content string
}

// Policies returns the hardening pack scoped to the label selector.
func Policies(selector string) []PolicyFile {
	sel := selectorLabel(selector)
	ky := "apiVersion: kyverno.io/v1\nkind: ClusterPolicy\n"
	return []PolicyFile{
		{"aig-require-nonroot.yaml", ky + policyHeader("aig-require-nonroot") + nonrootRule},
		{"aig-block-host-access.yaml", ky + policyHeader("aig-block-host-access") + hostAccessRule},
		{"aig-require-resources.yaml", ky + policyHeader("aig-require-resources") + resourcesRule},
		{"aig-cilium-egress-fqdn.yaml", ciliumPolicy(sel)},
	}
}

func selectorLabel(selector string) string {
	parts := strings.SplitN(selector, "=", 2)
	if len(parts) == 2 {
		return fmt.Sprintf("%s: %q", parts[0], parts[1])
	}
	return `ai.infra.guard/enabled: "true"`
}

func policyHeader(name string) string {
	return fmt.Sprintf(`metadata:
  name: %s
spec:
  validationFailureAction: Enforce
  background: true
  rules:
`, name)
}

const nonrootRule = `- name: require-nonroot
  match:
    any:
    - resources:
        kinds: [Pod]
        selector:
          matchLabels:
            ai.infra.guard/enabled: "true"
  validate:
    message: "AI inference pods must set runAsNonRoot and disallow privilege escalation"
    pattern:
      spec:
        securityContext:
          runAsNonRoot: true
        =(containers):
          - =(securityContext):
              =(allowPrivilegeEscalation): "false"
`

const hostAccessRule = `- name: block-host-access
  match:
    any:
    - resources:
        kinds: [Pod]
        selector:
          matchLabels:
            ai.infra.guard/enabled: "true"
  validate:
    message: "AI inference pods must not use hostNetwork/hostPID/hostPath"
    pattern:
      spec:
        =(hostNetwork): "false"
        =(hostPID): "false"
        =(volumes):
          - X(hostPath): "null"
`

const resourcesRule = `- name: require-resources
  match:
    any:
    - resources:
        kinds: [Pod]
        selector:
          matchLabels:
            ai.infra.guard/enabled: "true"
  validate:
    message: "AI inference containers must set requests and limits"
    pattern:
      spec:
        containers:
          - resources:
              requests:
                memory: "?*"
                cpu: "?*"
              limits:
                memory: "?*"
`

func ciliumPolicy(sel string) string {
	return fmt.Sprintf(`apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: aig-inference-egress
spec:
  endpointSelector:
    matchLabels:
      %s
  egress:
    - toEndpoints:
        - matchLabels:
            k8s:io.kubernetes.pod.namespace: kube-system
            k8s-app: kube-dns
      toPorts:
        - ports: [{ port: "53", protocol: ANY }]
          rules:
            dns:
              - matchPattern: "*"
    - toFQDNs:
        - matchName: huggingface.co
        - matchPattern: "*.huggingface.co"
        - matchName: cdn-lfs.huggingface.co
`, sel)
}

// Write dumps files to outDir.
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
