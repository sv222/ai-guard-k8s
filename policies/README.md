# Policy pack

Kyverno and Cilium policies for AI inference workloads. They select pods labeled `ai.infra.guard/enabled: "true"`. The Kyverno policies use `Audit` mode and skip `kube-system`, `kube-public` and `kube-node-lease`.

| File | Kind | Purpose |
|---|---|---|
| `aig-require-nonroot.yaml` | Kyverno ClusterPolicy | non-root, no privilege escalation, not privileged |
| `aig-block-host-access.yaml` | Kyverno ClusterPolicy | no hostNetwork, hostPID, hostIPC, hostPort or hostPath |
| `aig-require-resources.yaml` | Kyverno ClusterPolicy | resource requests and limits (containers and init containers) |
| `aig-cilium-egress-fqdn.yaml` | CiliumClusterwideNetworkPolicy (CiliumNetworkPolicy with `-n`) | egress only to DNS and model download hosts |

## How the pack is generated

These files are the default output of `ai-guard enforce`. A test (`TestPoliciesGolden` in `pkg/enforce`) compares the generator output with the golden files and with this directory. It fails if they differ.

Do not edit the files by hand. To regenerate them after a generator change:

    go test ./pkg/enforce -run TestPoliciesGolden -update

For other selectors, modes or hosts, run `ai-guard enforce` with the flags you need.
