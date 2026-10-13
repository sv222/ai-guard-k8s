# ai-guard-k8s

`kube-bench + Pod Security Standards for AI inference` — audits and hardens
Kubernetes workloads running vLLM, Ollama, Triton, TGI, Ray at the
**infrastructure layer** (auth, debug ports, host namespaces, seccomp, network
isolation, unsafe model formats). Not a prompt scanner.

## Quickstart

    ai-guard scan --path manifests/          # offline manifests
    ai-guard scan                            # live cluster (kubeconfig)
    ai-guard scan --json                     # CI-friendly, exit 1 on findings
    ai-guard enforce --out policies/         # generate Kyverno + Cilium policies

Mark any renamed inference workload with the label `ai.infra.guard/enabled: "true"`.

## Checks (v1)

AIG-001 missing auth · AIG-002 debug endpoints · AIG-003 host net/pid ·
AIG-004 hostPath · AIG-005 root/priv-esc · AIG-006 no seccomp ·
AIG-007 no resources · AIG-008 unsafe model execution (--trust-remote-code,
pickle formats, unverified object storage) · AIG-009 no NetworkPolicy ·
AIG-010 exposed Service.

Apache-2.0. Provided as-is; risk acceptance remains with your organization.

## Enforce (policy pack)

    ai-guard enforce --out policies/                     # write Kyverno + Cilium YAML
    ai-guard enforce --apply                             # server-side apply to the live cluster
    ai-guard enforce --selector team=llm --out policies/ # scope to another label selector

The generated pack is mirrored in [`policies/`](policies/) — ready for Artifact Hub
or upstreaming to `kyverno/policies`.
