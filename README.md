# ai-guard-k8s

Audit and harden Kubernetes AI inference workloads (vLLM, Ollama). Also covers Triton, TGI and Ray Serve.

[![ci](https://github.com/sv222/ai-guard-k8s/actions/workflows/ci.yml/badge.svg)](https://github.com/sv222/ai-guard-k8s/actions/workflows/ci.yml)
[![license](https://img.shields.io/github/license/sv222/ai-guard-k8s)](LICENSE)

`ai-guard` is a small Go CLI. It works like kube-bench and Pod Security Standards, but for AI inference workloads. It scans Kubernetes manifests or a live cluster for unsafe settings. It also generates Kyverno and Cilium policies to harden your workloads. It gives JSON output and exit codes for CI.

Supported platforms: Linux, macOS and Windows, on amd64 and arm64.

## Kubernetes security scanner for vLLM and Ollama

The tool looks at the infrastructure layer of your inference workloads:

- missing authentication on the engine or gateway
- debug flags and debug environment variables
- host namespaces and host paths
- root user, privileged containers, privilege escalation
- seccomp profile and resource limits
- unsafe model formats and model sources
- missing NetworkPolicy isolation
- inference Services exposed by `LoadBalancer` or `NodePort`

### What it does not do

It is not a prompt scanner or a model scanner. It does not test prompt injection, jailbreaks or model weights. It reads Kubernetes objects only.

## Install

From a release: download the archive for your system from the [Releases page](https://github.com/sv222/ai-guard-k8s/releases). Files are named `ai-guard_<version>_<os>_<arch>.tar.gz`, or `.zip` on Windows. Unpack it and put `ai-guard` in your `PATH`. Check the download with `checksums.txt`.

With Go:

    go install github.com/sv222/ai-guard-k8s@latest

Build from source:

    git clone https://github.com/sv222/ai-guard-k8s.git
    cd ai-guard-k8s
    make build
    ./ai-guard --version

## Quickstart: scan manifests

    ai-guard scan --path manifests/

This reads `.yaml`, `.yml` and `.json` files. Multi-document files and `kind: List` also work. It does not contact the cluster.

## Quickstart: scan a live cluster

    ai-guard scan
    ai-guard scan -n llm
    ai-guard scan --kubeconfig ~/.kube/config

Without `--path`, the tool scans the cluster from your kubeconfig (or `KUBECONFIG`). To scan manifests and the cluster together:

    ai-guard scan --path manifests/ --cluster

## JSON output and CI usage

    ai-guard scan --path manifests/ --json
    ai-guard scan --path manifests/ --fail-on high

| Exit code | Meaning |
|---|---|
| 0 | no finding at or above `--fail-on` |
| 1 | at least one finding at or above `--fail-on` |
| 2 | error: bad flag, unreadable path, cluster unreachable |

`--fail-on` accepts `low`, `medium` or `high`. The default is `low`, so any finding gives exit code 1.

## GitHub Actions example

```yaml
name: ai-guard
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: stable
      - run: go install github.com/sv222/ai-guard-k8s@latest
      - run: ai-guard scan --path manifests/ --fail-on high
```

## How workloads are found

A workload is treated as AI inference if one of these is true:

- the workload name or an image contains `vllm`, `ollama`, `tritonserver`, `text-generation-inference`, `tgi` or `ray-serve`
- the workload or its pod template has the label or annotation `ai.infra.guard/enabled: "true"`
- its labels match `--workload-selector`, for example `--workload-selector tier=inference`

If an authenticating gateway sits in front of a workload, set the label or annotation `ai.infra.guard/gateway-auth: "true"` on the workload or its pod template. AIG-001 and AIG-010 then stay quiet.

## Checks

| ID | What it finds | Severity | How it is detected | Fix or silence |
|---|---|---|---|---|
| AIG-001 | No auth on the inference engine | High for vLLM, Medium for other engines | No `--api-key` argument and none of `VLLM_API_KEY`, `API_KEY`, `OPENAI_API_KEY` in env | Add `--api-key` or an API key env var. Or set `ai.infra.guard/gateway-auth: "true"` if a gateway authenticates |
| AIG-002 | Debug or insecure endpoint | Medium | `--debug`, `--allow-http`, or `OLLAMA_DEBUG` set to `true` or `1` | Remove the flag or variable |
| AIG-003 | `hostNetwork` or `hostPID` | High | `spec.hostNetwork` or `spec.hostPID` is true | Set both to false |
| AIG-004 | `hostPath` volume | High | Any volume of type `hostPath` | Use a PVC or `emptyDir` |
| AIG-005 | Root, privileged, or privilege escalation | High | Effective `runAsUser: 0`, effective `runAsNonRoot` not `true` (a non-zero `runAsUser` alone is not enough, as in PSS Restricted), `privileged: true`, `allowPrivilegeEscalation` unset or true | Set `runAsNonRoot: true`, `privileged: false`, `allowPrivilegeEscalation: false` |
| AIG-006 | Seccomp profile missing or `Unconfined` | Medium | Effective `seccompProfile` (container, then pod) is unset or `Unconfined` | Set `seccompProfile.type: RuntimeDefault` |
| AIG-007 | Missing resource requests or limits | Low | A container lacks `requests.memory`, `requests.cpu` or `limits.memory` (same fields the Kyverno policy requires) | Set `requests.memory`, `requests.cpu` and `limits.memory` |
| AIG-008 | Unsafe model execution | High, Medium for `s3://` and `gs://` | `--trust-remote-code`; model args or env values ending in `.bin`, `.pt`, `.pth`, `.pkl`, `.pickle`, `.ckpt`; `s3://` or `gs://` sources | Remove the flag, use SafeTensors, pin model provenance |
| AIG-009 | No NetworkPolicy isolation | Medium | No NetworkPolicy in the namespace selects the pod and restricts traffic, or the matching policy allows all | Add default-deny plus an allowlist. See `ai-guard enforce` |
| AIG-010 | Inference exposed by `LoadBalancer` or `NodePort` | High | A Service of that type selects the workload and no auth evidence exists | Add engine auth, annotate `ai.infra.guard/gateway-auth: "true"`, or use an internal Service |

AIG-005, AIG-006 and AIG-007 also cover init containers. Container settings override pod settings.

There is no inline ignore comment. To silence a check, fix the cause. For AIG-001 and AIG-010 you can also use the gateway annotation.

## Sample output

This is real output of `ai-guard scan --path testdata/manifests/offending`. It is shortened to a few rows. The full scan prints 22 findings and exits with code 1.

```
ID       SEVERITY  WORKLOAD                   TITLE                                                  EVIDENCE
AIG-001  Medium    Deployment/bad/ollama-bad  Inference engine without engine/gateway auth evidence  container ollama (ollama/ollama) has no auth env (API_KEY/OPENAI_API_KEY) and engine has no native auth
AIG-002  Medium    Deployment/bad/ollama-bad  OLLAMA_DEBUG enabled                                   container ollama: env OLLAMA_DEBUG=true
AIG-001  High      Deployment/bad/vllm-bad    vLLM without API key auth                              container server: no --api-key arg and no VLLM_API_KEY/API_KEY env
AIG-003  High      Deployment/bad/vllm-bad    hostNetwork enabled                                    spec.hostNetwork: true
AIG-004  High      Deployment/bad/vllm-bad    hostPath volume                                        volume models mounts host path /srv/models
AIG-008  High      Deployment/bad/vllm-bad    non-SafeTensors model reference                        container server: arg "--model=/models/llama.bin" references .bin (pickle-deserialization risk)
AIG-010  High      Deployment/bad/vllm-bad    inference exposed via NodePort                         Service vllm-bad (NodePort) selects this workload and no auth evidence was found
```

A clean manifest prints `No findings.` and exits with code 0.

## Enforce: generate Kyverno and Cilium policies

    ai-guard enforce --out policies-out/

This writes four files:

- `aig-require-nonroot.yaml`, `aig-block-host-access.yaml`, `aig-require-resources.yaml`: Kyverno `ClusterPolicy`
- `aig-cilium-egress-fqdn.yaml`: `CiliumNetworkPolicy` that allows DNS and model download hosts only

The policies select pods with the label `ai.infra.guard/enabled: "true"`. Change this with `--selector team=llm,tier=gpu`.

Kyverno policies use `validationFailureAction: Audit` by default. They report violations but do not block pods. They skip `kube-system`, `kube-public` and `kube-node-lease`. To block violations, generate the policies in enforce mode:

    ai-guard enforce --mode enforce

The Cilium policy allows Hugging Face hosts by default: `huggingface.co`, `*.huggingface.co`, `cdn-lfs.huggingface.co`, `cdn-lfs.hf.co`, `*.hf.co` and the two-label storage hosts (`us.aws.cdn.hf.co`, `us.gcp.cdn.hf.co` and the `xethub` and `xethub-eu` hosts), because a Cilium `*` matches one label only. Add more hosts with a repeatable flag:

    ai-guard enforce --allow-fqdn models.example.com --allow-fqdn '*.cdn.example.org'

Apply to a cluster:

    ai-guard enforce --apply --dry-run     # print what would be applied, change nothing
    ai-guard enforce --apply -n llm        # server-side apply, namespace of the Cilium policy

`--apply` needs the Kyverno and Cilium CRDs in the cluster. `CiliumNetworkPolicy` is namespaced. The default namespace is `default`. The default output is mirrored in [`policies/`](policies/).

## Limitations

- Checks are static heuristics on Kubernetes objects. They do not see runtime behavior.
- Helm templates and Kustomize overlays are not rendered. Render them first (for example `helm template`) and scan the output.
- Auth detection is evidence-based. It looks for `--api-key` and known env names. It cannot prove that auth works.
- Engines are found by image or workload name. A custom image name may need the opt-in label or `--workload-selector`.
- Pods owned by a Deployment, StatefulSet, DaemonSet, Job or ReplicaSet are not scanned alone. Their owner is.

## FAQ

### How do I secure vLLM on Kubernetes?

Run `ai-guard scan --path manifests/`. It checks for a missing `--api-key`, root user, host access, `--trust-remote-code` and more. Then generate policies with `ai-guard enforce`.

### How do I secure Ollama on Kubernetes?

Ollama has no built-in auth. Put an authenticating gateway in front of it, or restrict traffic with a NetworkPolicy. AIG-001, AIG-009 and AIG-010 check for this.

### What if vLLM runs without an API key on Kubernetes?

AIG-001 reports it as High. Add `--api-key` or a `VLLM_API_KEY` env var. If a gateway handles auth, set the annotation `ai.infra.guard/gateway-auth: "true"`.

### What if Ollama is exposed by a NodePort or LoadBalancer?

AIG-010 reports a `LoadBalancer` or `NodePort` Service that selects an inference workload with no auth evidence. Use an internal Service or add auth.

### How do I allow huggingface.co in a Cilium egress policy?

`ai-guard enforce` writes a `CiliumNetworkPolicy` with FQDN egress. It allows DNS and Hugging Face hosts by default. Add more hosts with `--allow-fqdn`.

### How do I block hostPath and hostNetwork with Kyverno?

`ai-guard enforce` writes the Kyverno policy `aig-block-host-access.yaml`. It also writes policies that require `runAsNonRoot` and resource limits.

### Why is trust-remote-code a risk for vLLM?

It runs code from the model repository. AIG-008 reports `--trust-remote-code`. It also reports pickle model files such as `.bin` and `.pkl`. Use SafeTensors instead.

### Can I scan Helm template output for security issues?

Yes. Render the chart first with `helm template`, then run `ai-guard scan --path` on the output. Use `--fail-on high` to run it in GitHub Actions.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Report security issues as described in [SECURITY.md](SECURITY.md).

## License

Apache-2.0. Provided as is; risk acceptance remains with your organization.
