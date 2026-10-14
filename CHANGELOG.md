# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- ReplicaSets, ReplicationControllers and Argo Rollouts are scanned. Cluster scans list ReplicaSets that are not owned by a Deployment and ReplicationControllers (skipped at 0 replicas), which also makes Rollout pods visible. Manifests accept `kind: ReplicaSet`, `ReplicationController` and `Rollout` (`argoproj.io`). The cluster scan now needs list access to `replicasets` and `replicationcontrollers`.
- `ai-guard scan --lenient` keeps decode errors as warnings. Without it, a file that cannot be decoded makes `scan --path` exit with 2.
- `ai-guard enforce --skip-cilium` generates and applies only the Kyverno policies. `--apply` stopped with an error on clusters without Cilium CRDs after applying the Kyverno policies.
- `examples/hardened/ollama.yaml` and `examples/hardened/vllm.yaml`: manifests with no findings, tested with Ollama 0.40.4 and vLLM 0.31.0 (CPU) on kind with the generated Kyverno policies in Enforce mode. A test checks that they stay clean. See the README section Hardened examples.
- AIG-010 also reports workloads exposed through an Ingress that routes to a Service selecting them. Ingress auth annotations and `ai.infra.guard/gateway-auth: "true"` on the Ingress count as auth evidence. Cluster scans list Ingresses; a permission error gives a warning instead of failing the scan.

### Fixed

- `scan --path` follows no symlinks, skips special files (a named pipe no longer blocks the scan) and skips files larger than 10 MB. A YAML alias bomb is rejected by the decoder; a test covers it.
- `scan --path` exited with 0 and printed "No findings." when files could not be decoded (raw Helm templates, a Deployment with a wrong field type) or when the path had no Kubernetes object. It now exits with 2 and says why.
- AIG-001 and AIG-010 read auth env names per engine. vLLM reads only `--api-key` and `VLLM_API_KEY`, so `API_KEY` and `OPENAI_API_KEY` no longer hide a missing key on vLLM. Ollama, TGI, Triton and other engines without native auth get no credit from an env var. Text Embeddings Inference (`API_KEY`), llama.cpp (`LLAMA_API_KEY`) and LocalAI (`LOCALAI_API_KEY`, `API_KEY`) keep their own names.
- AIG-009 judges ingress only. An ingress rule with `ports` but no `from`, or with an empty `namespaceSelector`, no longer counts as isolation, and an egress-only policy no longer hides the finding while ingress stays open.
- `envFrom` Secret names count as auth evidence for AIG-001 only when they contain api-key, api-token, auth or bearer. Names such as `hf-token`, `aws-credentials` and `registry-auth` no longer hide a missing API key. Names with only `key` or `token` (for example `vllm-key`) no longer count.
- Workloads you opt in with the label, the annotation or `--workload-selector` now get the engine checks (AIG-001, AIG-002, AIG-008) when the pod has one container and the image is not recognized. Before, only AIG-003 to AIG-007, AIG-009 and AIG-010 ran on them.
- Engines started by `command` or `args` are detected when the image name does not match, for example `vllm serve`, `python -m vllm.entrypoints...` or `exec ollama serve`. A vLLM server in a custom image got no AIG-001, AIG-002 or AIG-008 checks.
- Engines missed before are now detected by image: `text-embeddings-inference`, `local-ai` and `localai`, `sglang`, `llama.cpp` and `llama-cpp`, `lmdeploy` and `tensorrt-llm`. A Text Embeddings Inference chart behind a `LoadBalancer` gave no findings.
- `tgi` matches only as a whole word. Images such as `postgis/postgis` were detected as Text Generation Inference.
- Helm test hook pods (`helm.sh/hook: test`) are no longer scanned. A `wget` test pod named after the chart was reported as an inference workload.

## [0.2.0] - 2026-10-14

### Added

- Checks parse shell-wrapped container commands (`sh -c "vllm serve ..."`).
- `envFrom` Secret references with names like key, token, auth or cred count as auth evidence for AIG-001.
- CronJob workloads are scanned in manifests and clusters.

### Changed

- AIG-005 follows Pod Security Standards Restricted: `runAsNonRoot` must be `true`. A non-zero `runAsUser` alone is not enough.
- AIG-007 checks `requests.memory`, `requests.cpu` and `limits.memory`, like the Kyverno policy.
- The default egress allowlist covers the two-label Hugging Face CDN hosts used by real downloads.
- README rewrite: demo, test evidence, limitations and roadmap.

### Fixed

- Jobs created by a CronJob were scanned again, so `scan --cluster` reported more findings than `scan --path`.

## [0.1.0] - 2026-10-13

### Added

- `ai-guard scan` for manifests (`--path`) and live clusters, with table and `--json` output.
- Checks AIG-001 to AIG-010 for AI inference workloads (vLLM, Ollama, Triton, TGI, Ray Serve).
- `--fail-on`, `--workload-selector`, `--cluster`, `--kubeconfig` and `-n` flags. Exit codes 0, 1 and 2.
- `ai-guard enforce` to generate Kyverno and Cilium policies, with `--out`, `--apply`, `--dry-run`, `--selector`, `--mode` and `--allow-fqdn`.
- Label `ai.infra.guard/enabled` and annotation `ai.infra.guard/gateway-auth`.
- Policy pack in `policies/`, checked by a golden test.

[Unreleased]: https://github.com/sv222/ai-guard-k8s/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/sv222/ai-guard-k8s/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/sv222/ai-guard-k8s/releases/tag/v0.1.0
