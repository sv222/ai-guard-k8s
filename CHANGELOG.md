# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0]

### Added

- `ai-guard scan` for manifests (`--path`) and live clusters, with table and `--json` output.
- Checks AIG-001 to AIG-010 for AI inference workloads (vLLM, Ollama, Triton, TGI, Ray Serve).
- `--fail-on`, `--workload-selector`, `--cluster`, `--kubeconfig` and `-n` flags. Exit codes 0, 1 and 2.
- `ai-guard enforce` to generate Kyverno and Cilium policies, with `--out`, `--apply`, `--dry-run`, `--selector`, `--mode` and `--allow-fqdn`.
- Label `ai.infra.guard/enabled` and annotation `ai.infra.guard/gateway-auth`.
- Policy pack in `policies/`, checked by a golden test.

[Unreleased]: https://github.com/sv222/ai-guard-k8s/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/sv222/ai-guard-k8s/releases/tag/v0.1.0
