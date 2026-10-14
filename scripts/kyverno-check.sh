#!/usr/bin/env bash
set -euo pipefail

IMAGE="${KYVERNO_CLI_IMAGE:-ghcr.io/kyverno/kyverno-cli:v1.19.1}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

out="$(docker run --rm -v "$ROOT:/repo:ro" "$IMAGE" apply /repo/policies/aig-require-nonroot.yaml /repo/policies/aig-block-host-access.yaml /repo/policies/aig-require-resources.yaml --resource /repo/testdata/kyverno/pods.yaml 2>&1 || true)"
echo "$out"

for name in hostipc hostport initport initnores hostnet; do
  echo "$out" | grep -q "resource llm/Pod/$name failed" || { echo "expected a violation for $name"; exit 1; }
done
if echo "$out" | grep -q "resource llm/Pod/good failed"; then
  echo "the good pod must pass"
  exit 1
fi
echo "kyverno check ok"
