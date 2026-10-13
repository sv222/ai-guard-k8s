# Security Policy

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Use GitHub private vulnerability reporting. Open the "Security" tab of this repository and choose "Report a vulnerability".

Include the version (`ai-guard --version`), the steps to reproduce, and the impact you see. We will reply as soon as we can and agree on a fix and disclosure date with you.

## Supported versions

Only the latest release gets security fixes.

## Scope

This tool reads Kubernetes objects and can write policies to a cluster with `enforce --apply`. Reports about unsafe handling of manifests, kubeconfig or generated policies are in scope.
