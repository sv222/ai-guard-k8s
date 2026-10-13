# Contributing

Thanks for your interest. Small, focused pull requests are easiest to review.

## Build and test

    make build
    make test
    make vet
    make fmt

Before you open a pull request, also run `gofmt -s -l .` and `go mod tidy`. Both must leave no changes.

## Add a check

1. Add a function `aigNNN(w target.WorkloadTarget) []Finding` in `pkg/checks/podspec.go` and add it to `Registry`. For checks that need Services or NetworkPolicies, extend `RunContextChecks` in `pkg/checks/context.go`.
2. Set a stable ID, a severity (`Low`, `Medium` or `High`), a short title, evidence text and a fix hint.
3. Add a failing and a passing case to the fixtures in `testdata/manifests/offending/` and `testdata/manifests/clean/`.
4. Add a test in `pkg/checks/checks_test.go` that covers both cases.
5. Add the check to the table in `README.md` and to `CHANGELOG.md` under Unreleased.

## Change the policy generator

If you change `pkg/enforce`, regenerate the golden files and the `policies/` mirror:

    go test ./pkg/enforce -run TestPoliciesGolden -update

## Style

- Keep Go code free of comments unless they explain something non-obvious.
- Write short commit messages: one summary line, imperative mood.

## Conduct

By taking part you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
