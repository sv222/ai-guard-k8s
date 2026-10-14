MODULE := github.com/sv222/ai-guard-k8s
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X $(MODULE)/cmd.Version=$(VERSION)
FUZZTIME ?= 15s

FUZZ_TARGETS := target:FuzzFromBytes scanner:FuzzScanManifest scanner:FuzzAnalyzeGenerated enforce:FuzzPolicies enforce:FuzzValidateFQDN selector:FuzzParse report:FuzzPrintJSON

.PHONY: build test vet fmt fuzz fuzz-seeds

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o ai-guard .

test:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -s -w .

fuzz-seeds:
	go test -count=1 -run '^(Fuzz|TestProperty)' ./...

fuzz:
	@set -e; for t in $(FUZZ_TARGETS); do \
		pkg=$${t%%:*}; name=$${t##*:}; \
		echo "fuzz $$pkg $$name $(FUZZTIME)"; \
		go test ./pkg/$$pkg -run '^$$' -fuzz "^$$name$$" -fuzztime $(FUZZTIME); \
	done
