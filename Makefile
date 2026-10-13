MODULE := github.com/aiguard/ai-guard-k8s
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X $(MODULE)/cmd.Version=$(VERSION)

.PHONY: build test vet fmt

build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o ai-guard .

test:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -s -w .
