BINDIR=bin
TOOLSDIR := $(shell pwd)/hack/tools
GOLINTER := $(TOOLSDIR)/bin/golangci-lint
GOLINTER_VERSION := v1.51.2

.PHONY: all
all: binary lint

$(GOLINTER):
	mkdir -p $(TOOLSDIR)/bin
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(TOOLSDIR)/bin $(GOLINTER_VERSION)
	$(GOLINTER) version

.PHONY: binary
binary:
	mkdir -p ${BINDIR}
	go build -v -o ${BINDIR}/sbom ./cmd/sbom/...

.PHONY: lint
lint: ./golangcilint.yaml $(GOLINTER)
	$(GOLINTER) --config ./golangcilint.yaml run --enable-all --out-format=colored-line-number ./...

.PHONY: test
test:
	go test -v -race -cover -coverpkg=./...
