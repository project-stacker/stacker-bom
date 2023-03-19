COMMIT_HASH=$(shell git describe --always --tags --long)
RELEASE_TAG=$(shell git describe --tags --abbrev=0)
COMMIT ?= $(if $(shell git status --porcelain --untracked-files=no),$(COMMIT_HASH)-dirty,$(COMMIT_HASH))

BINDIR=bin
TOOLSDIR := $(shell pwd)/hack/tools
GOLINTER := $(TOOLSDIR)/bin/golangci-lint
GOLINTER_VERSION := v1.51.2

BINARY := stacker-sbom
OS ?= linux
ARCH ?= amd64

.PHONY: all
all: binary lint

$(GOLINTER):
	mkdir -p $(TOOLSDIR)/bin
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(TOOLSDIR)/bin $(GOLINTER_VERSION)
	$(GOLINTER) version

.PHONY: binary
binary:
	mkdir -p ${BINDIR}
	GOOS=${OS} GOARCH=${ARCH} go build -v -trimpath -ldflags "-X stackerbuild.io/sbom/pkg/build.ReleaseTag=${RELEASE_TAG} -X stackerbuild.io/sbom/pkg/build.Commit=${COMMIT} -s -w" -o ${BINDIR}/${BINARY}-${OS}-${ARCH} ./cmd/sbom/...

.PHONY: lint
lint: ./golangcilint.yaml $(GOLINTER)
	$(GOLINTER) --config ./golangcilint.yaml run --enable-all --out-format=colored-line-number ./...

.PHONY: test
test:
	go test -v -race -cover -coverpkg=./...

.PHONY: clean
clean:
	rm -rf ${BINDIR}
	rm -rf ${TOOLSDIR}
