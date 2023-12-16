COMMIT_HASH=$(shell git describe --always --tags --long)
RELEASE_TAG=$(shell git describe --tags --abbrev=0)
COMMIT ?= $(if $(shell git status --porcelain --untracked-files=no),$(COMMIT_HASH)-dirty,$(COMMIT_HASH))

BINDIR=bin
TOOLSDIR := $(shell pwd)/hack/tools
GOLINTER := $(TOOLSDIR)/bin/golangci-lint
GOLINTER_VERSION := v1.52.2

# OCI registry
ZOT := $(TOOLSDIR)/bin/zot
ZOT_VERSION := 2.0.0
# OCI registry clients
ORAS := $(TOOLSDIR)/bin/oras
ORAS_VERSION := 1.0.0-rc.1
REGCTL := $(TOOLSDIR)/bin/regctl
REGCTL_VERSION := 0.5.0
# BOM tools
K8S_BOM := $(TOOLSDIR)/bin/bom
K8S_BOM_VERSION := 0.5.1
BATS := $(TOOLSDIR)/bin/bats

BINARY := stacker-bom
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
	CGO_ENABLED=1 GOOS=${OS} GOARCH=${ARCH} go build -tags netgo -v -trimpath -ldflags "-X stackerbuild.io/stacker-bom/pkg/buildgen.ReleaseTag=${RELEASE_TAG} -X stackerbuild.io/stacker-bom/pkg/buildgen.Commit=${COMMIT} -X stackerbuild.io/stacker-bom/pkg/cli.Binary=${BINARY} -linkmode external -extldflags -static"  -o ${BINDIR}/${BINARY}-${OS}-${ARCH} ./cmd/bom/...

.PHONY: lint
lint: ./golangcilint.yaml $(GOLINTER)
	$(GOLINTER) --config ./golangcilint.yaml run --enable-all --out-format=colored-line-number ./...

$(ZOT):
	mkdir -p $(TOOLSDIR)/bin
	curl -Lo $(ZOT) https://github.com/project-zot/zot/releases/download/v$(ZOT_VERSION)/zot-linux-amd64-minimal
	chmod +x $(ZOT)

$(TRUST):
	mkdir -p $(TOOLSDIR)/bin
	curl -Lo $(TRUST) https://github.com/project-machine/trust/releases/download/${TRUST_VERSION}/trust
	chmod +x $(TRUST)

$(ORAS):
	mkdir -p $(TOOLSDIR)/bin
	curl -Lo oras.tar.gz https://github.com/oras-project/oras/releases/download/v$(ORAS_VERSION)/oras_$(ORAS_VERSION)_linux_amd64.tar.gz
	tar xvzf oras.tar.gz -C $(TOOLSDIR)/bin oras
	rm oras.tar.gz

$(REGCTL):
	mkdir -p $(TOOLSDIR)/bin
	curl -Lo $(REGCTL) https://github.com/regclient/regclient/releases/download/v$(REGCTL_VERSION)/regctl-linux-amd64
	chmod +x $(REGCTL)

$(K8S_BOM):
	mkdir -p $(TOOLSDIR)/bin
	curl -Lo $(K8S_BOM) https://github.com/kubernetes-sigs/bom/releases/download/v$(K8S_BOM_VERSION)/bom-amd64-linux
	chmod +x $(K8S_BOM)

$(BATS):
	rm -rf bats-core; \
		git clone https://github.com/bats-core/bats-core.git; \
		cd bats-core; ./install.sh $(TOOLSDIR); cd ..; \
		rm -rf bats-core

.PHONY: test
test: $(BATS) $(ZOT) $(ORAS) $(REGCTL) $(K8S_BOM)
	go test -v -race -cover -coverpkg=./...
	$(BATS) --trace --verbose-run --print-output-on-failure --show-output-of-passing-tests test/*.bats

.PHONY: clean
clean:
	rm -rf ${BINDIR}
	rm -rf ${TOOLSDIR}
