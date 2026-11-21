VERSION        ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
IMAGE          ?= ghcr.io/chxmxii/kollektor
CONTAINER_TOOL ?= $(shell command -v docker 2>/dev/null || command -v podman 2>/dev/null)
BUILDER_IMAGE  := kollektor-bpf-builder
LDFLAGS        := -s -w -X main.version=$(VERSION)

.PHONY: all
all: build

## build: build bin/kollektor (static)
.PHONY: build
build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/kollektor ./cmd/kollektor

## generate: compile BPF C into Go bindings (uses local clang, else a builder container)
.PHONY: generate
generate:
ifneq ($(shell command -v clang 2>/dev/null),)
	go generate ./...
else
	$(CONTAINER_TOOL) build --target bpf-builder -t $(BUILDER_IMAGE) .
	$(CONTAINER_TOOL) run --rm -v $(CURDIR):/src:Z -w /src \
		-v $(shell go env GOMODCACHE):/go/pkg/mod:Z \
		$(BUILDER_IMAGE) go generate ./...
endif

## test: run unit tests
.PHONY: test
test:
	go test ./...

## lint: go vet + gofmt check
.PHONY: lint
lint:
	go vet ./...
	@test -z "$$(gofmt -l .)" || (gofmt -l .; exit 1)

## image: build the container image (used for node collection)
.PHONY: image
image:
	$(CONTAINER_TOOL) build --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) .

## clean: remove build output
.PHONY: clean
clean:
	rm -rf bin/

.PHONY: help
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //'
