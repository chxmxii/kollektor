IMAGE          ?= ghcr.io/chxmxii/kollektor-agent
TAG            ?= dev
CONTAINER_TOOL ?= $(shell command -v docker 2>/dev/null || command -v podman 2>/dev/null)
KIND_CLUSTER   ?= kind
BUILDER_IMAGE  := kollektor-bpf-builder

.PHONY: all
all: generate build

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

## build: build the agent binary into bin/
.PHONY: build
build:
	CGO_ENABLED=0 go build -trimpath -o bin/kollektor-agent ./cmd/kollektor-agent

## test: run unit tests
.PHONY: test
test:
	go test ./...

## lint: go vet + gofmt check
.PHONY: lint
lint:
	go vet ./...
	@test -z "$$(gofmt -l .)" || (gofmt -l .; exit 1)

## run: run the agent locally without k8s enrichment (needs root)
.PHONY: run
run: build
	sudo ./bin/kollektor-agent -k8s=false -log-events

## image: build the container image
.PHONY: image
image:
	$(CONTAINER_TOOL) build -t $(IMAGE):$(TAG) .

## kind-load: load the image into a kind cluster
.PHONY: kind-load
kind-load: image
	mkdir -p bin
	$(CONTAINER_TOOL) save $(IMAGE):$(TAG) -o bin/image.tar
	kind load image-archive bin/image.tar --name $(KIND_CLUSTER)

## deploy: apply the manifests to the current kube context
.PHONY: deploy
deploy:
	kubectl apply -k deploy/base

## undeploy: remove the manifests
.PHONY: undeploy
undeploy:
	kubectl delete -k deploy/base --ignore-not-found

## clean: remove build output
.PHONY: clean
clean:
	rm -rf bin/

.PHONY: help
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //'
