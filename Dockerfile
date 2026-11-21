# syntax=docker/dockerfile:1

# --- bpf-builder: Go + clang/libbpf toolchain for compiling BPF programs ----
FROM golang:1.26-trixie AS bpf-builder
RUN apt-get update \
 && apt-get install -y --no-install-recommends clang llvm libbpf-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src

# --- build: generate BPF bindings and compile a static binary ----------------
FROM bpf-builder AS build
ARG VERSION=dev
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go generate ./... \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/kollektor ./cmd/kollektor

# --- runtime -----------------------------------------------------------------
# The image is what node-collection pods will run. They need root: loading BPF
# requires CAP_BPF/CAP_PERFMON in the effective set.
FROM gcr.io/distroless/static-debian12
COPY --from=build /out/kollektor /kollektor
ENTRYPOINT ["/kollektor"]
