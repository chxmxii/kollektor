# syntax=docker/dockerfile:1

# --- bpf-builder: Go + clang/libbpf toolchain for compiling BPF programs ----
FROM golang:1.26-trixie AS bpf-builder
RUN apt-get update \
 && apt-get install -y --no-install-recommends clang llvm libbpf-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src

# --- build: generate BPF bindings and compile a static agent binary ---------
FROM bpf-builder AS build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go generate ./... \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/kollektor-agent ./cmd/kollektor-agent

# --- runtime -----------------------------------------------------------------
# Runs as root: loading BPF needs CAP_BPF/CAP_PERFMON in the effective set,
# which non-root users don't get from securityContext capabilities alone.
FROM gcr.io/distroless/static-debian12
COPY --from=build /out/kollektor-agent /kollektor-agent
ENTRYPOINT ["/kollektor-agent"]
