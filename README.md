# kollektor

kollektor is a tool to gather real-time information and data about your kubernetes cluster using ebpf!

It runs as a DaemonSet. On each node the agent loads eBPF probes, labels every
event with the pod and container it came from, and exposes the results as
Prometheus metrics (and optionally as a JSON event stream).

## Layout

```
bpf/                    eBPF C sources (one file per probe) + shared headers
cmd/kollektor-agent/    agent entrypoint
internal/
  agent/                wires probes → enrichment → sinks
  config/               flags / env
  events/               normalized event model shared by all probes
  k8s/                  pod informer + PID → container → pod resolution
  metrics/              Prometheus /metrics and /healthz
  probes/               Probe interface; one subpackage per probe
    exec/               sched_process_exec probe + generated bpf2go bindings
deploy/base/            kustomize manifests (namespace, RBAC, DaemonSet)
```

## Probes

| Probe  | Hook                                  | Emits                                |
|--------|---------------------------------------|--------------------------------------|
| `exec` | `raw_tracepoint/sched_process_exec`   | pid, tid, uid, comm, cgroup id       |

### Adding a probe

1. Write `bpf/<name>.c` that sends events through a ring buffer.
2. Create `internal/probes/<name>/` with a `//go:generate go tool bpf2go ...`
   directive (copy the one in `exec`) and a type that implements `probes.Probe`.
3. Add an `events.Type` constant and register the probe in `agent.New`.
4. Run `make generate`.

## Development

Requirements: Go 1.26+, and either clang/llvm/libbpf-dev or docker/podman.
The generated bindings (`bpf_*.go`, `bpf_*.o`) are checked in, so
`go build` works without clang. Re-run `make generate` after changing any
`.c` file.

```sh
make generate   # compile BPF → Go bindings (falls back to a builder container if there is no clang)
make build      # bin/kollektor-agent
make test lint
make run        # run locally as root with -k8s=false, printing events as JSON
```

### Deploy to kind

```sh
kind create cluster
make kind-load deploy
kubectl -n kollektor port-forward ds/kollektor-agent 9090 &
curl -s localhost:9090/metrics | grep kollektor_
```

## Requirements on nodes

- Linux ≥ 5.8 (ring buffer, CAP_BPF/CAP_PERFMON). On older kernels set
  `privileged: true` in the DaemonSet.
- `hostPID: true`, which the agent uses to read `/proc/<pid>/cgroup` for pod attribution.
