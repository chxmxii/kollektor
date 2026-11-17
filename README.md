# kollektor

kollektor is a tool to gather real-time information and data about your kubernetes cluster using ebpf!

One binary. Point it at a cluster and it collects everything into a single
compressed, hash-verified evidence archive. You can then investigate that
archive offline, or replay it to recreate the same setup on another cluster.

```sh
kollektor collect --context prod -o case-042.tar.zst   # collect
kollektor inspect case-042.tar.zst                     # verify integrity + summary
kollektor extract case-042.tar.zst ./case-042          # verify, then unpack
kollektor replay  --kind case-042 case-042.tar.zst     # reproduce in a fresh kind cluster
```

## What gets collected

| Path in archive | Content |
|---|---|
| `manifest.json` | who/when/where (OS user, host, kube identity, context, server version, tool version), SHA-256 + size of every file, and every error hit during collection |
| `cluster/version.json`, `cluster/api-resources.json` | server version and full API discovery |
| `cluster/<namespace>/<resource>[.<group>]/<name>.yaml` | every object of every listable resource, CRDs and custom resources included, stored exactly as the API served it (`managedFields` kept, which shows who changed what). Cluster-scoped objects are under `_cluster/`. |
| `logs/<namespace>/<pod>/<container>[.previous].log` | logs of every started container (with timestamps), plus the previous instance's log for restarted containers |

**Secrets** are redacted by default. Each value is replaced with `""`, and its
SHA-256 is recorded in the `kollektor.io/data-sha256` annotation, so you can
still compare secrets across objects and collections. The
`last-applied-configuration` annotation, which contains the plaintext values,
is removed. Use `--include-secrets` to store raw values.

**Gaps are documented, not hidden.** Forbidden resources, unreachable
aggregated APIs, and logs the kubelet has already rotated away are listed
under `errors` in the manifest, and `inspect` prints them.

### Integrity

`manifest.json` is the last entry of the archive and lists the hash of every
other file. `inspect` and `extract` re-hash everything and fail if anything is
missing, altered or unlisted. The archive is written with mode `0400`.

> Next steps: store the archive's own SHA-256 in your case notes, and sign the
> manifest (planned).

## Replay

`replay` reads `cluster/` from the archive and applies it with server-side
apply, in dependency order: namespaces and CRDs (waiting until they are
established), then RBAC and config, then workloads, custom resources, and
finally admission webhooks.

It removes server-populated and cluster-specific fields (UIDs,
resourceVersion, status, managedFields, owner references, cluster IPs, node
names, PV bindings, Job selectors). It skips:

- objects created by controllers (Pods of a ReplicaSet, ReplicaSets of a Deployment, ...), since their owners recreate them
- control-plane-managed kinds: Events, Nodes, Leases, Endpoints/EndpointSlices, APIServices, FlowSchemas, ...
- system namespaces and built-in RBAC/priority classes (`--include-system` to keep them)
- admission webhooks and policies (`--include-webhooks`), because a webhook whose backend isn't running would block the replay

```sh
kollektor replay --context staging case.tar.zst      # into an existing cluster
kollektor replay --kind repro case.tar.zst           # create kind cluster "repro" (kubeconfig written next to the archive)
kollektor replay --dry-run --context staging case.tar.zst
kollektor replay --out ./manifests case.tar.zst      # just write ordered YAML for kubectl apply
```

Redacted secrets are replayed with empty values. Workloads that need them
will start but may misbehave until you fill them in.

## Roadmap

- **Node collection**: temporary privileged pods on each node for host data
  (kernel, mounts, kubelet/containerd config, static pods), the process tree
  with binary hashes and pod attribution, sockets/conntrack, and runtime state.
- **Live eBPF capture** (`--duration`): process execs, network connections and
  file access, attributed to pods. The exec probe in `bpf/` and
  `internal/probes/exec` is the starting point.
- Signed manifests, `inspect` queries (timeline, RBAC "who can").

## Development

```
cmd/kollektor/         CLI (collect, inspect, extract, replay)
internal/archive/      tar.zst writer/reader, manifest, verification
internal/collect/      API discovery + listing, secret redaction, logs
internal/replay/       plan (filter/sanitize/order) and apply
internal/k8s/          kubeconfig loading, PID → pod resolver (node collection)
internal/probes/       eBPF probes with generated bpf2go bindings
bpf/                   eBPF C sources
```

```sh
make build test lint
make generate   # after editing bpf/*.c (uses clang, or a builder container if missing)
```
